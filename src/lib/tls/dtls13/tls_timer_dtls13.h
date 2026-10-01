/*
* DTLS timer helpers
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_TIMER_DTLS13_H_
#define BOTAN_TLS_TIMER_DTLS13_H_

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <chrono>
#include <optional>

namespace Botan::TLS {

class Callbacks;

/**
 * A convenience wrapper for Callbacks::tls_register_deferred_operation() that
 * allows modelling a cancellable asynchronous operation. This is achieved by
 * storing an internal token that is shared with the deferred operation. If the
 * token is destroyed before the operation is executed, it will act as a no-op.
 *
 * Cancelling the operation can be done by explicitly calling cancel() on the
 * TimerToken object or simply by destroying/overwriting the TimerToken object.
 */
class SingleshotTimer final {
   private:
      /**
       * This Token is owned by the SingleshotTimer object and shared with the
       * deferred operation as a weak_ptr. If the Token is destroyed before the
       * deferred operation is executed, the operation will act as a no-op.
       */
      struct Token {
            bool executed = false;
      };

      explicit SingleshotTimer(std::shared_ptr<Token> token) : m_token(std::move(token)) {}

   public:
      using DeferredOperation = std::function<void()>;

      SingleshotTimer() = default;
      ~SingleshotTimer() = default;

      SingleshotTimer(const SingleshotTimer&) = delete;
      SingleshotTimer& operator=(const SingleshotTimer&) = delete;
      SingleshotTimer(SingleshotTimer&&) = default;
      SingleshotTimer& operator=(SingleshotTimer&&) = default;

   public:
      static SingleshotTimer start(Callbacks& callbacks, std::chrono::milliseconds delay, DeferredOperation operation) {
         auto token = std::make_shared<Token>();
         callbacks.tls_register_deferred_operation(
            delay.count(), [weak_token = std::weak_ptr(token), operation = std::move(operation)]() mutable {
               if(auto handle = weak_token.lock()) {
                  operation();
                  handle->executed = true;
               }
            });

         return SingleshotTimer(std::move(token));
      }

      /// Cancel the deferred operation if it has not yet been executed.
      void cancel() { m_token.reset(); }

      /// @returns true if the deferred operation is currently armed and was
      ///          not yet executed; false otherwise
      bool armed() const { return m_token != nullptr && !m_token->executed; }

      // NOLINTNEXTLINE(*-explicit-conversions)
      operator bool() const { return armed(); }

   private:
      std::shared_ptr<Token> m_token;
};

/**
 * DTLS retransmission timer implementing the schedule of RFC 6347 sec 4.2.4.1:
 * the timeout starts at the policy's initial value and doubles with each
 * retransmission, capped at the policy's maximum.
 *
 * The user can cancel and restart the timer as needed. If the timer object is
 * destroyed, the timer is automatically cancelled.
 */
class RetransmissionTimer final {
   public:
      using DeferredOperation = std::function<void()>;

   private:
      /**
       * The retransmission timer keeps its state in a shared_ptr<Token> so that
       * the deferred operation can hold a weak_ptr to this state object instead
       * of the actual RetransmissionTimer object. The Token's lifetime is bound
       * to the RetransmissionTimer's lifetime and not the deferred operation.
       *
       * Because the RetransmissionTimer implements an exponential backoff, the
       * deferred operation can re-schedule itself using only the Token's state
       * without needing to access the RetransmissionTimer object.
       */
      struct Token {
            const std::chrono::milliseconds initial_timeout;
            const std::chrono::milliseconds max_timeout;
            const std::optional<size_t> max_retransmissions;
            const std::shared_ptr<Callbacks> callbacks;

            DeferredOperation on_retransmission;
            size_t retransmissions;
            std::chrono::milliseconds next_timeout;
            SingleshotTimer retransmission_timer;
      };

   public:
      RetransmissionTimer(const Policy& policy, std::shared_ptr<Callbacks> callbacks) :
            m_token(std::make_shared<Token>(Token{
               .initial_timeout = std::chrono::milliseconds(policy.dtls_initial_timeout()),
               .max_timeout = std::chrono::milliseconds(policy.dtls_maximum_timeout()),
               .max_retransmissions = policy.dtls_maximum_retransmissions(),
               .callbacks = std::move(callbacks),
               .on_retransmission = {},
               .retransmissions = 0,
               .next_timeout = std::chrono::milliseconds(policy.dtls_initial_timeout()),
               .retransmission_timer = {},
            })) {}

      ~RetransmissionTimer() = default;

      RetransmissionTimer(const RetransmissionTimer&) = delete;
      RetransmissionTimer& operator=(const RetransmissionTimer&) = delete;
      RetransmissionTimer(RetransmissionTimer&&) = default;
      RetransmissionTimer& operator=(RetransmissionTimer&&) = default;

      /// @returns true if the timer is currently armed; false otherwise
      bool armed() const { return m_token->retransmission_timer.armed(); }

      // NOLINTNEXTLINE(*-explicit-conversions)
      operator bool() const { return armed(); }

      /**
       * Disarm the timer and reset the retransmission counter. This is done
       * when the peer has acknowledged the last flight and no further
       * retransmissions are needed. Note that this doesn't necesarily mean
       * that the handshake is complete!
       */
      void cancel() { reset(); }

      /**
       * Arm (or restart) the timer when a *new* flight was just sent.
       * Resets the timeout span to the initial value and the retransmission
       * counter to zero.
       *
       * The operation @p on_retransmission will be executed consecutively
       * with an exponential backoff until the configured maximum retransmission
       * count is reached or the timer is cancelled.
       */
      void start(DeferredOperation on_retransmission) {
         reset(std::move(on_retransmission));
         set_timer(m_token);
      }

   private:
      void reset(DeferredOperation on_retransmission = {}) {
         m_token->on_retransmission = std::move(on_retransmission);
         m_token->retransmissions = 0;
         m_token->next_timeout = m_token->initial_timeout;
         m_token->retransmission_timer.cancel();
      }

      static void set_timer(const std::shared_ptr<Token>& token) {
         token->retransmission_timer = SingleshotTimer::start(*token->callbacks, token->next_timeout, on(token));
      }

      static SingleshotTimer::DeferredOperation on(const std::shared_ptr<Token>& token) {
         return [weak_token = std::weak_ptr(token)] {
            if(auto handle = weak_token.lock()) {
               if(handle->max_retransmissions.has_value() &&
                  handle->retransmissions >= handle->max_retransmissions.value()) {
                  throw TLS_Exception(Alert::None, "DTLS handshake timed out: maximum retransmissions exceeded");
               }

               handle->on_retransmission();
               handle->next_timeout = std::min(2 * handle->next_timeout, handle->max_timeout);
               handle->retransmissions++;
               set_timer(handle);
            }
         };
      }

   private:
      std::shared_ptr<Token> m_token;
};

}  // namespace Botan::TLS

#endif
