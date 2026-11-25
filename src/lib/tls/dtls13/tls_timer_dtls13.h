/*
* DTLS timer helpers
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_TIMER_DTLS13_H_
#define BOTAN_TLS_TIMER_DTLS13_H_

#include <botan/assert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/internal/stl_util.h>
#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>

namespace Botan::TLS {

class Callbacks;

/**
 * A convenience wrapper for Callbacks::tls_register_deferred_operation() that
 * allows scheduling an asynchronous operation that is run exactly once after
 * a specified delay.
 *
 * If the application invokes the registered operation before the deadline, the
 * timer is re-armed for the remaining time. A duplicate invocation of the same
 * registered operation is a no-op.
 */
class SingleshotTimer final {
   public:
      using DeferredOperation = std::function<void()>;

   private:
      /**
       * Tracks a single registration of a deferred operation. This is needed to
       * avoid re-arming a deferred operation more than once if an application
       * calls it prematurely multiple times, and to ensure the user operation
       * runs at most once across the whole registration chain.
       */
      struct Registration {
            bool consumed = false;
      };

      /**
       * This Token is owned by the SingleshotTimer object and shared with the
       * cancellable deferred operation as a weak_ptr. If the Token is destroyed
       * before the deferred operation is executed, the operation will act as a
       * no-op.
       *
       * If the using application (accidentally) calls the deferred operation
       * more than once on the same SingleshotTimer object it will still only be
       * executed once. If the Token is destroyed before the deferred operation
       * is executed, the operation will not be executed at all.
       */
      struct Token {
            uint64_t deadline_ms = 0;
            std::shared_ptr<Registration> registration;
      };

      using TokenHandle = std::variant<std::weak_ptr<Token>, std::shared_ptr<Token>>;

      explicit SingleshotTimer(std::shared_ptr<Token> token) : m_token(std::move(token)) {}

      static std::shared_ptr<Registration> register_deferred_operation(const std::shared_ptr<Callbacks>& callbacks,
                                                                       const TokenHandle& token_handle,
                                                                       uint64_t delay_ms,
                                                                       DeferredOperation operation) {
         auto registration = std::make_shared<Registration>();

         std::visit(
            [&](auto&& handle) mutable {
               callbacks->tls_register_deferred_operation(delay_ms,
                                                          [weak_cb = std::weak_ptr(callbacks),
                                                           handle,
                                                           registration,
                                                           operation = std::move(operation)]() mutable {
                                                             run_or_rearm(
                                                                weak_cb, handle, registration, std::move(operation));
                                                          });
            },
            token_handle);

         return registration;
      }

      static uint64_t remaining(const Token& token, Callbacks& callbacks) {
         const auto now = callbacks.tls_current_monotonic_clock_ms();
         const auto deadline = token.deadline_ms;

         if(deadline <= now) {
            return 0;
         } else {
            return deadline - now;
         }
      }

      static void run_or_rearm(const std::weak_ptr<Callbacks>& weak_callbacks,
                               const TokenHandle& token_handle,
                               const std::shared_ptr<Registration>& registration,
                               DeferredOperation operation) {
         // If the deferred operation was called previously this becomes a no-op
         // so that timers aren't re-armed multiple times and the user operation
         // is only executed exactly once.
         if(registration->consumed) {
            return;
         }

         // If our Callbacks object is gone, we have to assume that the deferred
         // operation survived the underlying TLS channel and its dependencies.
         const auto cb = weak_callbacks.lock();
         if(!cb) {
            return;
         }

         // The `token_handle` might be a shared or a weak pointer. In the latter
         // case, the Token might have been destroyed already (timer cancelled),
         // and we have to treat this as a no-op.
         std::shared_ptr<Token> token =
            std::visit(overloaded{
                          [&](const std::weak_ptr<Token>& weak_token) { return weak_token.lock(); },
                          [&](const std::shared_ptr<Token>& shared_token) { return shared_token; },
                       },
                       token_handle);
         if(!token) {
            return;
         }

         // We are now past the sanity checks and it is time to act. In any case
         // this particular registration is now being consumed.
         registration->consumed = true;

         const auto remaining_ms = remaining(*token, *cb);
         if(remaining_ms > DTLS_RETRANSMISSION_TIMER_FUDGE) {
            // The timer was called pre-maturely. We re-arm it with a new
            // registration for the remaining time until the deadline.
            token->registration = register_deferred_operation(cb, token_handle, remaining_ms, std::move(operation));
         } else {
            // The timer has expired and we can execute the deferred operation.
            // No new registration is created, because the operation served
            // its purpose and is now retired.
            token->registration.reset();
            operation();
         }
      }

      static std::shared_ptr<Token> make_token(const std::shared_ptr<Callbacks>& callbacks,
                                               std::chrono::milliseconds delay) {
         auto token = std::make_shared<Token>();
         const uint64_t now_ms = callbacks->tls_current_monotonic_clock_ms();
         token->deadline_ms = now_ms + static_cast<uint64_t>(delay.count());
         return token;
      }

   public:
      SingleshotTimer() = default;
      ~SingleshotTimer() = default;

      SingleshotTimer(const SingleshotTimer&) = delete;
      SingleshotTimer& operator=(const SingleshotTimer&) = delete;
      SingleshotTimer(SingleshotTimer&&) = default;
      SingleshotTimer& operator=(SingleshotTimer&&) = default;

   public:
      /**
       * Start a deferred operation that will be executed after the given delay.
       * This operation cannot be cancelled.
       */
      static void start_detached(const std::shared_ptr<Callbacks>& callbacks,
                                 std::chrono::milliseconds delay,
                                 DeferredOperation operation) {
         auto token = make_token(callbacks, delay);
         token->registration = register_deferred_operation(callbacks, token, delay.count(), std::move(operation));
      }

      /**
       * Start a deferred operation that can be cancelled using the returned
       * SingleshotTimer object. The operation will be executed after the given
       * delay unless the SingleshotTimer object is destroyed or cancel() is
       * called before the operation is executed.
       */
      [[nodiscard]] static SingleshotTimer start(const std::shared_ptr<Callbacks>& callbacks,
                                                 std::chrono::milliseconds delay,
                                                 DeferredOperation operation) {
         auto token = make_token(callbacks, delay);
         token->registration =
            register_deferred_operation(callbacks, std::weak_ptr(token), delay.count(), std::move(operation));
         return SingleshotTimer(std::move(token));
      }

      /// Cancel the deferred operation if it has not yet been executed.
      void cancel() { m_token.reset(); }

      /// @returns true if the deferred operation is currently armed and was
      ///          not yet executed; false otherwise
      bool armed() const { return m_token != nullptr && m_token->registration != nullptr; }

      // NOLINTNEXTLINE(*-explicit-conversions)
      operator bool() const { return armed(); }

      /**
       * @returns the remaining waiting time or std::nullopt if not armed
       *
       * Note that this might return 0ms if the timer is armed and the deadline
       * has been reached, but the deferred operation has not yet been executed.
       */
      std::optional<std::chrono::milliseconds> remaining(Callbacks& callbacks) const {
         if(!armed()) {
            return std::nullopt;
         }

         BOTAN_DEBUG_ASSERT(m_token != nullptr);
         return std::chrono::milliseconds(remaining(*m_token, callbacks));
      }

   private:
      std::shared_ptr<Token> m_token;
};

/**
 * DTLS retransmission timer implementing the schedule of RFC 6347 sec 4.2.4.1:
 * the timeout starts at the policy's initial value and doubles with each
 * retransmission, capped at the policy's maximum. Additionally, a "flight
 * timeout" can be configured to bound the waiting time for progress from the
 * peer with a blanket timeout.
 *
 * Blanket flight timeouts are especially useful in DTLS 1.3 when the peer fully
 * acknowledged our flight (either explicitly via ACKs or implicitly by
 * responding with a partial flight) but then does not complete its flight.
 *
 * The user can cancel and restart the timer as needed. The retransmission timer
 * can be cancelled without cancelling the blanket flight timeout in exactly the
 * scenario described above. If the timer object is destroyed, both timers are
 * automatically cancelled.
 */
class RetransmissionTimer final {
   public:
      using DeferredOperation = std::function<void()>;
      using TimeoutHandler = std::function<void()>;

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
            const std::optional<std::chrono::milliseconds> flight_timeout;
            const std::optional<size_t> max_retransmissions;
            const std::shared_ptr<Callbacks> callbacks;

            DeferredOperation on_retransmission;
            TimeoutHandler on_timeout;
            size_t retransmissions;
            std::chrono::milliseconds next_timeout;
            SingleshotTimer retransmission_timer;
            SingleshotTimer flight_timer;
      };

      static std::optional<std::chrono::milliseconds> get_flight_timeout(const Policy& policy) {
         // TODO(C++23): std::optional::transform
         if(const auto timeout = policy.dtls_flight_timeout()) {
            return std::chrono::milliseconds(*timeout);
         }
         return std::nullopt;
      }

   public:
      RetransmissionTimer(const Policy& policy, std::shared_ptr<Callbacks> callbacks) :
            m_token(std::make_shared<Token>(Token{
               .initial_timeout = std::chrono::milliseconds(policy.dtls_initial_timeout()),
               .max_timeout = std::chrono::milliseconds(policy.dtls_maximum_timeout()),
               .flight_timeout = get_flight_timeout(policy),
               .max_retransmissions = policy.dtls_maximum_retransmissions(),
               .callbacks = std::move(callbacks),
               .on_retransmission = {},
               .on_timeout = {},
               .retransmissions = 0,
               .next_timeout = std::chrono::milliseconds(policy.dtls_initial_timeout()),
               .retransmission_timer = {},
               .flight_timer = {},
            })) {
         BOTAN_ASSERT_NONNULL(m_token->callbacks);
      }

      ~RetransmissionTimer() = default;

      RetransmissionTimer(const RetransmissionTimer&) = delete;
      RetransmissionTimer& operator=(const RetransmissionTimer&) = delete;
      RetransmissionTimer(RetransmissionTimer&&) = default;
      RetransmissionTimer& operator=(RetransmissionTimer&&) = default;

      /// @returns true if the retransmission timer is currently armed; false otherwise
      bool retransmissions_armed() const { return m_token->retransmission_timer.armed(); }

      /// @returns true if the flight timer is currently armed; false otherwise
      bool flight_timeout_armed() const { return m_token->flight_timer.armed(); }

      /**
       * @returns the time remaining until the next retransmission, the blanket
       *          flight timeout or std::nullopt if neither timer is armed.
       *
       * Note that this might return 0ms if the timer is armed and a deadline
       * has been reached, but the deferred operation has not yet been executed.
       */
      std::optional<std::chrono::milliseconds> next_timeout() const {
         if(!retransmissions_armed() && !flight_timeout_armed()) {
            return std::nullopt;
         }

         const auto next_retransmission = m_token->retransmission_timer.remaining(*m_token->callbacks);
         const auto flight_timeout = m_token->flight_timer.remaining(*m_token->callbacks);
         BOTAN_DEBUG_ASSERT(next_retransmission.has_value() || flight_timeout.has_value());

         return std::min(next_retransmission.value_or(std::chrono::milliseconds::max()),
                         flight_timeout.value_or(std::chrono::milliseconds::max()));
      }

      /**
       * Stop any further time-based retransmissions. This is typically done
       * when a flight has been acknowledged by the peer and no further
       * retransmissions are needed. This does not affect the flight timer,
       * which may be used to detect a flight timeout if no further progress
       * is made after a flight was acknowledged.
       */
      void stop_retransmissions() { reset_retransmission_timer(); }

      /**
       * Disarm the timer and reset the retransmission counter. This is done
       * when progress is made by receiving a full flight from the peer and the
       * responsibility to produce a new flight now lies on us. In contrast to
       * stop_retransmissions(), this also cancels the flight timer.
       */
      void cancel() {
         reset_retransmission_timer();
         m_token->flight_timer.cancel();
      }

      /**
       * Arm (or restart) the timers when a *new* flight was just sent.
       * Resets the timeout span to the initial value and the retransmission
       * counter to zero. Optionally starts the blanket flight timer if it is
       * configured.
       *
       * The operation @p on_retransmission will be executed consecutively
       * with an exponential backoff until the configured maximum retransmission
       * count is reached or the timer is cancelled.
       *
       * If the optional flight timeout is reached, retransmissions will be
       * stopped as well.
       */
      void start(DeferredOperation on_retransmission) {
         reset_retransmission_timer(std::move(on_retransmission));
         set_retransmission_timer(m_token);
         set_flight_timer();
      }

      /**
       * Allows registering a callback that is invoked when the maximum
       * retransmission count is reached or the blanket flight timeout expires.
       * The callback is needed because the emitted exception from within the
       * deferred operations cannot be caught by higher layers of the library's
       * DTLS business logic as they typically are invoked by the application
       * directly.
       */
      void set_timeout_handler(TimeoutHandler handler) { m_token->on_timeout = std::move(handler); }

   private:
      void set_flight_timer() {
         if(auto timeout = m_token->flight_timeout) {
            m_token->flight_timer = SingleshotTimer::start(m_token->callbacks, *timeout, on_flight_timeout(m_token));
         }
      }

      void reset_retransmission_timer(DeferredOperation on_retransmission = {}) {
         m_token->on_retransmission = std::move(on_retransmission);
         m_token->retransmissions = 0;
         m_token->next_timeout = m_token->initial_timeout;
         m_token->retransmission_timer.cancel();
      }

      static void set_retransmission_timer(const std::shared_ptr<Token>& token) {
         token->retransmission_timer =
            SingleshotTimer::start(token->callbacks, token->next_timeout, on_retransmission_timeout(token));
      }

      static SingleshotTimer::DeferredOperation on_flight_timeout(const std::shared_ptr<Token>& token) {
         return [weak = std::weak_ptr(token)] {
            if(auto handle = weak.lock()) {
               handle->retransmission_timer.cancel();
               if(handle->on_timeout) {
                  handle->on_timeout();
               }
               throw TLS_Exception(Alert::None,
                                   "DTLS (post-)handshake message exchange timed out: flight timeout exceeded");
            }
         };
      }

      static SingleshotTimer::DeferredOperation on_retransmission_timeout(const std::shared_ptr<Token>& token) {
         return [weak_token = std::weak_ptr(token)] {
            if(auto handle = weak_token.lock()) {
               if(handle->max_retransmissions.has_value() &&
                  handle->retransmissions >= handle->max_retransmissions.value()) {
                  handle->flight_timer.cancel();
                  if(handle->on_timeout) {
                     handle->on_timeout();
                  }
                  throw TLS_Exception(
                     Alert::None, "DTLS (post-)handshake message exchange timed out: maximum retransmissions exceeded");
               }

               handle->on_retransmission();
               handle->next_timeout = std::min(2 * handle->next_timeout, handle->max_timeout);
               handle->retransmissions++;
               set_retransmission_timer(handle);
            }
         };
      }

   private:
      std::shared_ptr<Token> m_token;
};

}  // namespace Botan::TLS

#endif
