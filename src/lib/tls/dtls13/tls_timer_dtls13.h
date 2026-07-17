/*
* DTLS timer
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_TIMER_DTLS13_H_
#define BOTAN_TLS_TIMER_DTLS13_H_

#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <chrono>
#include <optional>

namespace Botan::TLS {

/**
 * DTLS retransmission timer implementing the schedule of RFC 6347 sec 4.2.4.1:
 * the timeout starts at the policy's initial value and doubles with each
 * retransmission, capped at the policy's maximum.
 *
 * The current time is obtained via Callbacks::tls_current_monotonic_clock_ms().
 */
class DTLS_Retransmission_Timer {
   public:
      DTLS_Retransmission_Timer(const Policy& policy, std::shared_ptr<Callbacks> callbacks) :
            m_initial_timeout(policy.dtls_initial_timeout()),  //
            m_max_timeout(policy.dtls_maximum_timeout()),
            m_max_retransmissions(policy.dtls_maximum_retransmissions()),
            m_callbacks(std::move(callbacks)) {}

      /**
       * @returns true iff the timer has been set
      */
      bool started() const { return m_next_deadline.has_value(); }

      /**
       * @returns true if the deadline was reached; false if the timer was never armed
       */
      bool expired() const { return started() && now() >= m_next_deadline.value(); }

      /**
       * @returns true if the policy's retransmission limit was reached;
       *          always false if the policy sets no limit or the timer is not armed
       */
      bool retransmissions_exhausted() const {
         if(!m_max_retransmissions.has_value() || !started()) {
            return false;
         }
         return m_retransmissions >= m_max_retransmissions.value();
      }

      /**
       *  Arm (or reset) the timer when a *new* flight was just sent.
       *  Resets the timeout span to the initial value and the retransmission
       *  counter to zero.
       */
      void flight_sent() {
         m_next_timeout_span = m_initial_timeout;
         m_next_deadline = now() + m_next_timeout_span;
         m_retransmissions = 0;
      }

      /**
       *  Re-arm the timer after retransmitting a flight. Doubles the timeout
       *  span (capped at the policy's maximum) and counts the retransmission.
       */
      void retransmitted() {
         m_next_timeout_span = std::min(2 * m_next_timeout_span, m_max_timeout);
         m_next_deadline = now() + m_next_timeout_span;
         m_retransmissions++;
      }

      /**
       *  Remaining time until expiry
       *  @returns time in ms until the next timeout, or std::nullopt if not yet armed.
       *
       *  Note that a return with value 0 means the timer has expired.
       */
      std::optional<std::chrono::milliseconds> next_timeout() const {
         if(!started()) {
            return std::nullopt;
         }

         if(expired()) {
            using namespace std::chrono_literals;
            return 0ms;
         }

         return m_next_deadline.value() - now();
      }

   private:
      std::chrono::milliseconds now() const {
         return std::chrono::milliseconds{m_callbacks->tls_current_monotonic_clock_ms()};
      }

   private:
      const std::chrono::milliseconds m_initial_timeout;
      const std::chrono::milliseconds m_max_timeout;
      const std::optional<size_t> m_max_retransmissions;
      const std::shared_ptr<Callbacks> m_callbacks;

      std::optional<std::chrono::milliseconds> m_next_deadline;  // unset until first flight
      std::chrono::milliseconds m_next_timeout_span = std::chrono::milliseconds(0);
      size_t m_retransmissions = 0;
};

}  // namespace Botan::TLS

#endif
