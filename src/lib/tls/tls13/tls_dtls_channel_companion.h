/*
* DTLS Channel Mix-in - adding DTLS-specific functionality on demand
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_DTLS_CHANNEL_COMPANION_BASE_H_
#define BOTAN_TLS_DTLS_CHANNEL_COMPANION_BASE_H_

#include <botan/assert.h>
#include <botan/tls_exceptn.h>
#include <chrono>
#include <optional>

namespace Botan::TLS {

class Cipher_State;

/**
 * Provides an abstract interface for DTLS-specific functionality that acts as
 * an entry-point for the TLS 1.3 channel implementation. The default
 * implementations of the virtual methods in this class are typically no-ops, or
 * throw meaningful error if some DTLS-only functionality was accidentally
 * invoked from within a TLS connection.
 */
class DTLS_Channel_Companion {
   public:
      DTLS_Channel_Companion() = default;

      virtual ~DTLS_Channel_Companion() = default;

      DTLS_Channel_Companion(const DTLS_Channel_Companion&) = delete;
      DTLS_Channel_Companion& operator=(const DTLS_Channel_Companion&) = delete;
      DTLS_Channel_Companion(DTLS_Channel_Companion&&) = delete;
      DTLS_Channel_Companion& operator=(DTLS_Channel_Companion&&) = delete;

   public:
      /**
       * Notifies that the TLS state machine is sure that we're talking to a
       * peer using DTLS 1.3. Typically that is the case after receiving and
       * processing a HelloRetryRequest or ServerHello, or a ClientHello
       * indicating support for DTLS 1.3.
       */
      virtual void notify_protocol_version_committed() {}

      virtual void notify_sent_handshake_flight() {}

      virtual void clear_resend_buffer() {}

      virtual void clear_outstanding_acknowledgements() {}

      virtual bool timeout_check(Cipher_State* cipher_state) {
         BOTAN_UNUSED(cipher_state);
         return false;
      }

      virtual std::optional<std::chrono::milliseconds> next_retransmission_timeout() const { return std::nullopt; }

      virtual std::vector<uint8_t> current_ack_record() const {
         throw TLS_Exception(AlertType::InternalError, "Requested an ACK record despite not being DTLS");
      }

      virtual void process_acknowledgements(Cipher_State* cipher_state, std::span<const uint8_t> ack_record) {
         BOTAN_UNUSED(cipher_state, ack_record);
         throw TLS_Exception(AlertType::UnexpectedMessage, "Received ACKs despite not being DTLS");
      }
};

}  // namespace Botan::TLS

#endif
