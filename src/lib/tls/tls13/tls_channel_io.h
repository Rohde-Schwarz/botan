/*
* (D)TLS Channel IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IO_BASE_H_
#define BOTAN_TLS_CHANNEL_IO_BASE_H_

#include <botan/assert.h>
#include <botan/tls_exceptn.h>
#include <chrono>
#include <optional>

#include <botan/internal/tls_flight_13.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_record_layer_13.h>

namespace Botan::TLS {

class Secret_Logger;
class Cipher_State;
struct RecordNumber;

class Channel_IO : public std::enable_shared_from_this<Channel_IO> {
   protected:
      Channel_IO() = default;

   public:
      Channel_IO(const Channel_IO&) = delete;
      Channel_IO& operator=(const Channel_IO&) = delete;
      Channel_IO(Channel_IO&&) = delete;
      Channel_IO& operator=(Channel_IO&&) = delete;

      virtual ~Channel_IO() = default;

      // TODO: Consider making send_record private and exposing:
      // send_flight, send_alert, send_app_data, send_ccs
      virtual void send_record(Record_Type record_type,
                               std::span<const uint8_t> payload,
                               Cipher_State* cipher_state) = 0;
      virtual void send_record(const Flight& flight, Cipher_State* cipher_state) = 0;

      virtual void send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) = 0;
      virtual void send_acknowledgements() = 0;

      // TODO: Move all DTLS specifics to DTLS_Channel_IO, ideally no DTLS stuff should remain here.
      /**
       * Notifies that the TLS state machine is sure that we're talking to a
       * peer using DTLS 1.3. Typically that is the case after receiving and
       * processing a HelloRetryRequest or ServerHello, or a ClientHello
       * indicating support for DTLS 1.3.
       */
      virtual void notify_protocol_version_committed() {}

      virtual void notify_sent_handshake_flight() {}

      virtual bool protocol_version_committed() const { return false; }

      virtual void register_pending_key_update(const RecordNumber& record_number) { BOTAN_UNUSED(record_number); }

      virtual bool has_pending_key_update() const { return false; }

      virtual void maybe_clear_resend_buffer() {}

      /**
       * Notifies that a complete flight was received from the peer and
       * therefore no lost records are expected anymore. Typically, this is
       * called in the [Client/Server]_Impl_13::handle() methods of messages
       * that appear as "last message in a flight" or in post-handshake
       * messages.
       */
      virtual void clear_outstanding_acknowledgements() {}

      virtual bool timeout_check(Cipher_State* cipher_state) {
         BOTAN_UNUSED(cipher_state);
         return false;
      }

      virtual std::optional<std::chrono::milliseconds> next_retransmission_timeout() const { return std::nullopt; }

      virtual std::vector<uint8_t> current_ack_record(size_t max_plaintext_length) const {
         BOTAN_UNUSED(max_plaintext_length);
         throw TLS_Exception(AlertType::InternalError, "Requested an ACK record despite not being DTLS");
      }

      virtual void process_acknowledgements(Cipher_State* cipher_state,
                                            std::span<const uint8_t> ack_record,
                                            const Secret_Logger& secret_logger) {
         BOTAN_UNUSED(cipher_state, ack_record, secret_logger);
         throw TLS_Exception(AlertType::UnexpectedMessage, "Received ACKs despite not being DTLS");
      }
};

}  // namespace Botan::TLS

#endif
