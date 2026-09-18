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
#include <optional>

#include <botan/internal/stl_util.h>
#include <botan/internal/tls_flight_13.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_record_layer_13.h>

namespace Botan::TLS {

class Secret_Logger;
class Cipher_State;
class Channel_Impl_13;
struct RecordNumber;

class Channel_IO {
   public:
      using ReceiveEvent = std::variant<BytesNeeded,  //
                                        Handshake_Message_13,
                                        Post_Handshake_Message_13,
                                        Record_Content>;

      static std::unique_ptr<Channel_IO> create(TLS_Flavor flavor,
                                                Connection_Side side,
                                                Channel_Impl_13& channel,
                                                const Secret_Logger& secret_logger,
                                                std::shared_ptr<const Policy> policy,
                                                std::shared_ptr<Callbacks> callbacks);

   protected:
      Channel_IO(TLS_Flavor flavor,
                 Connection_Side side,
                 std::shared_ptr<const Policy> policy,
                 std::shared_ptr<Callbacks> callbacks) :
            m_record_layer(Record_Layer::create(side, flavor, policy, callbacks)),
            m_handshake_layer(Handshake_Layer::create(side, flavor)),
            m_policy(std::move(policy)),
            m_callbacks(std::move(callbacks)) {}

   public:
      Channel_IO(const Channel_IO&) = delete;
      Channel_IO& operator=(const Channel_IO&) = delete;
      Channel_IO(Channel_IO&&) = delete;
      Channel_IO& operator=(Channel_IO&&) = delete;

      virtual ~Channel_IO() = default;

      // TODO: Consider making send_record private and exposing:
      // send_flight, send_alert, send_app_data, send_ccs
      virtual void send_records(Record_Type record_type,
                                std::span<const uint8_t> payload,
                                Cipher_State* cipher_state) = 0;
      virtual void send(Flight flight, Cipher_State* cipher_state) = 0;

      virtual void send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) = 0;

      virtual void ingest_records(std::span<const uint8_t> data) = 0;

      virtual ReceiveEvent next_receive_event(Cipher_State* cipher_state,
                                              Transcript_Hash_State* transcript_hash,
                                              bool handshake_complete) = 0;

      /**
       * Notifies that the TLS state machine is sure that we're talking to a
       * peer using (D)TLS 1.3. Typically that is the case after receiving and
       * processing a ServerHello or a ClientHello indicating support for (D)TLS
       * 1.3.
       *
       * This is relevant for DTLS: before this point, lost records must be
       * recovered by retransmitting entire flights (1.2-style); only afterwards
       * may the ACK mechanism (RFC 9147 7.) be relied upon.
       *
       * For the case of receiving a HelloRetryRequest, use
       * notify_protocol_version_committed_and_flight_superseded().
       */
      virtual void notify_protocol_version_committed() = 0;

      /**
       * Like notify_protocol_version_committed(), but for the case where
       * committing message additionally supersedes the flight currently held
       * for retransmission. This is the case exactly for a HelloRetryRequest.
       *
       * This difference is only relevant for DTLS: Since the buffered flight
       * (the initial ClientHello) is superseded by the response about to be
       * sent, retransmitting it would be wrong. So in addition to commiting the
       * protocol version, this method also clears the resend buffer and
       * retransmission timer.
       */
      virtual void notify_protocol_version_committed_and_flight_superseded() = 0;

      /**
       * Notifies that the last message completing a flight was received.
       *
       * This is relevant for DTLS: At that point, everything we need
       * was received and the ACK mechanism is no longer needed.
       */
      virtual void notify_received_complete_flight() = 0;

      /**
       * Notifies that a complete flight was received that expects no response,
       * i.e., the final flight of the peer (the client's Finished).
       *
       * This is relevant for DTLS: since there is no response flight
       * that would implicitly acknowledge it, the flight must be acknowledged
       * explicitly with an ACK message.
       */
      virtual void notify_received_final_flight() = 0;

      /**
       * Notifies that the channel is closed for reading (close_notify received).
       * The IO can discard any read-side state; no further data will be processed.
       */
      void notify_closed_for_reading() { m_record_layer->clear_read_buffer(); }

      void set_record_size_limits(uint16_t out, uint16_t in) { m_record_layer->set_record_size_limits(out, in); }

      void set_selected_certificate_type(Certificate_Type t) { m_handshake_layer->set_selected_certificate_type(t); }

      std::optional<Epoch0_SequenceNumbers> epoch0_sequence_numbers() const {
         // TODO: If possible, remove optional, make this DTLS-only
         return m_record_layer->epoch0_sequence_numbers();
      }

   protected:
      std::optional<ReceiveEvent> next_pending_handshake_message(Transcript_Hash_State* transcript_hash,
                                                                 bool handshake_complete) {
         if(!handshake_complete) {
            BOTAN_ASSERT_NONNULL(transcript_hash);
            auto handshake_msg = m_handshake_layer->next_message(*m_policy, *transcript_hash);
            if(!handshake_msg.has_value()) {
               return std::nullopt;
            }

            // RFC 8446 5.1
            //    Handshake messages MUST NOT span key changes.  Implementations
            //    MUST verify that all messages immediately preceding a key change
            //    align with a record boundary; if not, then they MUST terminate the
            //    connection with an "unexpected_message" alert.  Because the
            //    ClientHello, EndOfEarlyData, ServerHello, Finished, and KeyUpdate
            //    messages can immediately precede a key change, implementations
            //    MUST send these messages in alignment with a record boundary.
            //
            // Note: Hello_Retry_Request was added to the list below although it cannot immediately precede a key change.
            //       However, there cannot be any further sensible messages in the record after HRR.
            //
            // Note: Server_Hello_12 was deliberately not included in the check below because in TLS 1.2 Server Hello and
            //       other handshake messages can be legally coalesced in a single record.
            //
            // TODO: This should be handled differently for DTLS
            // Kimi: need per-record bookkeeping: copy_data should record
            // whether the fragment completing a message was followed by
            // more fragments in the same record, and attach that flag to
            // the ReassembledMessage, rather than inferring it from
            // global map state.
            if(holds_any_of<Client_Hello_12_Shim,
                            Client_Hello_13 /*, EndOfEarlyData,*/,
                            Server_Hello_13,
                            Hello_Verify_Request,  // DTLS 1.3 -> 1.2 downgrade
                            Hello_Retry_Request,
                            Finished_13>(handshake_msg.value()) &&
               m_handshake_layer->has_pending_data()) {
               throw Unexpected_Message("Unexpected additional handshake message data found in record");
            }

            // After the initial handshake message is received, the record
            // layer must be more restrictive.
            // See RFC 8446 5.1 regarding "legacy_record_version"
            if(!m_first_message_delivered) {
               // TODO: Consider always calling disable_receiving_compat_mode
               // to get rid of m_first_message_delivered
               m_record_layer->disable_receiving_compat_mode();
               m_first_message_delivered = true;
            }
            return ReceiveEvent(std::move(handshake_msg.value()));
         }

         // if handshake_complete
         auto post_handshake_msg = m_handshake_layer->next_post_handshake_message(*m_policy);
         if(!post_handshake_msg.has_value()) {
            return std::nullopt;
         }

         // make sure Key_Update appears only at the end of a record; see RFC
         // 8446 5.1 description above
         //
         // TODO: This doesn't work for DTLS, because the data may be delivered
         //       out-of-order. This check assumes reliable stream semantics of
         //       the underlying transport.
         if(std::holds_alternative<Key_Update>(post_handshake_msg.value()) && m_handshake_layer->has_pending_data()) {
            throw Unexpected_Message("Unexpected additional post-handshake message data found in record");
         }

         return ReceiveEvent(std::move(post_handshake_msg.value()));
      }

      Record_Layer::ReadResult<Record_Content> pull_record(Cipher_State* cipher_state) {
         return std::visit(
            overloaded{[](BytesNeeded bytes) -> Record_Layer::ReadResult<Record_Content> { return bytes; },
                       [&](const Record_Content& record) -> Record_Layer::ReadResult<Record_Content> {
                          // RFC 8446 5.1
                          //   Handshake messages MUST NOT be interleaved with other record types.
                          if(record.type != Record_Type::Handshake && m_handshake_layer->has_pending_data()) {
                             throw Unexpected_Message("Expected remainder of a handshake message");
                          }

                          return record;
                       }},
            m_record_layer->next_record(cipher_state));
      }

      bool feed_handshake_record(const Record_Content& record) {
         return m_handshake_layer->copy_data(*m_policy, record.payload, record.epoch);
      }

   protected:
      std::unique_ptr<Record_Layer> m_record_layer;        // NOLINT(*non-private-member-variable*)
      std::unique_ptr<Handshake_Layer> m_handshake_layer;  // NOLINT(*non-private-member-variable*)
      std::shared_ptr<const Policy> m_policy;              // NOLINT(*non-private-member-variable*)
      std::shared_ptr<Callbacks> m_callbacks;              // NOLINT(*non-private-member-variable*)
      bool m_first_message_delivered = false;              // NOLINT(*non-private-member-variable*)
};

class TLS_Channel_IO final : public Channel_IO {
   public:
      TLS_Channel_IO(Connection_Side side, std::shared_ptr<const Policy> policy, std::shared_ptr<Callbacks> callbacks) :
            Channel_IO(TLS_Flavor::TLS, side, std::move(policy), std::move(callbacks)) {}

      void send_records(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override;

      void send(Flight flight, Cipher_State* cipher_state) override;

      void send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) override;

      void ingest_records(std::span<const uint8_t> data) override { m_record_layer->copy_data(data); }

      ReceiveEvent next_receive_event(Cipher_State* cipher_state,
                                      Transcript_Hash_State* transcript_hash,
                                      bool handshake_complete) override;

      void notify_protocol_version_committed() override {
         // In TLS, we do not care about this.
      }

      void notify_protocol_version_committed_and_flight_superseded() override {
         // In TLS, we do not care about this.
      }

      void notify_received_complete_flight() override {
         // In TLS, we do not care about this.
      }

      void notify_received_final_flight() override {
         // In TLS, we do not care about this.
      }
};

}  // namespace Botan::TLS

#endif
