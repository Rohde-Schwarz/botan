/*
* TLS 1.3 Channel I/O
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_io.h>

#include <botan/tls_callbacks.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_messages_internal.h>

#if defined(BOTAN_HAS_DTLS_13)
   #include <botan/internal/tls_channel_io_dtls13.h>
#endif

namespace Botan::TLS {

std::optional<Channel_IO::ReceiveEvent> Channel_IO::next_pending_handshake_message(
   Transcript_Hash_State* transcript_hash, bool handshake_complete) {
   auto& hs_layer = handshake_layer();
   auto& rec_layer = record_layer();

   if(!handshake_complete) {
      BOTAN_ASSERT_NONNULL(transcript_hash);
      auto handshake_msg = hs_layer.next_message(*m_policy, *transcript_hash);
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
         hs_layer.has_pending_data()) {
         throw Unexpected_Message("Unexpected additional handshake message data found in record");
      }

      // After the initial handshake message is received, the record
      // layer must be more restrictive.
      // See RFC 8446 5.1 regarding "legacy_record_version"
      if(!m_first_message_delivered) {
         // TODO: Consider always calling disable_receiving_compat_mode
         // to get rid of m_first_message_delivered
         rec_layer.disable_receiving_compat_mode();
         m_first_message_delivered = true;
      }

      return std::move(handshake_msg).value();
   } else {
      auto post_handshake_msg = hs_layer.next_post_handshake_message(*m_policy);
      if(!post_handshake_msg.has_value()) {
         return std::nullopt;
      }

      // make sure Key_Update appears only at the end of a record; see RFC
      // 8446 5.1 description above
      //
      // TODO: This doesn't work for DTLS, because the data may be delivered
      //       out-of-order. This check assumes reliable stream semantics of
      //       the underlying transport.
      if(std::holds_alternative<Key_Update>(post_handshake_msg.value()) && hs_layer.has_pending_data()) {
         throw Unexpected_Message("Unexpected additional post-handshake message data found in record");
      }

      return std::move(post_handshake_msg).value();
   }
}

void Channel_IO::copy_data(std::span<const uint8_t> data) {
   auto* cipher_state = channel()->cipher_state();
   const auto has_cryptographic_association =
      (cipher_state != nullptr) && cipher_state->has_cryptographic_association();

   record_layer().copy_data(data, has_cryptographic_association);
}

Channel_IO::ReceiveEvent Channel_IO::next_pending_event(Transcript_Hash_State* transcript_hash,
                                                        bool handshake_complete) {
   while(true) {
      // First we check if the handshake layer has any complete messages ready
      // to be consumed by the channel. If yes, we return that message....
      if(auto event = next_pending_handshake_message(transcript_hash, handshake_complete)) {
         // Handshake messages can be directly consumed by the channel
         return std::move(event).value();
      }

      // ... otherwise we check if the record layer has any complete records
      // ready to be processed. If yes, we dispatch the record to the
      // appropriate handler or return it to the channel (e.g. application data,
      // alerts, etc.). If no complete record is available, we return a
      // BytesNeeded event which indicates that no more events are available and
      // the channel needs to wait for the application to provide more data.
      auto res = std::visit(  //
         overloaded{
            [&](const Handshake_Record& record) -> std::optional<Channel_IO::ReceiveEvent> {
               process(record);
               return std::nullopt;  // continue looping, the handshake layer may have progressed...
            },
            [&](const ACK_Record& record) -> std::optional<Channel_IO::ReceiveEvent> {
               process(record);
               return std::nullopt;  // continue looping, the record layer may have more data...
            },
            [](auto anything_else) -> std::optional<Channel_IO::ReceiveEvent> { return anything_else; },
         },
         record_layer().next_record(channel()->cipher_state()));

      if(res.has_value()) {
         return std::move(res).value();
      }
   }
}

void Channel_IO::send(std::span<const uint8_t> payload) {
   send_data(Record_Type::ApplicationData, payload, channel()->cipher_state());
}

void Channel_IO::send(const Alert& alert) {
   send_data(Record_Type::Alert, alert.serialize(), channel()->cipher_state());
}

void Channel_IO::send_dummy_change_cipher_spec() {
   constexpr auto ccs = std::array<uint8_t, 1>{0x01};
   send_data(Record_Type::ChangeCipherSpec, ccs, nullptr);
}

void Channel_IO::notify_closed_for_reading() {
   record_layer().clear_read_buffer();
}

void Channel_IO::set_record_size_limits(uint16_t out, uint16_t in) {
   record_layer().set_record_size_limits(out, in);
}

void Channel_IO::set_selected_certificate_type(Certificate_Type t) {
   handshake_layer().set_selected_certificate_type(t);
}

std::optional<Epoch0_SequenceNumbers> Channel_IO::epoch0_sequence_numbers() const {
   // TODO: If possible, remove optional, make this DTLS-only
   return record_layer().epoch0_sequence_numbers();
}

std::shared_ptr<const Channel_Impl_13> Channel_IO::channel() const {
   auto channel = m_channel.lock();
   BOTAN_ASSERT_NONNULL(channel);
   return channel;
}

std::shared_ptr<Channel_Impl_13> Channel_IO::channel() {
   auto channel = m_channel.lock();
   BOTAN_ASSERT_NONNULL(channel);
   return channel;
}

namespace {

class TLS_Channel_IO final : public Channel_IO {
   public:
      TLS_Channel_IO(Connection_Side side,
                     std::weak_ptr<Channel_Impl_13> channel,
                     std::shared_ptr<const Policy> policy,
                     std::shared_ptr<Callbacks> callbacks) :
            Channel_IO(std::move(channel), policy, std::move(callbacks)),
            m_record_layer(side, std::move(policy)),
            m_handshake_layer(side) {}

      void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override;

      void send_flight(std::vector<Flight::Message> flight) override;

      void send_key_update(Key_Update msg) override;

      void process(const Handshake_Record& record) override {
         std::ignore = m_handshake_layer.copy_data(policy(), record);
      }

      void process(const ACK_Record& ack_record) override {
         BOTAN_UNUSED(ack_record);
         throw Unexpected_Message("Received ACK record in TLS 1.3");
      }

      Record_Layer& record_layer() override { return m_record_layer; }

      const Record_Layer& record_layer() const override { return m_record_layer; }

      Handshake_Layer& handshake_layer() override { return m_handshake_layer; }

      const Handshake_Layer& handshake_layer() const override { return m_handshake_layer; }

   private:
      TLS_Record_Layer m_record_layer;
      TLS_Handshake_Layer m_handshake_layer;
};

}  // namespace

std::unique_ptr<Channel_IO> Channel_IO::create(TLS_Flavor flavor,
                                               Connection_Side side,
                                               const std::shared_ptr<Channel_Impl>& channel,
                                               std::shared_ptr<const Policy> policy,
                                               std::shared_ptr<Callbacks> callbacks) {
   auto channel_13 = std::dynamic_pointer_cast<Channel_Impl_13>(channel);
   if(flavor == TLS_Flavor::DTLS) {
#if defined(BOTAN_HAS_DTLS_13)
      return std::make_unique<DTLS_Channel_IO>(side, channel_13, std::move(policy), std::move(callbacks));
#else
      throw Not_Implemented("DTLS 1.3 is not enabled in this build of Botan");
#endif
   } else {
      BOTAN_UNUSED(channel);
      return std::make_unique<TLS_Channel_IO>(side, channel_13, std::move(policy), std::move(callbacks));
   }
}

void TLS_Channel_IO::send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) {
   const size_t max_plaintext_payload_size = record_layer().record_payload_size_limit(policy(), cipher_state);

   // RFC 9846 5.1
   //    Handshake messages MAY be [...] fragmented across several records.
   //    [...] Application Data fragments MAY be split across multiple records
   //    [...].
   //
   // In TLS, we may fragment application data and handshake data into multiple
   // records. Other record types are not allowed to be fragmented.
   BOTAN_ASSERT_IMPLICATION(payload.size() > max_plaintext_payload_size,
                            record_type == Record_Type::ApplicationData || record_type == Record_Type::Handshake,
                            "Application Data records MUST NOT be zero-length");

   BufferSlicer bs(payload);

   // RFC 9846 5.1
   //    Zero-length fragments of Application Data [...] MAY be sent, as they
   //    are potentially useful as a traffic analysis countermeasure.
   //
   // We're using a do-while loop to ensure that we process at least one slice
   // of the payload, even if that first slice is empty.
   do /* NOLINT(*-avoid-do-while) */ {
      const size_t pt_size = std::min(bs.remaining(), max_plaintext_payload_size);
      const auto pt_fragment = bs.take(pt_size);

      const auto [record_to_write, _] = m_record_layer.prepare_record(record_type, pt_fragment, cipher_state);
      callbacks().tls_emit_data(record_to_write);
   } while(!bs.empty());
}

void TLS_Channel_IO::send_flight(std::vector<Flight::Message> flight) {
   // TODO: Pass the Flight straight into the record layer to optimize the number of data copies

   auto* cipher_state = channel()->cipher_state();

   // Now, we go through all messages of the flight, grouping them into
   // two runs, one for the unprotected messages and one for the
   // protected messages.
   bool protect_current_msgs = false;
   auto msgs = MarshalledHandshakeMessageFlight();

   auto prepare_and_flush_current_prepared = [&](bool protect) {
      if(msgs.get().empty()) {
         return;
      }

      BOTAN_ASSERT_IMPLICATION(
         protect, cipher_state != nullptr, "Cipher State is available when messages require protection");
      auto* cs = protect ? cipher_state : nullptr;

      send_data(Record_Type::Handshake, msgs, cs);

      msgs.get().clear();
   };

   for(const auto& msg_info : flight) {
      std::visit(  //
         overloaded{
            [&](const Flight::Dummy_ChangeCipherSpec&) {
               // We reached a dummy CCS. Before that only unprotected
               // messages were allowed. Flush those (if any).
               BOTAN_STATE_CHECK(!protect_current_msgs);
               prepare_and_flush_current_prepared(false /* no protection */);

               // Then send the dummy CCS record.
               send_dummy_change_cipher_spec();
            },
            [&](const Flight::Message_Info& msg_info) {
               const bool protect = !msg_info.epoch.has_value() || msg_info.epoch > Epoch_Number::Unprotected;

               if(!protect) {
                  // Once we have reached the first protected message, all
                  // subsequent messages must be protected as well.
                  BOTAN_ASSERT_NOMSG(!protect_current_msgs);
               } else if(!protect_current_msgs) {
                  // We reached the first protected message. Flush the
                  // unprotected ones (if any).
                  prepare_and_flush_current_prepared(false /* no protection */);
                  BOTAN_DEBUG_ASSERT(msgs.empty());
                  protect_current_msgs = true;
               }

               // Collect marshalled messages into the current run.
               msgs.get().insert(msgs.get().end(), msg_info.header.begin(), msg_info.header.end());
               msgs.get().insert(msgs.get().end(), msg_info.serialized.begin(), msg_info.serialized.end());
            },
         },
         msg_info);
   }

   // After we have processed all messages of the given flight, flush the last
   // run of messages (if any).
   prepare_and_flush_current_prepared(protect_current_msgs);
}

void TLS_Channel_IO::send_key_update(Key_Update msg) {
   const auto msg_serialized_bytes = msg.serialize();
   const auto msg_marshalled_bytes = concat<MarshalledHandshakeMessage>(
      prepare_tls_handshake_header(Handshake_Type::KeyUpdate, msg_serialized_bytes), msg_serialized_bytes);

   auto ch = channel();
   send_data(Record_Type::Handshake, msg_marshalled_bytes, ch->cipher_state());

   // Immediately update the write keys after sending the
   // KeyUpdate message (in contrast to DTLS, we have
   // reliable transport and know it went through).
   ch->cipher_state()->update_write_keys(ch->secret_logger());
}

}  // namespace Botan::TLS
