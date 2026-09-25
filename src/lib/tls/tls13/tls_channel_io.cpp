/*
* TLS Channel - implementation for TLS 1.3
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_io.h>

#include <botan/tls_callbacks.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_messages_internal.h>

namespace Botan::TLS {

void TLS_Channel_IO::send_records(Record_Type record_type,
                                  std::span<const uint8_t> payload,
                                  Cipher_State* cipher_state) {
   for(const auto& [record_to_write, _] : m_record_layer->prepare_records(record_type, payload, cipher_state)) {
      m_callbacks->tls_emit_data(record_to_write);
   }
}

void TLS_Channel_IO::send(Flight flight, Cipher_State* cipher_state) {
   // TODO: Pass the Flight straight into the record layer to optimize the number of data copies

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

      for(const auto& [record_to_write, _] : m_record_layer->prepare_records(Record_Type::Handshake, msgs, cs)) {
         m_callbacks->tls_emit_data(record_to_write);
      }

      msgs.get().clear();
   };

   for(const auto& msg_info : flight.messages()) {
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

void TLS_Channel_IO::send_dummy_change_cipher_spec() {
   static constexpr std::array<uint8_t, 1> dummy_ccs = {0x01};
   send_records(Record_Type::ChangeCipherSpec, dummy_ccs, nullptr);
}

void TLS_Channel_IO::send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) {
   const auto msg_serialized_bytes = msg.serialize();
   const auto msg_marshalled_bytes = concat<MarshalledHandshakeMessage>(
      prepare_tls_handshake_header(Handshake_Type::KeyUpdate, msg_serialized_bytes), msg_serialized_bytes);

   const auto prepared_records =
      m_record_layer->prepare_records(Record_Type::Handshake, msg_marshalled_bytes, cipher_state);

   BOTAN_ASSERT_NOMSG(prepared_records.size() == 1);  // KeyUpdate is small enough to fit into a single record
   m_callbacks->tls_emit_data(prepared_records.front().first);

   // Immediately update the write keys after sending the
   // KeyUpdate message (in contrast to DTLS, we have
   // reliable transport and know it went through).
   cipher_state->update_write_keys(logger);
}

Channel_IO::ReceiveEvent TLS_Channel_IO::next_receive_event(Cipher_State* cipher_state,
                                                            Transcript_Hash_State* transcript_hash,
                                                            bool handshake_complete) {
   std::optional<Channel_IO::ReceiveEvent> res;

   while(!res.has_value()) {
      if(auto event = next_pending_handshake_message(transcript_hash, handshake_complete)) {
         // Handshake messages can be directly consumed by the channel
         res = std::move(event);
         break;
      }

      res = std::visit(  //
         overloaded{
            [](BytesNeeded bytes) -> std::optional<Channel_IO::ReceiveEvent> { return bytes; },
            [&](Record_Content record) -> std::optional<Channel_IO::ReceiveEvent> {
               switch(record.type) {
                  case Record_Type::Handshake:
                     // Handshake records need to be fed to the handshake layer before
                     // their messages can be consumed by the channel
                     feed_handshake_record(record);
                     return std::nullopt;

                  case Record_Type::ChangeCipherSpec:
                  case Record_Type::ApplicationData:
                  case Record_Type::Alert:
                     // CCS, AppData or alert can be directly consumed by the channel
                     return record;

                  default:
                     throw Unexpected_Message("Unexpected record type received");
               }
            },
         },
         pull_record(cipher_state));
   }

   return std::move(res).value();
}

}  // namespace Botan::TLS
