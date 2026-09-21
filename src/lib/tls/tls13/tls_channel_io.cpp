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

   // RFC 9846 E.4 placement:
   //  - client: immediately before its second flight (second ClientHello
   //    or the encrypted handshake flight).
   //  - server: immediately after its first handshake message, i.e., at the
   //    unprotected -> protected transition, or after an all-unprotected
   //    flight (HelloRetryRequest).
   const bool is_client = m_record_layer->side() == Connection_Side::Client;

   if(flight.send_ccs() && is_client) {
      send_dummy_change_cipher_spec();
   }
   bool ccs_pending = flight.send_ccs() && !is_client;

   // Now, we go through all messages of the flight, grouping them into
   // two runs, one for the unprotected messages and one for the
   // protected messages.
   auto current_prepared = MarshalledHandshakeMessageFlight();
   bool protect_current_prepared = false;

   auto prepare_and_flush_current_prepared = [&]() {
      if(current_prepared.get().empty()) {
         return;
      }

      // Messages with a desired_epoch Unprotected must go out in plaintext
      // records, even if a cipher_state is provided by the caller.
      auto* run_cipher_state = protect_current_prepared ? cipher_state : nullptr;
      for(const auto& [record_to_write, _] :
          m_record_layer->prepare_records(Record_Type::Handshake, current_prepared, run_cipher_state)) {
         m_callbacks->tls_emit_data(record_to_write);
      }
      current_prepared.get().clear();
   };

   // TODO: First figure out how much data we need to fully concatenate, then pre-allocate, then copy.
   for(const auto& msg_info : flight.messages()) {
      // For post-handshake messages, desired_epoch is nullopt
      const bool protect = !msg_info.desired_epoch.has_value() || *msg_info.desired_epoch > Epoch_Number::Unprotected;
      if(!current_prepared.get().empty() && protect != protect_current_prepared) {
         prepare_and_flush_current_prepared();
         if(ccs_pending) {
            // Transition unprotected->protected, this is where we send the dummy CCS if still pending
            send_dummy_change_cipher_spec();
            ccs_pending = false;
         }
      }
      protect_current_prepared = protect;

      current_prepared.get().insert(current_prepared.get().end(), msg_info.header.begin(), msg_info.header.end());
      current_prepared.get().insert(
         current_prepared.get().end(), msg_info.serialized.begin(), msg_info.serialized.end());
   }

   prepare_and_flush_current_prepared();

   if(ccs_pending) {
      // all-unprotected flight (HelloRetryRequest)
      BOTAN_STATE_CHECK(cipher_state == nullptr);
      send_dummy_change_cipher_spec();
   }
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
