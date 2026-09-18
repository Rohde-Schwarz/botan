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
   auto prepared = MarshalledHandshakeMessageFlight();

   // TODO: First figure out how much data we need to fully concatenate, then pre-allocate, then copy.
   for(const auto& msg_info : flight.messages()) {
      auto& flat = prepared.get();
      flat.insert(flat.end(), msg_info.header.begin(), msg_info.header.end());
      flat.insert(flat.end(), msg_info.serialized.begin(), msg_info.serialized.end());
   }

   // TODO: Pass the Flight straight into the record layer to optimize the number of data copies
   for(const auto& [record_to_write, _] :
       m_record_layer->prepare_records(Record_Type::Handshake, prepared, cipher_state)) {
      m_callbacks->tls_emit_data(record_to_write);
   }
}

void TLS_Channel_IO::send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) {
   const auto msg_bytes = concat<MarshalledHandshakeMessage>(
      prepare_tls_handshake_header(Handshake_Type::KeyUpdate, msg.serialize()), msg.serialize());

   const auto prepared_records = m_record_layer->prepare_records(Record_Type::Handshake, msg_bytes, cipher_state);

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
   while(true) {
      if(auto event = next_pending_handshake_message(transcript_hash, handshake_complete)) {
         // Handshake messages can be directly consumed by the channel
         return std::move(event.value());
      }

      auto result = pull_record(cipher_state);
      if(std::holds_alternative<BytesNeeded>(result)) {
         return std::get<BytesNeeded>(result);
      }

      // TODO: double-check if we can do the record type validation fully here
      //       (similarly as we do with ACK)
      const auto& record = std::get<Record_Content>(result);
      if(record.type == Record_Type::Handshake) {
         // Handshake records need to be fed to the handshake layer before
         // their messages can be consumed by the channel
         feed_handshake_record(record);
      } else if(record.type == Record_Type::ACK) {
         throw Unexpected_Message("Received ACKs despite not being DTLS");
      } else {
         // CCS, AppData or alert can be directly consumed by the channel
         return record;
      }
   }
}

}  // namespace Botan::TLS
