/*
* DTLS 1.3 Channel IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_io_dtls13.h>

#include <botan/internal/tls_channel_impl_13.h>

namespace Botan::TLS {

void DTLS_Channel_IO::send_record(Record_Type record_type,
                                  std::span<const uint8_t> payload,
                                  Cipher_State* cipher_state) {
   for(const auto& [record_to_write, _] : m_record_layer->prepare_records(record_type, payload, cipher_state)) {
      m_callbacks->tls_emit_data(record_to_write);
   }
}

void DTLS_Channel_IO::send_record(const Flight& flight, Cipher_State* cipher_state) {
   const auto max_payload_size = m_record_layer->record_payload_size_limit(*m_policy, cipher_state);

   auto prepared = std::vector<MarshalledHandshakeMessageFragment>{};

   for(const auto& msg_info : flight.messages()) {
      auto frags = m_handshake_layer->fragment_message(msg_info.type, msg_info.serialized, max_payload_size);

      prepared.insert(prepared.end(), std::make_move_iterator(frags.begin()), std::make_move_iterator(frags.end()));
   }

   for(const auto& [record_to_write, _] : m_record_layer->prepare_records(prepared, cipher_state)) {
      m_callbacks->tls_emit_data(record_to_write);
   }

   notify_sent_handshake_flight();
   arm_dtls_retransmission_timer();
}

void DTLS_Channel_IO::send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) {
   BOTAN_UNUSED(logger);  // Actual key update is deferred to ACK receiving
   auto msg_bytes = m_handshake_layer->fragment_message(Handshake_Type::KeyUpdate, msg.serialize(), 13);

   const auto prepared_records = m_record_layer->prepare_records(msg_bytes, cipher_state);

   BOTAN_ASSERT_NOMSG(prepared_records.size() == 1);  // KeyUpdate is small enough to fit into a single record
   m_callbacks->tls_emit_data(prepared_records.front().first);

   // RFC 9147 8.
   //    [...]  KeyUpdates MUST be acknowledged. In order to facilitate epoch
   //    reconstruction [...], implementations MUST NOT send records with the
   //    new keys or send a new KeyUpdate until the previous KeyUpdate has
   //    been acknowledged [...].
   //
   // The actual call to cipher_state->update_write_keys() is
   // deferred to the handling of the respective acknowledgement.
   const auto key_update_record_number = prepared_records.front().second;
   register_pending_key_update(key_update_record_number);

   arm_dtls_retransmission_timer();
}

bool DTLS_Channel_IO::timeout_check(Cipher_State* cipher_state) {
   if(!m_retransmission_timer.started()) {
      return false;
   }

   if(m_retransmission_timer.retransmissions_exhausted()) {
      throw TLS_Exception(Alert::None, "DTLS handshake timed out: maximum retransmissions exceeded");
   }

   if(!m_retransmission_timer.expired()) {
      return false;  // timer has not yet expired
   }

   for(const auto& record_to_write : m_record_layer->prepare_unacknowledged_records(cipher_state)) {
      m_callbacks->tls_emit_data(record_to_write);
   }
   m_retransmission_timer.retransmitted();
   return true;
}

void DTLS_Channel_IO::arm_dtls_retransmission_timer(TimerGeneration generation_policy) {
   const auto next_timeout = next_retransmission_timeout();

   // If there is no timeout, the handshake is complete or there is no handshake
   // in progress, so there is nothing to arm a timer for.
   if(!next_timeout.has_value()) {
      return;
   }

   // If a new timer generation was requested, we increment the channel-wide
   // generation counter to invalidate any other timer chain that might still be
   // running from a backoff interval that has been cut short by incoming data
   // from the peer.
   if(generation_policy == TimerGeneration::Advance) {
      ++m_retransmission_timer_generation;
   }

   // The actual asynchronous operation:
   auto on_timer = [self = weak_from_this(), generation = m_retransmission_timer_generation]() mutable {
      // If this operation is called after the channel implementation is gone,
      // the channel magically became some other type, or the operation was
      // called more than once (see below) just return.
      auto io = std::dynamic_pointer_cast<DTLS_Channel_IO>(self.lock());
      if(!io) {
         return;
      }

      // Ensures that if the user erronerously performs subsequent invocations of this operation,
      // these will be harmless no-ops.
      self.reset();

      io->on_retransmission_timer(generation);
   };

   m_callbacks->tls_register_deferred_operation(next_timeout->count(), on_timer);
}

void DTLS_Channel_IO::on_retransmission_timer(uint64_t generation) {
   // This timer-chain may have been superseded by a newer one, when a
   // backoff interval was reset by the arrival of a belated handshake
   // message. This generation is no longer active and ends here.
   if(generation != m_retransmission_timer_generation) {
      return;
   }

   // Now we know that we're on the active retransmission/backoff
   // chain...
   if(timeout_check(m_channel.cipher_state())) {
      // ... and a retransmission was performed: Spawn the next timer
      // generation for the next backoff interval in this chain.
      arm_dtls_retransmission_timer(TimerGeneration::Advance);
   } else {
      // ... but no retransmission was performed. Either, because the user
      // invoked the operation too early, in which case we will just reset
      // the timer for the remaining time until the next deadline, or a
      // retransmission was not needed anymore (because the peer's flight
      // arrived), then maybe_arm_* will not re-arm the timer.
      arm_dtls_retransmission_timer(TimerGeneration::Keep);
   }
}

}  // namespace Botan::TLS
