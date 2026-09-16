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

/**
 * Token owned by a DTLS_Channel_IO object as a shared_ptr
 * and passed to deferred operations as a weak_ptr.
 * This ensures that the DTLS_Channel_IO object is still alive
 * if the token is still present.
 */
class DTLS_Channel_IO::TimerToken {
   public:
      explicit TimerToken(DTLS_Channel_IO& channel_io) : m_channel_io(channel_io) {}

      DTLS_Channel_IO& channel_io() { return m_channel_io; }

   private:
      DTLS_Channel_IO& m_channel_io;
};

DTLS_Channel_IO::DTLS_Channel_IO(Channel_Impl_13& channel,
                                 std::shared_ptr<const Policy> policy,
                                 std::shared_ptr<Callbacks> callbacks,
                                 std::shared_ptr<Record_Layer> record_layer,
                                 std::shared_ptr<Handshake_Layer> handshake_layer) :
      m_policy(std::move(policy)),
      m_callbacks(std::move(callbacks)),
      m_record_layer(std::dynamic_pointer_cast<DTLS_Record_Layer>(std::move(record_layer))),
      m_handshake_layer(std::dynamic_pointer_cast<DTLS_Handshake_Layer>(std::move(handshake_layer))),
      m_channel(channel),
      m_retransmission_timer(*m_policy, m_callbacks) {
   BOTAN_ASSERT_NONNULL(m_callbacks);
   BOTAN_ASSERT_NONNULL(m_record_layer);
   BOTAN_ASSERT_NONNULL(m_handshake_layer);
}

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
   maybe_cancel_dtls_acknowledgement_timer();
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

   // TODO: BoGo is completely green if we forget to
   // arm the retransmission timer here -> add a regression test.
   // But here it may be possible that the timer is not started.
   // If we just reset it, it may possibly interfere with
   // a retransmission of the last client flight, have to check
   // that again.
   m_retransmission_timer.start_if_not_started();
   arm_dtls_retransmission_timer();
}

void DTLS_Channel_IO::send_acknowledgements() {
   const auto max_plaintext_length = m_record_layer->record_payload_size_limit(*m_policy, m_channel.cipher_state());
   send_record(Record_Type::ACK, current_ack_record(max_plaintext_length), m_channel.cipher_state());
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

void DTLS_Channel_IO::arm_dtls_retransmission_timer() {
   const auto next_timeout = next_retransmission_timeout();

   // If there is no timeout, the handshake is complete or there is no handshake
   // in progress, so there is nothing to arm a timer for.
   if(!next_timeout.has_value()) {
      return;
   }

   // We invalidate any other timer chain that might still be
   // running from a backoff interval that has been cut short by incoming data
   // from the peer by dropping any possible previous m_retransmission_token.
   m_retransmission_token = std::make_shared<TimerToken>(*this);

   // The actual asynchronous operation:
   auto on_timer = [token = std::weak_ptr(m_retransmission_token)]() mutable {
      // If this operation is called after the channel implementation is gone,
      // the channel magically became some other type, or the token was consumed
      // because the operation was called more than once (see below) just return.
      auto handle = token.lock();
      if(!handle) {
         // Arming superseded, cancelled, or channel gone
         return;
      }

      auto& io = handle->channel_io();
      io.m_retransmission_token.reset();  // firing consumes the token
      io.on_retransmission_timer();
   };

   m_callbacks->tls_register_deferred_operation(next_timeout->count(), on_timer);
}

void DTLS_Channel_IO::on_retransmission_timer() {
   timeout_check(m_channel.cipher_state());

   // Spawn the next timer generation for the next backoff interval in this
   // chain. This will be a no-op if the timer is no longer needed.
   arm_dtls_retransmission_timer();
}

void DTLS_Channel_IO::maybe_arm_dtls_acknowledgement_timer() {
   const auto ack_time = m_policy->dtls_initial_timeout() / 4;

   if(!m_ack_token && protocol_version_committed()) {
      m_ack_token = std::make_shared<TimerToken>(*this);

      m_callbacks->tls_register_deferred_operation(ack_time, [token = std::weak_ptr(m_ack_token)] {
         auto handle = token.lock();
         if(!handle) {
            return;
         }

         auto& channel_io = handle->channel_io();

         // The ACK timer is meant to be single-shot. We reset the ACK timer
         // handle to let belated or resent fragments start a new ACK timer.
         // Note the difference to the retransmission timer, where any new
         // armament supersedes and invalidates any prior deferred op.
         channel_io.m_ack_token.reset();

         channel_io.send_acknowledgements();
      });
   }
}

void DTLS_Channel_IO::maybe_cancel_dtls_acknowledgement_timer() {
   m_ack_token.reset();
}

}  // namespace Botan::TLS
