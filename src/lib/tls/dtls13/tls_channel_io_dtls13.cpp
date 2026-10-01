/*
* DTLS 1.3 Channel I/O
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_io_dtls13.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_cipher_state_dtls13.h>

#include <limits>
#include <utility>

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

DTLS_Channel_IO::DTLS_Channel_IO(Connection_Side side,
                                 std::shared_ptr<const Policy> policy_ptr,
                                 std::shared_ptr<Callbacks> callbacks) :
      Channel_IO(policy_ptr, callbacks),
      m_record_layer(side, std::move(policy_ptr), callbacks),
      m_handshake_layer(side),
      m_retransmission_timer(policy(), std::move(callbacks)) {}

void DTLS_Channel_IO::send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) {
   const auto [prepared_record, _] = m_record_layer.prepare_record(record_type, payload, cipher_state);
   callbacks().tls_emit_data(prepared_record);
}

void DTLS_Channel_IO::send_flight(std::vector<Flight::Message> flight) {
   // RFC 9147 Section 4.3
   //    DTLS messages MAY be fragmented into multiple DTLS records. Each DTLS
   //    record MUST fit within a single datagram. [...] Multiple DTLS records
   //    MAY be placed in a single datagram. Records are encoded consecutively.
   //    [...] Records MUST NOT span datagrams.
   //
   // We make use of this and pack handshake message fragments into handshake
   // records (even across message boundaries, as long as they share an epoch)
   // and handshake records into datagrams, as tightly as the MTU configured in
   // the policy allows.

   // A fragment must contain at least one payload byte in addition to its
   // handshake header to make progress.
   constexpr size_t min_fragment_size = DTLS_Handshake_Layer::FRAGMENT_HEADER_LENGTH + 1;

   std::vector<uint8_t> current_datagram;                   // datagram currently being packed with records
   PackedHandshakeMessageFragments current_record_payload;  // record currently being packed with fragments
   std::optional<Epoch_Number> current_record_epoch;

   // Seals the pending record and appends it to the pending datagram. The
   // record layer tracks the sealed record for potential retransmission.
   const auto flush_record = [&]() {
      if(current_record_payload.empty()) {
         return;
      }

      auto [record, _record_number] = record_layer().prepare_handshake_record(
         std::exchange(current_record_payload, {}), cipher_state(), current_record_epoch);
      current_datagram.insert(current_datagram.end(), record.begin(), record.end());
   };

   // Seals the pending record and emits the pending datagram.
   const auto flush_datagram = [&]() {
      flush_record();
      if(!current_datagram.empty()) {
         callbacks().tls_emit_data(current_datagram);
         current_datagram.clear();
      }
   };

   for(const auto& msg : flight) {
      const auto* msg_info = std::get_if<Flight::Message_Info>(&msg);
      // RFC 9147 5
      //    DTLS implementations do not use the TLS 1.3 "compatibility mode" [...].
      //
      // `msg` is either Flight::Message_Info or Flight::Dummy_ChangeCipherSpec.
      BOTAN_ASSERT_NONNULL(msg_info);

      // A record must not contain fragments of different protection epochs.
      // Note that the sealed record may still share the pending datagram with
      // records of other epochs (e.g. an unprotected ServerHello may be packed
      // with a protected EncryptedExtensions record in the same datagram).
      if(current_record_epoch != msg_info->epoch) {
         flush_record();
      }
      current_record_epoch = msg_info->epoch;

      // The payload limit of a record that occupies a datagram all by itself,
      // given the record overhead of the current epoch.
      const size_t record_payload_limit =
         record_layer().record_payload_size_limit(policy(), cipher_state(), msg_info->epoch);

      // Space left for another fragment in the pending record, taking the
      // records already packed into the pending datagram into account. If not
      // even a minimal fragment fits, the pending record (and with it the
      // pending datagram) is full.
      const size_t packed_bytes = current_datagram.size() + current_record_payload.size();
      if(packed_bytes + min_fragment_size > record_payload_limit) {
         flush_datagram();
      }

      // The first fragment of this message may fill up the space that is left
      // in the pending record; all further fragments may fill up entire
      // records.
      const auto first_fragment_size =
         static_cast<uint16_t>(record_payload_limit - current_datagram.size() - current_record_payload.size());

      const auto fragments = handshake_layer().fragment_message(
         msg_info->type, msg_info->serialized, static_cast<uint16_t>(record_payload_limit), first_fragment_size);

      for(const auto& fragment : fragments) {
         if(current_datagram.size() + current_record_payload.size() + fragment.size() > record_payload_limit) {
            // The pending record (and with it the pending datagram) is full.
            flush_datagram();
         }
         current_record_payload.get().insert(current_record_payload.get().end(), fragment.begin(), fragment.end());
      }
   }

   flush_datagram();

   m_retransmission_timer.flight_sent();
   arm_dtls_retransmission_timer();
   m_ack_token.reset();
}

bool DTLS_Channel_IO::can_send_key_update() const {
   // RFC 9147 8.
   //    [...] implementations MUST NOT send [...] a new KeyUpdate until the
   //    previous KeyUpdate has been acknowledged [...].
   if(has_unacknowledged_key_update()) {
      return false;
   }

   // RFC 9147 8. (Errata-ID 8050)
   //    After the handshake, each epoch change consumes a message_seq value,
   //    which is limited to 2^16-1. [...] In this case, the implementation MUST
   //    check for this limit, if reached, terminate the association.
   //
   // We don't terminate the association but we reject any further key updates.
   BOTAN_ASSERT_NONNULL(cipher_state());
   if(to_underlying(cipher_state()->current_write_epoch_number()) == std::numeric_limits<uint16_t>::max()) {
      throw Invalid_State("Cannot update keys: maximum DTLS epoch number reached");
   }

   return true;
}

void DTLS_Channel_IO::schedule_read_epoch_pruning(Epoch_Number latest_epoch) {
   // RFC 9147 Section 4.2.1
   //    Implementations [...] MAY choose to retain keying material from
   //    previous epochs for up to the default MSL specified for TCP [RFC0793]
   //    to allow for packet reordering.
   //
   // RFC 9293 4.
   //    MSL: Maximum Segment Lifetime, the time a TCP segment can exist in the
   //         internetwork system. Arbitrarily defined to be 2 minutes.
   constexpr uint64_t expiration_time_ms = 2 * 60 * 1000;
   callbacks().tls_register_deferred_operation(expiration_time_ms, [weak = weak_from_this(), latest_epoch] {
      if(auto self = weak.lock()) {
         if(auto* cs = as_dtls_cipher_state(self->cipher_state())) {
            BOTAN_ASSERT_NONNULL(cs);
            cs->prune_read_epochs_older_than(latest_epoch);
         }
      }
   });
}

void DTLS_Channel_IO::send_key_update(const Key_Update& msg) {
   BOTAN_STATE_CHECK(!has_unacknowledged_key_update());

   // TODO: Let Handshake_Message::serialize() emit the strong type
   const auto serialized_key_update = SerializedHandshakeMessage(msg.serialize());
   auto msg_bytes =
      handshake_layer().fragment_message(Handshake_Type::KeyUpdate,
                                         serialized_key_update,
                                         DTLS_Handshake_Layer::FRAGMENT_HEADER_LENGTH + serialized_key_update.size());

   BOTAN_ASSERT_NOMSG(msg_bytes.size() == 1);  // KeyUpdate is small enough to always fit into a single fragment
   const auto [prepared_record, record_number] = record_layer().prepare_handshake_record(
      PackedHandshakeMessageFragments(std::move(msg_bytes.front())), cipher_state());

   callbacks().tls_emit_data(prepared_record);

   // RFC 9147 8.
   //    [...]  KeyUpdates MUST be acknowledged. In order to facilitate epoch
   //    reconstruction [...], implementations MUST NOT send records with the
   //    new keys or send a new KeyUpdate until the previous KeyUpdate has
   //    been acknowledged [...].
   //
   // The actual call to cipher_state->update_write_keys() is
   // deferred to the handling of the respective acknowledgement.
   m_pending_key_update_record = record_number;

   // TODO: BoGo is completely green if we forget to
   // arm the retransmission timer here -> add a regression test.
   // But here it may be possible that the timer is not started.
   // If we just reset it, it may possibly interfere with
   // a retransmission of the last client flight, have to check
   // that again.
   m_retransmission_timer.start_if_not_started();
   arm_dtls_retransmission_timer();

   // TODO: There is a case where the user requests a KeyUpdate while the channel does one
   // automatically - one of them will lock the ACK mechanism, the other will fail because
   // 2 KeyUpdates are not allowed to be outstanding. Add a test and maybe find a way
   // to avoid this.
}

void DTLS_Channel_IO::send_acknowledgements() {
   // There might be nothing to acknowledge, e.g. when all recently received
   // handshake records contained fragments that had to be discarded. Don't
   // emit a pointless empty ACK record in that case.
   if(!record_layer().has_outstanding_acknowledgements()) {
      return;
   }

   const auto max_plaintext_length = record_layer().record_payload_size_limit(policy(), cipher_state());
   send_data(Record_Type::ACK, current_ack_record(max_plaintext_length), cipher_state());
}

void DTLS_Channel_IO::notify_protocol_version_committed_and_flight_superseded() {
   notify_protocol_version_committed();
   maybe_clear_resend_buffer();
}

void DTLS_Channel_IO::notify_received_complete_flight() {
   // We have everything we needed, no reason to do any ACKing anymore
   record_layer().clear_outstanding_acknowledgements();
}

void DTLS_Channel_IO::notify_received_final_flight() {
   // RFC 9147 5.7
   //     When a handshake flight is sent without any expected response, as
   //     is the case with the client's final flight [...], the flight must
   //     be acknowledged with an ACK message.
   send_acknowledgements();
}

void DTLS_Channel_IO::maybe_retransmit(Cipher_State* cipher_state) {
   if(!m_retransmission_timer.started()) {
      return;
   }

   if(m_retransmission_timer.retransmissions_exhausted()) {
      throw TLS_Exception(Alert::None, "DTLS handshake timed out: maximum retransmissions exceeded");
   }

   if(!m_retransmission_timer.expired()) {
      return;  // timer has not yet expired
   }

   // Pack the retransmitted records into datagrams up to the MTU, just like
   // send_flight() did for the original transmission. This keeps the packing
   // of a full retransmission identical to the original flight.
   const size_t mtu = policy().dtls_default_mtu();

   std::vector<uint8_t> datagram;
   for(const auto& record_to_write : record_layer().prepare_unacknowledged_records(cipher_state)) {
      if(!datagram.empty() && datagram.size() + record_to_write.size() > mtu) {
         callbacks().tls_emit_data(datagram);
         datagram.clear();
      }
      datagram.insert(datagram.end(), record_to_write.begin(), record_to_write.end());
   }
   if(!datagram.empty()) {
      callbacks().tls_emit_data(datagram);
   }

   m_retransmission_timer.retransmitted();
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

   callbacks().tls_register_deferred_operation(next_timeout->count(), on_timer);
}

void DTLS_Channel_IO::on_retransmission_timer() {
   maybe_retransmit(cipher_state());

   // Spawn the next timer generation for the next backoff interval in this
   // chain. This will be a no-op if the timer is no longer needed.
   arm_dtls_retransmission_timer();
}

void DTLS_Channel_IO::maybe_arm_dtls_acknowledgement_timer() {
   const auto ack_time = policy().dtls_initial_timeout() / 4;

   if(!m_ack_token && m_dtls_version_committed) {
      m_ack_token = std::make_shared<TimerToken>(*this);

      callbacks().tls_register_deferred_operation(ack_time, [token = std::weak_ptr(m_ack_token)] {
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

void DTLS_Channel_IO::process(const Handshake_Record& record) {
   // Handshake records need to be fed to the handshake layer before
   // their messages can be consumed by the channel
   const auto result = handshake_layer().copy_data(policy(), record);

   // RFC 9147 7.
   //    During the handshake, ACKs only cover the current outstanding flight
   //    (this is possible because DTLS is generally a lock-step protocol).
   //    In particular, receiving a message from a handshake flight implicitly
   //    acknowledges all messages from the previous flight(s).
   //
   // Handshake_Layer::copy_data() reports progress if a handshake message
   // fragment with a previously unprocessed sequence number was queued for
   // reassembly. This indicates progress and therefore ACKs our previously sent
   // flight implicitly. Discarded fragments (retransmissions of consumed
   // messages or messages beyond the buffering window) do not count as
   // progress.
   //
   // Note: This assumes that we only send our flight once we fully received a
   //       flight from the peer. This is a hard requirement in TLS 1.3.
   if(result == Handshake_Layer::CopyDataResult::Consumed ||
      result == Handshake_Layer::CopyDataResult::ConsumedPartially) {
      const bool is_post_handshake_traffic =
         record.epoch.has_value() && record.epoch.value() >= Epoch_Number::ApplicationTraffic_0;
      if(!is_post_handshake_traffic) {
         maybe_clear_resend_buffer();
      }
   }

   // RFC 9147 7.
   //    Implementations MUST NOT acknowledge records containing handshake
   //    messages or fragments which have not been processed or buffered.
   //    Otherwise, deadlock can ensue.
   //
   // If the handshake layer was fully consumed or was a retransmission of a
   // previously consumed message, we can (re-)acknowledge this record.
   if(result == Handshake_Layer::CopyDataResult::Consumed ||
      result == Handshake_Layer::CopyDataResult::DiscardedDuplicate) {
      record_layer().acknowledge_handshake_record({
         .epoch = record.epoch.value(),
         .sequence_number = record.sequence_number.value(),
      });

      // RFC 9147 7.1
      //    [...] it is RECOMMENDED that [an implementation] generats ACKs
      //    under two circumstances:
      //
      //    - [...]
      //    - When they have received part of a flight and do not immediately
      //      receive the rest of the flight [...]. One approach is to set a
      //      timer [...] and then send an ACK when that timer expires.
      //
      // This opportunistically sets such a timer which gets cancelled when we
      // successfully generate our next handshake flight in response to the
      // incoming data. If we fail to generate such a flight, the timer will
      // eventually emit ACKs to the peer.
      maybe_arm_dtls_acknowledgement_timer();
   }
}

void DTLS_Channel_IO::process(const ACK_Record& ack_record) {
   // If we receive ACKs before we know for sure that the peer is using
   // DTLS 1.3, we ignore them. The peer might still pick DTLS 1.2, and as
   // a result would depend on a full flight retransmission.
   //
   // This mirrors the behavior of BoringSSL and is needed to pass
   // relevant BoGo tests.
   if(!m_dtls_version_committed) {
      return;
   }

   const auto acks = ACKs(ack_record.payload);

   // RFC 9147 Section 7.2 Errata 8108
   //    If any element of record_numbers in the ACK references an epoch that is
   //    higher than the epoch in which the ACK was received, the implementation
   //    MUST terminate the connection with an "illegal_parameter" alert.
   BOTAN_ASSERT_NOMSG(ack_record.epoch.has_value());
   if(!acks.validate(*ack_record.epoch)) {
      throw TLS_Exception(Alert::IllegalParameter, "ACK record refers to an invalid record number");
   }

   if(record_layer().handle_acknowledgements(acks)) {
      // Nothing left to retransmit, stop the timer
      m_retransmission_timer.stop();
   }

   auto* cs = as_dtls_cipher_state(cipher_state());

   if(has_unacknowledged_key_update() &&
      !record_layer().has_unacknowledged_record(m_pending_key_update_record.value())) {
      BOTAN_ASSERT_NONNULL(cs);
      cs->update_write_keys();
      m_pending_key_update_record.reset();
   }

   // If there's nothing left to retransmit, we can safely discard any
   // outdated write epochs.
   if(cs != nullptr && !record_layer().has_unacknowledged_records()) {
      cs->prune_write_epochs_older_than(cs->current_write_epoch_number());
   }

   // RFC 9147 7.2
   //    Upon receipt of an ACK that leaves it with only some messages from
   //    a flight having been acknowledged, an implementation SHOULD
   //    retransmit the unacknowledged messages or fragments.
   //
   // TODO: In the future we might want to use this cipher_state to trigger
   //       an immediate retransmission after receiving a partial ACK from
   //       the peer. For now, we just wait until `maybe_retransmit` is called.
   //
   // Not sending retransmissions immediately mirrors the current behavior
   // of BoringSSL and is expected by BoGo tests.
}

}  // namespace Botan::TLS
