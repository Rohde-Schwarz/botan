/*
* DTLS 1.3 Channel IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_io_dtls13.h>

#include <botan/internal/tls_channel_impl_13.h>

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
                                 Channel_Impl_13& channel,
                                 const Secret_Logger& secret_logger,
                                 std::shared_ptr<const Policy> policy,
                                 std::shared_ptr<Callbacks> callbacks) :
      Channel_IO(TLS_Flavor::DTLS, side, std::move(policy), std::move(callbacks)),
      m_channel(channel),
      m_secret_logger(secret_logger),
      m_retransmission_timer(*m_policy, m_callbacks) {
   BOTAN_ASSERT_NONNULL(m_callbacks);
   BOTAN_ASSERT_NONNULL(m_record_layer);
   BOTAN_ASSERT_NONNULL(m_handshake_layer);
}

void DTLS_Channel_IO::send_records(Record_Type record_type,
                                   std::span<const uint8_t> payload,
                                   Cipher_State* cipher_state) {
   for(const auto& [record_to_write, _] : m_record_layer->prepare_records(record_type, payload, cipher_state)) {
      m_callbacks->tls_emit_data(record_to_write);
   }
}

void DTLS_Channel_IO::send_flight(std::vector<Flight::Message> flight, Cipher_State* cipher_state) {
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
         std::exchange(current_record_payload, {}), cipher_state, current_record_epoch);
      current_datagram.insert(current_datagram.end(), record.begin(), record.end());
   };

   // Seals the pending record and emits the pending datagram.
   const auto flush_datagram = [&]() {
      flush_record();
      if(!current_datagram.empty()) {
         m_callbacks->tls_emit_data(current_datagram);
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
         record_layer().record_payload_size_limit(*m_policy, cipher_state, msg_info->epoch);

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

   notify_sent_handshake_flight();
   arm_dtls_retransmission_timer();
   maybe_cancel_dtls_acknowledgement_timer();
}

void DTLS_Channel_IO::send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) {
   BOTAN_UNUSED(logger);  // Actual key update is deferred to ACK receiving
   BOTAN_STATE_CHECK(!has_pending_key_update());

   // TODO: Let Handshake_Message::serialize() emit the strong type
   const auto serialized_key_update = SerializedHandshakeMessage(msg.serialize());
   auto msg_bytes =
      handshake_layer().fragment_message(Handshake_Type::KeyUpdate,
                                         serialized_key_update,
                                         DTLS_Handshake_Layer::FRAGMENT_HEADER_LENGTH + serialized_key_update.size());

   BOTAN_ASSERT_NOMSG(msg_bytes.size() == 1);  // KeyUpdate is small enough to always fit into a single fragment
   const auto prepared_record = record_layer().prepare_handshake_record(
      PackedHandshakeMessageFragments(std::move(msg_bytes.front())), cipher_state);

   m_callbacks->tls_emit_data(prepared_record.first);

   // RFC 9147 8.
   //    [...]  KeyUpdates MUST be acknowledged. In order to facilitate epoch
   //    reconstruction [...], implementations MUST NOT send records with the
   //    new keys or send a new KeyUpdate until the previous KeyUpdate has
   //    been acknowledged [...].
   //
   // The actual call to cipher_state->update_write_keys() is
   // deferred to the handling of the respective acknowledgement.
   m_pending_key_update_record = prepared_record.second;

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

void DTLS_Channel_IO::ingest_records(std::span<const uint8_t> data) {
   const auto has_cryptographic_association =
      (m_channel.cipher_state() != nullptr) &&
      m_channel.cipher_state()->current_read_epoch_number() > Epoch_Number::Unprotected;

   record_layer().copy_data(data, has_cryptographic_association);
}

void DTLS_Channel_IO::send_acknowledgements() {
   // There might be nothing to acknowledge, e.g. when all recently received
   // handshake records contained fragments that had to be discarded. Don't
   // emit a pointless empty ACK record in that case.
   if(!record_layer().has_outstanding_acknowledgements()) {
      return;
   }

   const auto max_plaintext_length = record_layer().record_payload_size_limit(*m_policy, m_channel.cipher_state());
   send_records(Record_Type::ACK, current_ack_record(max_plaintext_length), m_channel.cipher_state());
}

Channel_IO::ReceiveEvent DTLS_Channel_IO::next_receive_event(Cipher_State* cipher_state,
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
                  case Record_Type::Handshake: {
                     process_handshake_record(record);
                     return std::nullopt;
                  }
                  case Record_Type::ChangeCipherSpec:
                  case Record_Type::Alert:
                  case Record_Type::ApplicationData:
                     // CCS, AppData or alert can be directly consumed by the channel
                     return record;
                  case Record_Type::ACK:
                     process_acknowledgements(cipher_state, record, m_secret_logger);
                     return std::nullopt;
                  case Record_Type::Invalid:
                  case Record_Type::Heartbeat:
                     break;
               }
               throw Unexpected_Message("Unexpected record type received");
            },
         },
         pull_record(cipher_state));
   }

   return std::move(res).value();
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
   const size_t mtu = m_policy->dtls_default_mtu();

   std::vector<uint8_t> datagram;
   for(const auto& record_to_write : record_layer().prepare_unacknowledged_records(cipher_state)) {
      if(!datagram.empty() && datagram.size() + record_to_write.size() > mtu) {
         m_callbacks->tls_emit_data(datagram);
         datagram.clear();
      }
      datagram.insert(datagram.end(), record_to_write.begin(), record_to_write.end());
   }
   if(!datagram.empty()) {
      m_callbacks->tls_emit_data(datagram);
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

   m_callbacks->tls_register_deferred_operation(next_timeout->count(), on_timer);
}

void DTLS_Channel_IO::on_retransmission_timer() {
   maybe_retransmit(m_channel.cipher_state());

   // Spawn the next timer generation for the next backoff interval in this
   // chain. This will be a no-op if the timer is no longer needed.
   arm_dtls_retransmission_timer();
}

void DTLS_Channel_IO::maybe_arm_dtls_acknowledgement_timer() {
   const auto ack_time = m_policy->dtls_initial_timeout() / 4;

   if(!m_ack_token && m_dtls_version_committed) {
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

void DTLS_Channel_IO::process_handshake_record(Record_Content record) {
   // Handshake records need to be fed to the handshake layer before
   // their messages can be consumed by the channel
   const auto result = feed_handshake_record(record);

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

void DTLS_Channel_IO::process_acknowledgements(Cipher_State* cipher_state,
                                               const Record_Content& ack_record,
                                               const Secret_Logger& secret_logger) {
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

   if(has_pending_key_update() && !record_layer().has_unacknowledged_record(m_pending_key_update_record.value())) {
      BOTAN_ASSERT_NONNULL(cipher_state);
      cipher_state->update_write_keys(secret_logger);
      m_pending_key_update_record.reset();
   }

   // If there's nothing left to retransmit, we can safely discard any
   // outdated write epochs.
   if(cipher_state != nullptr && !record_layer().has_unacknowledged_records()) {
      cipher_state->prune_outdated_write_epochs();
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

DTLS_Record_Layer& DTLS_Channel_IO::record_layer() {
   return dynamic_cast<DTLS_Record_Layer&>(*m_record_layer);
}

const DTLS_Record_Layer& DTLS_Channel_IO::record_layer() const {
   return dynamic_cast<DTLS_Record_Layer&>(*m_record_layer);
}

DTLS_Handshake_Layer& DTLS_Channel_IO::handshake_layer() {
   return dynamic_cast<DTLS_Handshake_Layer&>(*m_handshake_layer);
}

}  // namespace Botan::TLS
