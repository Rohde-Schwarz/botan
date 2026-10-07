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
      Channel_IO(side, std::move(policy_ptr), callbacks),
      m_handshake_layer(side),
      m_retransmission_timer(policy(), std::move(callbacks)) {
   // In DTLS we flush out the payload one datagram at a time. Hence, the output
   // buffer is capped to the application-defined MTU or the maximum record
   // length if the application provides a larger MTU.
   m_outgoing_datagram.reserve(std::min(policy().dtls_default_mtu(), to_underlying(MAX_CIPHERTEXT_SIZE_TLS13)));
}

void DTLS_Channel_IO::send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) {
   BOTAN_STATE_CHECK(m_outgoing_datagram.empty());

   std::ignore = m_record_layer.prepare_record(record_type, payload, policy(), cipher_state, m_outgoing_datagram);
   callbacks().tls_emit_data(m_outgoing_datagram);
   m_outgoing_datagram.clear();
}

void DTLS_Channel_IO::send_flight(std::vector<Flight::Message> flight) {
   BOTAN_STATE_CHECK(m_outgoing_datagram.empty());

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

   PackedHandshakeMessageFragments current_record_payload;  // record currently being packed with fragments
   std::optional<EpochNumber> current_record_epoch;

   // Seals the pending record and appends it to the pending datagram. The
   // record layer tracks the sealed record for potential retransmission.
   const auto flush_record = [&]() {
      if(current_record_payload.empty()) {
         return;
      }

      record_layer().prepare_handshake_record(std::exchange(current_record_payload, {}),
                                              m_outgoing_datagram,
                                              policy(),
                                              cipher_state().get(),
                                              current_record_epoch);
   };

   // Seals the pending record and emits the pending datagram.
   const auto flush_datagram = [&]() {
      flush_record();
      if(!m_outgoing_datagram.empty()) {
         callbacks().tls_emit_data(m_outgoing_datagram);
         m_outgoing_datagram.clear();
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
         record_layer().record_payload_size_limit(policy(), cipher_state().get(), msg_info->epoch);

      // Space left for another fragment in the pending record, taking the
      // records already packed into the pending datagram into account. If not
      // even a minimal fragment fits, the pending record (and with it the
      // pending datagram) is full.
      const size_t packed_bytes = m_outgoing_datagram.size() + current_record_payload.size();
      if(packed_bytes + min_fragment_size > record_payload_limit) {
         flush_datagram();
      }

      // The first fragment of this message may fill up the space that is left
      // in the pending record; all further fragments may fill up entire
      // records.
      const auto first_fragment_size =
         static_cast<uint16_t>(record_payload_limit - m_outgoing_datagram.size() - current_record_payload.size());

      // TODO: This could be optimized with an out-param to avoid allocation
      //       and copy for each fragment. I.e. just hand it a reference to
      //       `current_record_payload` and let it append the fragment directly.
      const auto fragments = handshake_layer().fragment_message(
         msg_info->wire_type, msg_info->serialized, static_cast<uint16_t>(record_payload_limit), first_fragment_size);

      for(const auto& fragment : fragments) {
         if(m_outgoing_datagram.size() + current_record_payload.size() + fragment.size() > record_payload_limit) {
            // The pending record (and with it the pending datagram) is full.
            flush_datagram();
         }
         current_record_payload.get().insert(current_record_payload.get().end(), fragment.begin(), fragment.end());
      }
   }

   flush_datagram();

   arm_retransmission_timer();
   m_ack_timer.cancel();
}

void DTLS_Channel_IO::handle_key_update(const Key_Update& key_update) {
   using namespace std::chrono_literals;

   // RFC 9147 8.
   //    With a 128-bit key as in AES-128, rekeying 2^64 times has a high
   //    probability of key reuse within a given connection. [...] In order to
   //    provide an extra margin of security, sending implementations MUST NOT
   //    allow the epoch to exceed 2^48-1. [...]
   //
   // RFC 9147 8. (Errata-ID 8050)
   //    After the handshake, each epoch change consumes a message_seq value,
   //    which is limited to 2^16-1. Both sending and receiving implementations
   //    MAY instead enforce an epoch limit of 2^16-1. In this case, the
   //    implementation MUST check for this limit, if reached, terminate the
   //    association.
   //
   // If the just-received KeyUpdate would move the epoch number beyond the
   // limit of 2^16-1, we reject it as unexpected message.
   if(to_underlying(cipher_state()->current_read_epoch_number()) == std::numeric_limits<uint16_t>::max()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Cannot update keys: maximum DTLS epoch number reached");
   }

   Channel_IO::handle_key_update(key_update);

   // RFC 9147 Section 4.2.1
   //    Implementations [...] MAY choose to retain keying material from
   //    previous epochs for up to the default MSL specified for TCP [RFC0793]
   //    to allow for packet reordering.
   //
   // RFC 9293 4.
   //    MSL: Maximum Segment Lifetime, the time a TCP segment can exist in the
   //         internetwork system. Arbitrarily defined to be 2 minutes.
   //
   // Note: In the unlikely case that the peer never receives our ACK for this
   // KeyUpdate (or its retransmissions), it may keep transmitting application
   // data on the old epoch. After this timer expires, we prune all read epochs
   // except the one the just-received KeyUpdate moved us into. In that case we
   // would not be able to decrypt any data from the peer anymore and this
   // association would be effectively dead. We currently don't handle this case
   // explicitly at the moment.
   SingleshotTimer::start_detached(
      callbacks(), 2min, [weak = weak_from_this(), latest_epoch = cipher_state()->current_read_epoch_number()] {
         if(auto self = weak.lock()) {
            if(auto cs = self->cipher_state()) {
               auto* dcs = as_dtls_cipher_state(cs.get());
               BOTAN_ASSERT_NONNULL(dcs);
               dcs->prune_read_epochs_older_than(latest_epoch);
            }
         }
      });
}

bool DTLS_Channel_IO::can_send_post_handshake_messages() const {
   // RFC 9147 5.8.4
   //    Sending multiple instances of messages of a given category without
   //    having completed earlier transmissions is allowed for some categories,
   //    but not for others. Specifically, a server MAY send multiple
   //    NewSessionTicket messages at once without awaiting ACKs for earlier
   //    NewSessionTicket messages first. [...] In contrast, implementations
   //    MUST NOT send KeyUpdate, NewConnectionId, or RequestConnectionId
   //    messages if an earlier message of the same type has not yet been
   //    acknowledged.
   //
   // RFC 9147 8. Key Updates
   //    In order to facilitate epoch reconstruction, implementations MUST NOT
   //    send records with the new keys or send a new KeyUpdate until the
   //    previous KeyUpdate has been acknowledged [...].
   //
   // Right now, the only post-handshake messages we support are KeyUpdate and
   // NewSessionTicket. For simplicity, we block all post-handshake messages
   // while a KeyUpdate is unacknowledged so that no further post-handshake
   // messages are sent in the already-doomed epoch. That makes us compatible
   // with BoringSSL, which enforces this restriction even though the RFC does
   // not require it explicitly (see BoGo test "KeyUpdate-ExtraMessage-DTLS").
   return Channel_IO::can_send_post_handshake_messages() && !has_unacknowledged_key_update();
}

void DTLS_Channel_IO::send_key_update(const Key_Update& msg) {
   BOTAN_STATE_CHECK(!has_unacknowledged_key_update());
   BOTAN_STATE_CHECK(m_outgoing_datagram.empty());

   const auto serialized_key_update = Handshake_Layer::serialize(msg);
   auto msg_bytes =
      handshake_layer().fragment_message(Handshake_Type::KeyUpdate,
                                         serialized_key_update,
                                         DTLS_Handshake_Layer::FRAGMENT_HEADER_LENGTH + serialized_key_update.size());

   BOTAN_ASSERT_NOMSG(msg_bytes.size() == 1);  // KeyUpdate is small enough to always fit into a single fragment
   const auto record_number =
      record_layer().prepare_handshake_record(PackedHandshakeMessageFragments(std::move(msg_bytes.front())),
                                              m_outgoing_datagram,
                                              policy(),
                                              cipher_state().get());

   callbacks().tls_emit_data(m_outgoing_datagram);
   m_outgoing_datagram.clear();

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
   if(!m_retransmission_timer.armed()) {
      arm_retransmission_timer();
   }

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

   const auto max_plaintext_length = record_layer().record_payload_size_limit(policy(), cipher_state().get());
   send_data(Record_Type::ACK, m_record_layer.acknowledgements().serialize(max_plaintext_length), cipher_state().get());
}

void DTLS_Channel_IO::notify_protocol_version_committed_and_flight_superseded() {
   notify_protocol_version_committed();
   maybe_clear_retransmission_buffer();
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

void DTLS_Channel_IO::maybe_clear_retransmission_buffer() {
   // If we're not sure that the peer is using DTLS 1.3, we must not clear
   // the resend buffer as soon as we received any fragment of the peer's
   // flight. If some fragment got lost, we can't ACK and therefore are
   // forced to retransmit our entire previous flight.
   if(m_dtls_version_committed) {
      record_layer().clear_resend_buffer();

      // Nothing left to retransmit, cancel the timer
      m_retransmission_timer.cancel();
   }
}

void DTLS_Channel_IO::retransmit() {
   // Pack the retransmitted records into datagrams up to the MTU, just like
   // send_flight() did for the original transmission. This keeps the packing
   // of a full retransmission identical to the original flight.
   const size_t mtu = policy().dtls_default_mtu();

   std::vector<uint8_t> datagram;
   for(const auto& record_to_write : record_layer().prepare_unacknowledged_records(policy(), cipher_state().get())) {
      if(!datagram.empty() && datagram.size() + record_to_write.size() > mtu) {
         callbacks().tls_emit_data(datagram);
         datagram.clear();
      }
      datagram.insert(datagram.end(), record_to_write.begin(), record_to_write.end());
   }
   if(!datagram.empty()) {
      callbacks().tls_emit_data(datagram);
   }
}

void DTLS_Channel_IO::arm_retransmission_timer() {
   m_retransmission_timer.start([weak = weak_from_this()] {
      if(auto self = weak.lock()) {
         self->retransmit();
      }
   });
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
         record.epoch.has_value() && record.epoch.value() >= EpochNumber::ApplicationTraffic_0;
      if(!is_post_handshake_traffic) {
         maybe_clear_retransmission_buffer();
      }
   }

   // RFC 9147 7.
   //    Implementations MUST NOT acknowledge records containing handshake
   //    messages or fragments which have not been processed or buffered.
   //    Otherwise, deadlock can ensue.
   //
   // If the handshake record was fully consumed or was a retransmission of a
   // previously consumed message, we can (re-)acknowledge this record.
   if(result == Handshake_Layer::CopyDataResult::Consumed ||
      result == Handshake_Layer::CopyDataResult::DiscardedDuplicate) {
      record_layer().acknowledge_handshake_record(
         {
            .epoch = record.epoch.value(),
            .sequence_number = record.sequence_number.value(),
         },
         policy());

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
      if(m_dtls_version_committed && !m_ack_timer.armed()) {
         const auto ack_time = std::chrono::milliseconds(policy().dtls_initial_timeout() / 4);
         m_ack_timer = SingleshotTimer::start(callbacks(), ack_time, [weak = weak_from_this()] {
            if(auto self = weak.lock()) {
               self->send_acknowledgements();
            }
         });
      }
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
      // Nothing left to retransmit, cancel the timer
      m_retransmission_timer.cancel();
   }

   const auto locked_cs = cipher_state();
   auto* cs = as_dtls_cipher_state(locked_cs.get());

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
