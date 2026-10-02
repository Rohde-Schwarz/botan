/*
* TLS 1.3 Channel I/O
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_io.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
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
   const auto has_cryptographic_association =
      (cipher_state() != nullptr) && cipher_state()->has_cryptographic_association();

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
         record_layer().next_record(cipher_state()));

      if(res.has_value()) {
         return std::move(res).value();
      }
   }
}

void Channel_IO::send(std::vector<Flight::Message> flight) {
   send_flight(std::move(flight));
}

void Channel_IO::send(std::span<const uint8_t> payload) {
   // RFC 9846 4.7.3
   //    If the request_update field [of a received KeyUpdate] is set to
   //    "update_requested", then the receiver MUST send a KeyUpdate of its own
   //    with request_update set to "update_not_requested" prior to sending its
   //    next Application Data record. This mechanism allows either side to
   //    force an update to the entire connection, but causes an implementation
   //    which receives multiple KeyUpdates while it is silent to respond with
   //    a single update.
   if(m_key_update_reciprocation_pending) {
      update_traffic_keys(false /* update_requested */);
      m_key_update_reciprocation_pending = false;
   } else if(needs_traffic_based_key_update()) {
      // If approaching traffic limits request the peer update their own keys
      // as well, unless an earlier request is still unanswered:
      //
      // RFC 9846 4.7.3
      //    Until receiving a subsequent KeyUpdate from the peer, the sender
      //    MUST NOT send another KeyUpdate with request_update set to
      //    "update_requested".
      update_traffic_keys(!m_key_update_requested);
   }

   send_data(Record_Type::ApplicationData, payload, cipher_state());
}

bool Channel_IO::needs_traffic_based_key_update() const {
   // RFC 9846 5.5
   //    There are cryptographic limits on the amount of plaintext which can be
   //    safely encrypted under a given set of keys. [...] Implementations MUST
   //    either close the connection or do a key update as described in Section
   //    4.7.3 prior to reaching these limits.
   //
   // The ChaCha-based suites don't have any practical usage limit but we apply
   // the limit for all suites for simplicity.
   const uint64_t limit = policy().records_per_traffic_key();
   BOTAN_ASSERT_NONNULL(cipher_state());

   // Have to skip this if the handshake is not yet completed since we can't
   // send a KeyUpdate in the (unlikely) case that the limit is hit with
   // half-RTT data. If it is we just defer until the handshake completes.
   if(limit == 0 || !cipher_state()->is_handshake_complete()) {
      return false;
   }

   if(cipher_state()->current_write_sequence_number() >= limit) {
      return true;
   }

   // For the read side all we can do is ask the peer to update its keys,
   // and only if no earlier request is still outstanding. The threshold is
   // set above the write-side limit so that a peer which tracks its own
   // write limit will normally have rotated its keys already, avoiding a
   // redundant key update crossing ours in flight.
   const uint64_t read_limit = limit + limit / 2;
   return !m_key_update_requested && cipher_state()->current_read_sequence_number() >= read_limit;
}

void Channel_IO::handle_key_update(const Key_Update& key_update) {
   BOTAN_ASSERT_NONNULL(cipher_state());

   // A non-requesting KeyUpdate received while our own request is outstanding
   // is the reciprocation we solicited. It is exempt from rate limiting (and
   // invisible to it), so that a peer whose own key update crossed ours in
   // flight is not penalized for the resulting back to back KeyUpdates.
   const bool solicited_reciprocation = m_key_update_requested && !key_update.expects_reciprocation();

   if(const uint64_t min_interval = policy().minimum_key_update_interval_ms();
      min_interval > 0 && !solicited_reciprocation) {
      const uint64_t now = callbacks().tls_current_monotonic_clock_ms();

      if(m_last_peer_key_update_ms != 0 && (now - m_last_peer_key_update_ms) < min_interval) {
         throw TLS_Exception(Alert::UnexpectedMessage, "Peer is requesting KeyUpdates too frequently");
      }

      m_last_peer_key_update_ms = now;
   }

   schedule_read_epoch_pruning(cipher_state()->update_read_keys());

   if(key_update.expects_reciprocation()) {
      // RFC 9846 4.7.3
      //    If the request_update field is set to "update_requested", then the
      //    receiver MUST send a KeyUpdate of its own with request_update set to
      //    "update_not_requested" prior to sending its next Application Data
      //    record.
      //
      // This happens opportunistically in send_application_data().
      m_key_update_reciprocation_pending = true;
   } else {
      // Only an actual reciprocation settles our outstanding request. RFC 9846
      // 4.7.3 would allow requesting again after any KeyUpdate from the peer,
      // but waiting for the reciprocation keeps the exemption above one-shot.
      m_key_update_requested = false;
   }
}

void Channel_IO::update_traffic_keys(bool request_peer_update) {
   BOTAN_ASSERT_NONNULL(cipher_state());

   // In DTLS we cannot send a KeyUpdate while a previous one is not yet
   // acknowledged. In that case, we just skip the update silently.
   if(!can_send_key_update()) {
      return;
   }

   const auto key_update = Key_Update(request_peer_update);
   callbacks().tls_inspect_handshake_msg(key_update);
   send_key_update(key_update);

   if(request_peer_update) {
      m_key_update_requested = true;
   } else {
      // Any KeyUpdate with "update_not_requested" satisfies a pending request
      // of the peer (RFC 9846 4.7.3).
      m_key_update_reciprocation_pending = false;
   }
}

void Channel_IO::send(const Alert& alert) {
   send_data(Record_Type::Alert, alert.serialize(), cipher_state());
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
   return record_layer().epoch0_sequence_numbers();
}

const Cipher_State* Channel_IO::cipher_state() const {
   return m_cipher_state.get();
}

Cipher_State* Channel_IO::cipher_state() {
   return m_cipher_state.get();
}

namespace {

class TLS_Channel_IO final : public Channel_IO {
   public:
      TLS_Channel_IO(Connection_Side side, std::shared_ptr<const Policy> policy, std::shared_ptr<Callbacks> callbacks) :
            Channel_IO(policy, std::move(callbacks)),
            m_record_layer(side, std::move(policy)),
            m_handshake_layer(side) {}

      void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override;

      void send_flight(std::vector<Flight::Message> flight) override;

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
      void send_key_update(const Key_Update& msg) override;

      void schedule_read_epoch_pruning(Epoch_Number /* latest_epoch */) override { /* don't care */ }

   private:
      TLS_Record_Layer m_record_layer;
      TLS_Handshake_Layer m_handshake_layer;
};

}  // namespace

std::shared_ptr<Channel_IO> Channel_IO::create(TLS_Flavor flavor,
                                               Connection_Side side,
                                               std::shared_ptr<const Policy> policy,
                                               std::shared_ptr<Callbacks> callbacks) {
   if(flavor == TLS_Flavor::DTLS) {
#if defined(BOTAN_HAS_DTLS_13)
      return std::make_shared<DTLS_Channel_IO>(side, std::move(policy), std::move(callbacks));
#else
      throw Not_Implemented("DTLS 1.3 is not enabled in this build of Botan");
#endif
   } else {
      return std::make_shared<TLS_Channel_IO>(side, std::move(policy), std::move(callbacks));
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
   // Now, we go through all messages of the flight, grouping them into two runs
   // one for the unprotected messages and one for the protected messages.
   bool protect_current_msgs = false;
   auto msgs = MarshalledHandshakeMessageFlight();

   auto prepare_and_flush_current_prepared = [&](bool protect) {
      if(msgs.get().empty()) {
         return;
      }

      BOTAN_ASSERT_IMPLICATION(
         protect, cipher_state() != nullptr, "Cipher State is available when messages require protection");
      auto* cs = protect ? cipher_state() : nullptr;

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

void TLS_Channel_IO::send_key_update(const Key_Update& msg) {
   send_data(Record_Type::Handshake, m_handshake_layer.marshal(msg), cipher_state());
   cipher_state()->update_write_keys();
}

}  // namespace Botan::TLS
