/*
* TLS Channel - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages_13.h>
#include <botan/tls_policy.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_transcript_hash_13.h>

#if defined(BOTAN_HAS_DTLS_13)
   #include <botan/internal/tls_dtls_channel_companion_dtls13.h>
#else
   #include <botan/internal/tls_dtls_channel_companion.h>
#endif

namespace {
bool is_user_canceled_alert(const Botan::TLS::Alert& alert) {
   return alert.type() == Botan::TLS::Alert::UserCanceled;
}

bool is_close_notify_alert(const Botan::TLS::Alert& alert) {
   return alert.type() == Botan::TLS::Alert::CloseNotify;
}

bool is_error_alert(const Botan::TLS::Alert& alert) {
   // In TLS 1.3 all alerts except for closure alerts are considered error alerts.
   // (RFC 8446 6.)
   return !is_close_notify_alert(alert) && !is_user_canceled_alert(alert);
}
}  // namespace

namespace Botan::TLS {

Channel_Impl_13::Channel_Impl_13(const std::shared_ptr<Callbacks>& callbacks,
                                 const std::shared_ptr<Session_Manager>& session_manager,
                                 const std::shared_ptr<Credentials_Manager>& credentials_manager,
                                 const std::shared_ptr<RandomNumberGenerator>& rng,
                                 const std::shared_ptr<const Policy>& policy,
                                 Connection_Side connection_side,
                                 TLS_Flavor flavor) :
      m_side(connection_side),
      m_transcript_hash(std::make_unique<Transcript_Hash_State>(flavor)),
      m_flavor(flavor),
      m_record_layer(Record_Layer::create(m_side, flavor, policy)),
      m_handshake_layer(Handshake_Layer::create(m_side, flavor)),
      m_callbacks(callbacks),
      m_session_manager(session_manager),
      m_credentials_manager(credentials_manager),
      m_rng(rng),
      m_policy(policy),
      m_can_read(true),
      m_can_write(true),
      m_opportunistic_key_update(false),
      m_key_update_requested(false),
      m_first_message_sent(false),
      m_first_message_received(false) {
   BOTAN_ASSERT_NONNULL(m_callbacks);
   BOTAN_ASSERT_NONNULL(m_session_manager);
   BOTAN_ASSERT_NONNULL(m_credentials_manager);
   BOTAN_ASSERT_NONNULL(m_rng);
   BOTAN_ASSERT_NONNULL(m_policy);
   if(is_datagram()) {
#if defined(BOTAN_HAS_DTLS_13)
      m_dtls_channel_companion = std::make_unique<DTLS_Channel_Companion_DTLS>(m_policy, m_callbacks, m_record_layer);
#else
      throw TLS_Exception(AlertType::InternalError, "DTLS 1.3 is not supported in this build of Botan");
#endif
   } else {
      m_dtls_channel_companion = std::make_unique<DTLS_Channel_Companion>();
   }
}

Channel_Impl_13::~Channel_Impl_13() = default;

size_t Channel_Impl_13::from_peer(std::span<const uint8_t> data) {
   BOTAN_STATE_CHECK(!is_downgrading());

   // RFC 8446 6.1
   //    Any data received after a closure alert has been received MUST be ignored.
   if(!m_can_read) {
      return 0;
   }

   try {
#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
      if(expects_downgrade()) {
         preserve_peer_transcript(data);
      }
#endif

      m_record_layer->copy_data(data);

      while(true) {
         // RFC 8446 6.1
         //    Any data received after a closure alert has been received MUST be ignored.
         //
         // ... this data might already be in the record layer's read buffer.
         if(!m_can_read) {
            return 0;
         }

         auto result = m_record_layer->next_record(m_cipher_state.get());

         if(std::holds_alternative<BytesNeeded>(result)) {
            return std::get<BytesNeeded>(result);
         }

         const auto& record = std::get<Record_Content>(result);

         // RFC 8446 5.1
         //   Handshake messages MUST NOT be interleaved with other record types.
         if(record.type != Record_Type::Handshake && m_handshake_layer->has_pending_data()) {
            throw Unexpected_Message("Expected remainder of a handshake message");
         }

         if(record.type == Record_Type::Handshake) {
            if(m_handshake_layer->copy_data(policy(), record.payload)) {
               // RFC 9147 7.
               //    During the handshake, ACKs only cover the current outstanding flight
               //    (this is possible because DTLS is generally a lock-step protocol).
               //    In particular, receiving a message from a handshake flight implicitly
               //    acknowledges all messages from the previous flight(s).
               //
               // Handshake_Layer::copy_data() returns true if a handshake message fragment
               // with a previously unprocessed sequence number was received. This indicates
               // progress and therefore ACKs our previously sent flight implicitly. Note
               // that this doesn't hold for post-handshake messages; for instance some
               // NewSessionTicket message _does not_ acknowledge the Client's Finished!
               //
               // Note: This assumes that we only send our flight once we fully received
               //       a flight from the peer. This is a hard requirement in TLS 1.3.
               const bool is_post_handshake_traffic =
                  record.epoch.has_value() && record.epoch.value() >= Epoch_Number::ApplicationTraffic_0;
               if(!is_post_handshake_traffic) {
                  m_dtls_channel_companion->clear_resend_buffer();
               }

               maybe_arm_dtls_acknowledgement_timer();
            }

            if(!is_handshake_complete()) {
               BOTAN_ASSERT_NONNULL(m_transcript_hash);
               while(auto handshake_msg = m_handshake_layer->next_message(policy(), *m_transcript_hash)) {
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
                  if(holds_any_of<Client_Hello_12_Shim,
                                  Client_Hello_13 /*, EndOfEarlyData,*/,
                                  Server_Hello_13,
                                  Hello_Retry_Request,
                                  Finished_13>(handshake_msg.value()) &&
                     m_handshake_layer->has_pending_data()) {
                     throw Unexpected_Message("Unexpected additional handshake message data found in record");
                  }

                  process_handshake_msg(std::move(handshake_msg.value()));

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
                  if(is_downgrading()) {
                     // Downgrade to TLS 1.2 was detected. Stop everything we do and await being replaced by a 1.2 implementation.
                     return 0;
                  } else if(m_downgrade_info != nullptr) {
                     // We received a TLS 1.3 error alert that could have been a TLS 1.2 warning alert.
                     // Now that we know that we are talking to a TLS 1.3 server, shut down.
                     if(m_downgrade_info->received_tls_13_error_alert) {
                        shutdown();
                     }

                     // Downgrade can only be indicated in the first received peer message. This was not the case.
                     m_downgrade_info.reset();
                  }
#endif

                  // After the initial handshake message is received, the record
                  // layer must be more restrictive.
                  // See RFC 8446 5.1 regarding "legacy_record_version"
                  if(!m_first_message_received) {
                     m_record_layer->disable_receiving_compat_mode();
                     m_first_message_received = true;
                  }
               }
            } else {
               while(auto handshake_msg = m_handshake_layer->next_post_handshake_message(policy())) {
                  process_post_handshake_msg(std::move(handshake_msg.value()));
               }
            }
         } else if(record.type == Record_Type::ChangeCipherSpec) {
            process_dummy_change_cipher_spec();
         } else if(record.type == Record_Type::ApplicationData) {
            BOTAN_ASSERT_NONNULL(m_cipher_state);
            if(!m_cipher_state->can_decrypt_application_traffic()) {
               throw Unexpected_Message("Application data received before handshake completion");
            }
            /*
            The record sequence number is set in Record_Layer::next_record only when
            the record contents are decrypted under the current set of traffic keys
            */
            if(!record.sequence_number.has_value()) {
               throw Unexpected_Message("Application data must have a sequence number");
            }
            callbacks().tls_record_received(record.sequence_number.value(), record.payload);
         } else if(record.type == Record_Type::Alert) {
            process_alert(record.payload);
         } else if(record.type == Record_Type::ACK) {
            process_acknowledgements(record.payload);
         } else {
            throw Unexpected_Message("Unexpected record type " + std::to_string(static_cast<size_t>(record.type)) +
                                     " from counterparty");
         }
      }
   } catch(TLS_Exception& e) {
      send_fatal_alert(e.type());
      throw;
   } catch(Invalid_Authentication_Tag&) {
      // RFC 8446 5.2
      //    If the decryption fails, the receiver MUST terminate the connection
      //    with a "bad_record_mac" alert.
      send_fatal_alert(Alert::BadRecordMac);
      throw;
   } catch(Decoding_Error&) {
      send_fatal_alert(Alert::DecodeError);
      throw;
   } catch(...) {
      send_fatal_alert(Alert::InternalError);
      throw;
   }
}

void Channel_Impl_13::handle(const Key_Update& key_update) {
   // make sure Key_Update appears only at the end of a record; see description above
   if(m_handshake_layer->has_pending_data()) {
      throw Unexpected_Message("Unexpected additional post-handshake message data found in record");
   }

   // A non-requesting KeyUpdate received while our own request is outstanding
   // is the reciprocation we solicited. It is exempt from rate limiting (and
   // invisible to it), so that a peer whose own key update crossed ours in
   // flight is not penalized for the resulting back to back KeyUpdates.
   const bool solicited_reciprocation = m_key_update_requested && !key_update.expects_reciprocation();

   if(const uint64_t min_interval = policy().minimum_key_update_interval_ms();
      min_interval > 0 && !solicited_reciprocation) {
      const uint64_t now = callbacks().tls_current_monotonic_clock_ms();

      if(m_last_key_update_ms != 0 && (now - m_last_key_update_ms) < min_interval) {
         throw TLS_Exception(Alert::UnexpectedMessage, "Peer is requesting KeyUpdates too frequently");
      }

      m_last_key_update_ms = now;
   }

   BOTAN_ASSERT_NONNULL(m_cipher_state);
   m_cipher_state->update_read_keys(*this);

   // Only an actual reciprocation settles our outstanding request. RFC 9846
   // 4.7.3 would allow requesting again after any KeyUpdate from the peer,
   // but waiting for the reciprocation keeps the exemption above one-shot.
   if(!key_update.expects_reciprocation()) {
      m_key_update_requested = false;
   }

   // RFC 8446 4.6.3
   //    If the request_update field is set to "update_requested", then the
   //    receiver MUST send a KeyUpdate of its own with request_update set to
   //    "update_not_requested" prior to sending its next Application Data
   //    record.
   if(key_update.expects_reciprocation()) {
      // RFC 8446 4.6.3
      //    This mechanism allows either side to force an update to the
      //    multiple KeyUpdates while it is silent to respond with a single
      //    update.
      opportunistically_update_traffic_keys();
   }
}

Channel_Impl_13::AggregatedMessages::AggregatedMessages(Channel_Impl_13& channel, Handshake_Layer& handshake_layer) :
      m_channel(channel), m_handshake_layer(handshake_layer) {}

Channel_Impl_13::AggregatedHandshakeMessages::AggregatedHandshakeMessages(Channel_Impl_13& channel,
                                                                          Handshake_Layer& handshake_layer,
                                                                          Transcript_Hash_State& transcript_hash) :
      AggregatedMessages(channel, handshake_layer), m_transcript_hash(transcript_hash) {}

Channel_Impl_13::AggregatedHandshakeMessages& Channel_Impl_13::AggregatedHandshakeMessages::add(
   const Handshake_Message_13_Ref message) {
   std::visit([&](const auto msg) { m_channel.callbacks().tls_inspect_handshake_msg(msg.get()); }, message);
   const auto max_payload_size =  // TODO: m_record_layer
      m_channel.m_record_layer->record_payload_size_limit(m_channel.policy(), m_channel.m_cipher_state.get());

   stash(m_handshake_layer.prepare_message(message, m_transcript_hash, max_payload_size));
   return *this;
}

Channel_Impl_13::AggregatedPostHandshakeMessages& Channel_Impl_13::AggregatedPostHandshakeMessages::add(
   Post_Handshake_Message_13 message) {
   std::visit([&](const auto& msg) { m_channel.callbacks().tls_inspect_handshake_msg(msg); }, message);
   const auto max_payload_size =  // TODO: m_record_layer
      m_channel.m_record_layer->record_payload_size_limit(m_channel.policy(), m_channel.m_cipher_state.get());

   stash(m_handshake_layer.prepare_post_handshake_message(message, max_payload_size));
   return *this;
}

void Channel_Impl_13::AggregatedMessages::stash(PreparedHandshakeMessage message) {
   if(!contains_messages()) {
      std::visit(overloaded{
                    [&](const MarshalledHandshakeMessage&) { m_buffer.emplace(MarshalledHandshakeMessageFlight()); },
                    [&](const std::vector<MarshalledHandshakeMessageFragment>&) {
                       m_buffer.emplace(std::vector<MarshalledHandshakeMessageFragment>());
                    },
                 },
                 message);
   }

   std::visit(overloaded{
                 [&](MarshalledHandshakeMessageFlight& buf, MarshalledHandshakeMessage msg) {
                    buf.get().insert(buf.end(), msg.begin(), msg.end());
                 },
                 [&](std::vector<MarshalledHandshakeMessageFragment>& buf,
                     std::vector<MarshalledHandshakeMessageFragment> msg) {
                    buf.insert(buf.end(), std::make_move_iterator(msg.begin()), std::make_move_iterator(msg.end()));
                 },

                 // Invalid state: Incoming messages' variant must be consistent
                 [](auto&&, auto&&) { BOTAN_ASSERT_NOMSG(false); },
              },
              *m_buffer,  // checked via contains_messages() above
              std::move(message));
}

void Channel_Impl_13::AggregatedMessages::send() {
   BOTAN_STATE_CHECK(contains_messages());
   m_channel.send_record(*m_buffer);
}

void Channel_Impl_13::send_dummy_change_cipher_spec() {
   // RFC 9846 5.
   //    The change_cipher_spec record is used only for compatibility purposes
   //    (see Appendix E.4).
   //
   //    An implementation may receive an unencrypted record of type
   //    change_cipher_spec consisting of the single byte value 0x01 at any time
   //    after the first ClientHello message has been sent or received and
   //    before the peer's Finished message has been received.
   BOTAN_STATE_CHECK(!is_handshake_complete());

   constexpr auto ccs_content = std::array<uint8_t, 1>{0x01};
   send_record(Record_Type::ChangeCipherSpec, ccs_content);
}

void Channel_Impl_13::to_peer(std::span<const uint8_t> data) {
   if(!is_active()) {
      throw Invalid_State("Data cannot be sent on inactive TLS connection");
   }

   // RFC 9846 Section 5.5
   //    Implementations MUST either close the connection or do a key update as
   //    described in Section 4.7.3 prior to reaching these limits.
   //
   // [This is a SHOULD in RFC 8446]
   //
   // The ChaCha-based suites don't have any practical usage limit but we
   // apply the limit for all suites for simplicity.
   auto needs_traffic_based_key_update = [&]() {
      const uint64_t limit = policy().records_per_traffic_key();

      // Have to skip this if the handshake is not yet completed since we can't
      // send a KeyUpdate in the (unlikely) case that the limit is hit with
      // half-RTT data. If it is we just defer until the handshake completes.

      if(limit == 0 || !is_handshake_complete()) {
         return false;
      }

      if(m_cipher_state->current_write_sequence_number() >= limit) {
         return true;
      }

      // For the read side all we can do is ask the peer to update its keys,
      // and only if no earlier request is still outstanding. The threshold is
      // set above the write-side limit so that a peer which tracks its own
      // write limit will normally have rotated its keys already, avoiding a
      // redundant key update crossing ours in flight.
      const uint64_t read_limit = limit + limit / 2;
      return !m_key_update_requested && m_cipher_state->current_read_sequence_number() >= read_limit;
   };

   // RFC 8446 4.6.3
   //    If the request_update field [of a received KeyUpdate] is set to
   //    "update_requested", then the receiver MUST send a KeyUpdate of its own
   //    with request_update set to "update_not_requested" prior to sending its
   //    next Application Data record.
   //    This mechanism allows either side to force an update to the entire
   //    connection, but causes an implementation which receives multiple
   //    KeyUpdates while it is silent to respond with a single update.
   if(m_opportunistic_key_update) {
      update_traffic_keys(false /* update_requested */);
      m_opportunistic_key_update = false;
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

   send_record(Record_Type::ApplicationData, std::vector<uint8_t>{data.begin(), data.end()});
}

void Channel_Impl_13::send_alert(const Alert& alert) {
   if(alert.is_valid() && m_can_write) {
      try {
         maybe_handle_compatibility_mode(Compat_Mode_Situation::BeforeSendingAlert);
         send_record(Record_Type::Alert, alert.serialize());
      } catch(...) { /* swallow it */
      }
   }

   // Note: In TLS 1.3 sending a CloseNotify must not immediately lead to closing the reading end.
   // RFC 8446 6.1
   //    Each party MUST send a "close_notify" alert before closing its write
   //    side of the connection, unless it has already sent some error alert.
   //    This does not have any effect on its read side of the connection.
   if(is_close_notify_alert(alert) && m_can_write) {
      m_can_write = false;
      if(m_cipher_state) {
         m_cipher_state->clear_write_keys();
      }
   }

   if(is_error_alert(alert)) {
      shutdown();
   }
}

bool Channel_Impl_13::is_active() const {
   return m_cipher_state != nullptr && m_cipher_state->can_encrypt_application_traffic()  // handshake done
          && m_can_write;                                                                 // close() hasn't been called
}

SymmetricKey Channel_Impl_13::key_material_export(std::string_view label,
                                                  std::string_view context,
                                                  size_t length) const {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_cipher_state != nullptr && m_cipher_state->can_export_keys());
   return SymmetricKey(m_cipher_state->export_key(label, context, length));
}

void Channel_Impl_13::update_traffic_keys(bool request_peer_update) {
   BOTAN_STATE_CHECK(!is_downgrading() && is_handshake_complete() && is_active());
   BOTAN_ASSERT_NONNULL(m_cipher_state);
   send_post_handshake_message(Key_Update(request_peer_update));
   m_cipher_state->update_write_keys(*this);
   if(request_peer_update) {
      m_key_update_requested = true;
   }
}

bool Channel_Impl_13::timeout_check() {
   if(!is_datagram()) {
      return false;
   }

   throw Not_Implemented(
      "timeout_check() is not implemented for DTLS 1.3, please implement "
      "TLS::Callbacks::tls_register_deferred_operation() instead");
}

std::optional<std::chrono::milliseconds> Channel_Impl_13::next_retransmission_timeout() const {
   if(!is_datagram()) {
      return std::nullopt;
   }

   throw Not_Implemented(
      "next_retransmission_timeout() is not implemented for DTLS 1.3, please "
      "implement TLS::Callbacks::tls_register_deferred_operation() instead");
}

void Channel_Impl_13::send_record(Record_Type record_type, std::span<const uint8_t> payload) {
   BOTAN_ASSERT(record_type != Record_Type::Handshake, "Handshake messages are sent via another overload");
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_can_write);

   // RFC 9846 5.
   //    An implementation which [...] receives a protected change_cipher_spec
   //    record MUST abort the handshake [...].
   //
   // I.e. Change Cipher Spec records must always be sent unprotected, even if
   // the cipher state is already set up for handshake message encryption.
   auto* cipher_state = (record_type != Record_Type::ChangeCipherSpec) ? m_cipher_state.get() : nullptr;

   for(const auto& record_to_write : m_record_layer->prepare_records(record_type, payload, cipher_state)) {
      callbacks().tls_emit_data(record_to_write);
   }
}

void Channel_Impl_13::send_record(const PreparedHandshakeMessageFlight& flight) {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_can_write);

   // TODO: Currently, this method is called separately for the ServerHello and
   // the encrypted handshake messages of the server's first flight. Once
   // AggregatedMessages also aggregates the ServerHello, we could move the
   // calls to notify_flight_state_progress() from deep inside the state machine
   // to this call, since then we will know for certain that the state has
   // advanced as we are sending out the next complete flight.
   for(const auto& record_to_write : m_record_layer->prepare_records(flight, m_cipher_state.get())) {
      callbacks().tls_emit_data(record_to_write);
   }

   m_dtls_channel_companion->notify_sent_handshake_flight();
   maybe_cancel_dtls_acknowledgement_timer();
   maybe_arm_dtls_retransmission_timer();

   // After the initial handshake message is sent, the record layer must
   // adhere to a more strict record specification. Note that for the
   // server case this is a NOOP.
   // See (RFC 8446 5.1. regarding "legacy_record_version")
   if(!m_first_message_sent) {
      m_record_layer->disable_sending_compat_mode();
      m_first_message_sent = true;
   }
}

void Channel_Impl_13::send_acknowledgements() {
   send_record(Record_Type::ACK,
               m_dtls_channel_companion->current_ack_record(
                  m_record_layer->record_payload_size_limit(policy(), m_cipher_state.get())));
}

void Channel_Impl_13::process_alert(const secure_vector<uint8_t>& record) {
   const Alert alert(record);

   if(is_close_notify_alert(alert)) {
      m_can_read = false;
      if(m_cipher_state) {
         m_cipher_state->clear_read_keys();
      }
      m_record_layer->clear_read_buffer();
   }

   // user canceled alerts are ignored

   // RFC 8446 5.
   //    All the alerts listed in Section 6.2 MUST be sent with
   //    AlertLevel=fatal and MUST be treated as error alerts when received
   //    regardless of the AlertLevel in the message.  Unknown Alert types
   //    MUST be treated as error alerts.
   if(is_error_alert(alert) && !alert.is_fatal()) {
      if(!expects_downgrade()) {
         throw TLS_Exception(Alert::DecodeError, "Error alert not marked fatal");
      }

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
      BOTAN_DEBUG_ASSERT(expects_downgrade());

      // In TLS 1.2 error alerts might be marked as 'warnings' and would not
      // demand an immediate shutdown. Until we are sure to talk to a TLS 1.3
      // peer we must defer the shutdown and refrain from raising a decode
      // error.
      m_downgrade_info->received_tls_13_error_alert = true;
#endif
   }

   if(alert.is_fatal()) {
      shutdown();
   }

   callbacks().tls_alert(alert);

   // Respond with our "close_notify" if the application requests us to.
   if(is_close_notify_alert(alert) && callbacks().tls_peer_closed_connection()) {
      close();
   }
}

void Channel_Impl_13::process_acknowledgements(std::span<const uint8_t> record) {
   m_dtls_channel_companion->process_acknowledgements(m_cipher_state.get(), record);
}

void Channel_Impl_13::maybe_arm_dtls_retransmission_timer(TimerGeneration generation_policy) {
   if(!is_datagram()) {
      return;
   }

   const auto next_timeout = m_dtls_channel_companion->next_retransmission_timeout();

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
      auto channel = std::dynamic_pointer_cast<Channel_Impl_13>(self.lock());
      if(!channel) {
         return;
      }

      // Drop the reference to the channel in this deferred operation. If the
      // user accidentally calls the operation more than once, the second
      // invocation will be a harmless no-op.
      self.reset();

      // This timer-chain may have been superseded by a newer one, when a
      // backoff interval was reset by the arrival of a belated handshake
      // message. This generation is no longer active and ends here.
      if(generation != channel->m_retransmission_timer_generation) {
         return;
      }

      // Now we know that we're on the active retransmission/backoff
      // chain...
      if(channel->m_dtls_channel_companion->timeout_check(channel->m_cipher_state.get())) {
         // ... and a retransmission was performed: Spawn the next timer
         // generation for the next backoff interval in this chain.
         channel->maybe_arm_dtls_retransmission_timer(TimerGeneration::Advance);
      } else {
         // ... but no retransmission was performed. Either, because the user
         // invoked the operation too early, in which case we will just reset
         // the timer for the remaining time until the next deadline, or a
         // retransmission was not needed anymore (because the peer's flight
         // arrived), then maybe_arm_* will not re-arm the timer.
         channel->maybe_arm_dtls_retransmission_timer(TimerGeneration::Keep);
      }
   };

   m_callbacks->tls_register_deferred_operation(next_timeout->count(), on_timer);
}

class AcknowledgementTimer : public std::enable_shared_from_this<AcknowledgementTimer> {
   public:
      explicit AcknowledgementTimer(std::shared_ptr<Channel_Impl> channel) :
            m_channel(std::dynamic_pointer_cast<Channel_Impl_13>(std::move(channel))) {}

      std::shared_ptr<Channel_Impl_13> channel() const { return m_channel.lock(); }

   private:
      std::weak_ptr<Channel_Impl_13> m_channel;
};

void Channel_Impl_13::maybe_arm_dtls_acknowledgement_timer() {
   const auto ack_time = m_policy->dtls_initial_timeout() / 4;

   if(!m_ack_timer) {
      m_ack_timer = std::make_shared<AcknowledgementTimer>(shared_from_this());

      m_callbacks->tls_register_deferred_operation(ack_time, [self = std::weak_ptr(m_ack_timer)] {
         auto handle = self.lock();
         if(!handle) {
            return;
         }

         auto channel = handle->channel();
         if(!channel) {
            return;
         }

         channel->send_acknowledgements();
      });
   }
}

void Channel_Impl_13::maybe_cancel_dtls_acknowledgement_timer() {
   m_ack_timer.reset();
}

void Channel_Impl_13::shutdown() {
   // RFC 8446 6.2
   //    Upon transmission or receipt of a fatal alert message, both
   //    parties MUST immediately close the connection.
   m_can_read = false;
   m_can_write = false;
   m_cipher_state.reset();
   m_active_state.reset();
}

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)

void Channel_Impl_13::expect_downgrade(const Server_Information& server_info,
                                       const std::vector<std::string>& next_protocols) {
   Downgrade_Information di{
      {},
      {},
      {},
      server_info,
      next_protocols,
      Botan::TLS::Channel::IO_BUF_DEFAULT_SIZE,
      m_callbacks,
      m_session_manager,
      m_credentials_manager,
      m_rng,
      m_policy,
      is_datagram() ? TLS_Flavor::DTLS : TLS_Flavor::TLS,
      false,         // received_tls_13_error_alert
      false,         // will_downgrade
      std::nullopt,  // epoch0_sequence_numbers
   };
   m_downgrade_info = std::make_unique<Downgrade_Information>(std::move(di));
}

#endif

void Channel_Impl_13::set_record_size_limits(const uint16_t outgoing_limit, const uint16_t incoming_limit) {
   m_record_layer->set_record_size_limits(outgoing_limit, incoming_limit);
}

void Channel_Impl_13::set_selected_certificate_type(const Certificate_Type cert_type) {
   m_handshake_layer->set_selected_certificate_type(cert_type);
}

}  // namespace Botan::TLS
