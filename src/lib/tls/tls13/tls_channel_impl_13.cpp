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
#include <botan/internal/tls_channel_io.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_messages_internal.h>
#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_transcript_hash_13.h>

#include <utility>

#if defined(BOTAN_HAS_DTLS_13)
   #include <botan/internal/tls_channel_io_dtls13.h>

#endif

namespace Botan::TLS {

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
      m_callbacks(callbacks),
      m_session_manager(session_manager),
      m_credentials_manager(credentials_manager),
      m_rng(rng),
      m_policy(policy),
      m_can_read(true),
      m_can_write(true),
      m_opportunistic_key_update(false),
      m_key_update_requested(false) {
   BOTAN_ASSERT_NONNULL(m_callbacks);
   BOTAN_ASSERT_NONNULL(m_session_manager);
   BOTAN_ASSERT_NONNULL(m_credentials_manager);
   BOTAN_ASSERT_NONNULL(m_rng);
   BOTAN_ASSERT_NONNULL(m_policy);

   const Secret_Logger& secret_logger = *this;
   m_channel_io = Channel_IO::create(flavor, m_side, *this, secret_logger, m_policy, m_callbacks);
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

      m_channel_io->ingest_records(data);

      std::optional<size_t> res;

      while(!res.has_value()) {
         // RFC 8446 6.1
         //    Any data received after a closure alert has been received MUST be ignored.
         //
         // ... this data might already be in the record layer's read buffer.
         if(!m_can_read) {
            return 0;
         }

         res = std::visit(
            overloaded{
               [](BytesNeeded bytes) -> std::optional<size_t> { return bytes; },
               [&]<typename T>(T&& event) -> std::optional<size_t> { return process_event(std::forward<T>(event)); },
            },
            m_channel_io->next_receive_event(m_cipher_state.get(), m_transcript_hash.get(), is_handshake_complete()));
      }

      return res.value();

   } catch(TLS_Exception& e) {
      send_fatal_alert(e.type());
      throw;
   }

   catch(Invalid_Authentication_Tag&) {
      // RFC 8446 5.2
      //    If the decryption fails, the receiver MUST terminate the connection
      //    with a "bad_record_mac" alert.
      send_fatal_alert(Alert::BadRecordMac);
      throw;
   }

   catch(Decoding_Error&) {
      send_fatal_alert(Alert::DecodeError);
      throw;
   }

   catch(...) {
      send_fatal_alert(Alert::InternalError);
      throw;
   }
}

void Channel_Impl_13::handle(const Key_Update& key_update) {
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

namespace {

std::optional<Epoch_Number> epoch_for_handshake_type(Handshake_Type handshake_type,
                                                     const Flight::PostHandshake post_handshake) {
   // Post-handshake messages are encrypted with whatever application traffic
   // epoch that is currently active, we can't determine this statically.
   if(post_handshake == Flight::PostHandshake::Yes) {
      return std::nullopt;
   }

   // RFC 9846 2.  Figure 1 as well as RFC 9846 2.3 Figure 4
   switch(handshake_type) {
      using enum Handshake_Type;

      case ClientHello:
      case ServerHello:
      case HelloRetryRequest:
         return Epoch_Number::Unprotected;

      case EncryptedExtensions:
      case Certificate:
      case CertificateRequest:
      case CertificateVerify:
      case Finished:
         return Epoch_Number::HandshakeTraffic;

      case EndOfEarlyData:
         return Epoch_Number::EarlyTraffic;

      case NewSessionTicket:
      case KeyUpdate:
         // KeyUpdate and NewSessionTicket are always post-handshake messages,
         // so this function should never reach here (but return early with
         // std::nullopt above).
         BOTAN_ASSERT_UNREACHABLE();

      case HelloRequest:
      case HelloVerifyRequest:
      case ServerKeyExchange:
      case ServerHelloDone:
      case ClientKeyExchange:
      case CertificateUrl:
      case CertificateStatus:
      case HandshakeCCS:
      case None:
         // These messages are not used in TLS 1.3, hence, no TLS 1.3 flight
         // should ever be constructed with one of these messages.
         BOTAN_ASSERT_UNREACHABLE();
   }
}

Flight::Message_Info make_message_info(Handshake_Type handshake_type,
                                       SerializedHandshakeMessage serialized_message,
                                       const Flight::PostHandshake post_handshake) {
   return {
      .type = handshake_type,
      .epoch = epoch_for_handshake_type(handshake_type, post_handshake),
      .header = prepare_tls_handshake_header(handshake_type, serialized_message),
      .serialized = std::move(serialized_message),
   };
}

}  // namespace

void Flight::add(const Handshake_Message_13_Ref message, Transcript_Hash_State& transcript_hash, Callbacks& callbacks) {
   BOTAN_STATE_CHECK(m_post_handshake == PostHandshake::No);
   std::visit(
      [&](const auto msg) {
         callbacks.tls_inspect_handshake_msg(msg.get());

         auto msg_info = make_message_info(msg.get().wire_type(),
                                           // TODO: Handshake_Message::serialize() should return the strong type
                                           SerializedHandshakeMessage(msg.get().serialize()),
                                           PostHandshake::No);
         transcript_hash.update(msg_info.header, msg_info.serialized);
         m_messages.push_back(std::move(msg_info));
      },
      message);
}

void Flight::add(const Post_Handshake_Message_13 message, Callbacks& callbacks) {
   BOTAN_STATE_CHECK(m_post_handshake == PostHandshake::Yes);
   std::visit(
      [&](const auto& msg) {
         callbacks.tls_inspect_handshake_msg(msg);

         m_messages.push_back(make_message_info(msg.wire_type(),
                                                // TODO: Handshake_Message::serialize() should return the strong type
                                                SerializedHandshakeMessage(msg.serialize()),
                                                PostHandshake::Yes));
      },
      message);
}

void Flight::add_dummy_change_cipher_spec() {
   BOTAN_STATE_CHECK(m_post_handshake == PostHandshake::No);
   m_messages.push_back(Dummy_ChangeCipherSpec{});
}

namespace {

/**
 * Ensures that the constructed flight sequence is legal. In a sense that,
 * unprotected messages (if any) always come first and never after any
 * protected message. Dummy cipher specs don't interleave with protected
 * messages, and post-handshake flights never contain dummy cipher specs or
 * statically pinned epochs.
 *
 * @throws Internal_Error if the flight message sequence is illegal
 * @returns true if the flight message sequence is legal
 */
bool valid_message_sequence(std::span<const Flight::Message> flight, Flight::PostHandshake post_handshake) {
   bool in_protected_portion = false;
   bool change_cipher_spec_seen = false;

   for(const auto& msg_info : flight) {
      std::visit(  //
         overloaded{
            [&](const Flight::Dummy_ChangeCipherSpec&) {
               if(post_handshake == Flight::PostHandshake::Yes) {
                  throw Internal_Error("Flight contains a dummy ChangeCipherSpec in a post-handshake flight");
               }
               if(change_cipher_spec_seen) {
                  throw Internal_Error("Flight contains multiple dummy ChangeCipherSpec messages");
               }
               if(in_protected_portion) {
                  throw Internal_Error("Flight contains a dummy ChangeCipherSpec after a protected message");
               }

               change_cipher_spec_seen = true;
            },
            [&](const Flight::Message_Info& msg_info) {
               const bool static_epoch = msg_info.epoch.has_value();
               const bool protected_message = static_epoch && msg_info.epoch != Epoch_Number::Unprotected;

               if(post_handshake == Flight::PostHandshake::Yes) {
                  if(static_epoch) {
                     throw Internal_Error("Post-handshake flight contains a message with a pre-defined epoch");
                  }
               } else {
                  if(!static_epoch) {
                     throw Internal_Error("Handshake messages must have a pre-defined epoch");
                  }
                  if(protected_message) {
                     in_protected_portion = true;
                  } else if(in_protected_portion) {
                     throw Internal_Error("Flight contains an unprotected message after a protected message");
                  }
               }
            },
         },
         msg_info);
   }

   return true;
}

}  // namespace

std::vector<Flight::Message> Flight::commit() {
   BOTAN_DEBUG_ASSERT(valid_message_sequence(m_messages, m_post_handshake));
   return std::exchange(m_messages, {});
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
         // RFC 9846 E.4
         //    [...] the client sends a dummy change_cipher_spec record [...]
         //    immediately before its second flight.
         //
         // This is true also if the second flight is an alert aborting the
         // handshake (e.g., from a failing certificate verification or a
         // throwing callback).
         if(compat_mode_ccs_requested() && compat_mode_ccs_needed_before_alert()) {
            static constexpr std::array<uint8_t, 1> dummy_ccs = {0x01};
            send_record(Record_Type::ChangeCipherSpec, dummy_ccs);
         }

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

   // RFC 9147 8. (Errata-ID 8050)
   //    After the handshake, each epoch change consumes a message_seq value,
   //    which is limited to 2^16-1. [...] In this case, the implementation MUST
   //    check for this limit, if reached, terminate the association.
   //
   // We don't terminate the association but we reject any further key updates.
   if(is_datagram() &&
      to_underlying(m_cipher_state->current_write_epoch_number()) == std::numeric_limits<uint16_t>::max()) {
      // TODO: move to Channel_IO
      throw Invalid_State("Cannot update keys: maximum DTLS epoch number reached");
   }

   auto key_update_msg = Key_Update(request_peer_update);
   callbacks().tls_inspect_handshake_msg(key_update_msg);

   m_channel_io->send_key_update(std::move(key_update_msg), m_cipher_state.get(), *this);

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

   m_channel_io->send_records(record_type, payload, cipher_state);
}

void Channel_Impl_13::send_flight(std::vector<Flight::Message> flight) {
   BOTAN_STATE_CHECK(!flight.empty());
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_can_write);

   m_channel_io->send_flight(std::move(flight), m_cipher_state.get());
}

void Channel_Impl_13::process_alert(const secure_vector<uint8_t>& record) {
   const Alert alert(record);

   if(is_close_notify_alert(alert)) {
      m_can_read = false;
      if(m_cipher_state) {
         m_cipher_state->clear_read_keys();
      }
      m_channel_io->notify_closed_for_reading();
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

std::optional<size_t> Channel_Impl_13::process_event(Handshake_Message_13 handshake_msg) {
   process_handshake_msg(std::move(handshake_msg));

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
   if(is_downgrading()) {
      // Downgrade to TLS 1.2 was detected. Stop everything we do and await being replaced by a 1.2 implementation.
      return 0;
   }
   if(m_downgrade_info != nullptr) {
      // We received a TLS 1.3 error alert that could have been a TLS 1.2 warning alert.
      // Now that we know that we are talking to a TLS 1.3 server, shut down.
      if(m_downgrade_info->received_tls_13_error_alert) {
         shutdown();
      }

      // Downgrade can only be indicated in the first received peer message. This was not the case.
      m_downgrade_info.reset();
   }
#endif
   return std::nullopt;
}

std::optional<size_t> Channel_Impl_13::process_event(Post_Handshake_Message_13 post_handshake_msg) {
   process_post_handshake_msg(std::move(post_handshake_msg));
   return std::nullopt;
}

std::optional<size_t> Channel_Impl_13::process_event(const Record_Content& record) {
   switch(record.type) {
      case Record_Type::ChangeCipherSpec:
         process_dummy_change_cipher_spec();
         break;
      case Record_Type::ApplicationData:
         BOTAN_ASSERT_NONNULL(m_cipher_state);
         if(!m_cipher_state->can_decrypt_application_traffic()) {
            throw Unexpected_Message("Application data received before handshake completion");
         }
         /*
         The record sequence number is set in Record_Layer::next_record only when
         the record contents are decrypted under the current set of traffic keys
         for TLS or under any retained epoch for DTLS.
         */
         if(!record.sequence_number.has_value()) {
            throw Unexpected_Message("Application data must have a sequence number");
         }
         callbacks().tls_record_received(record.sequence_number.value(), record.payload);

         break;
      case Record_Type::Alert:
         process_alert(record.payload);
         break;
      default:
         throw Unexpected_Message("Unexpected record type " + std::to_string(static_cast<size_t>(record.type)) +
                                  " from counterparty");
   }

   return std::nullopt;
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
   m_channel_io->set_record_size_limits(outgoing_limit, incoming_limit);
}

void Channel_Impl_13::set_selected_certificate_type(const Certificate_Type cert_type) {
   m_channel_io->set_selected_certificate_type(cert_type);
}

std::unique_ptr<Channel_IO> Channel_IO::create(TLS_Flavor flavor,
                                               Connection_Side side,
                                               Channel_Impl_13& channel,
                                               const Secret_Logger& secret_logger,
                                               std::shared_ptr<const Policy> policy,
                                               std::shared_ptr<Callbacks> callbacks) {
   if(flavor == TLS_Flavor::DTLS) {
#if defined(BOTAN_HAS_DTLS_13)
      return std::make_unique<DTLS_Channel_IO>(side, channel, secret_logger, std::move(policy), std::move(callbacks));
#else
      throw Not_Implemented("DTLS 1.3 is not enabled in this build of Botan");
#endif
   } else {
      BOTAN_UNUSED(channel, secret_logger);
      return std::make_unique<TLS_Channel_IO>(side, std::move(policy), std::move(callbacks));
   }
}

}  // namespace Botan::TLS
