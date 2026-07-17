/*
* TLS cipher state implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/**
 * Cipher_State state machine adapted from RFC 8446 7.1.
 *
 *                                     0
 *                                     |
 *                                     v
 *                           PSK ->  HKDF-Extract = Early Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "ext binder" | "res binder" | "imp binder", "")
 *                                     |                     = binder_key
 *                              STATE PSK BINDER
 * This state is reached by constructing the Cipher_State using init_with_psk().
 * The state can then be further advanced using advance_with_client_hello() once
 * the initial Client Hello is fully generated.
 *                                     |
 *                                     +-----> Derive-Secret(., "c e traffic", ClientHello)
 *                                     |                     = client_early_traffic_secret
 *                                     |
 *                                     +-----> Derive-Secret(., "e exp master", ClientHello)
 *                                     |                     = early_exporter_master_secret
 *                                     v
 *                               Derive-Secret(., "derived", "")
 *                                     |
 *                                     *
 *                             STATE EARLY TRAFFIC
 * This state is reached by calling advance_with_client_hello().
 * In this state the early data traffic secrets are available. TODO: implement early data.
 * The state can then be further advanced using advance_with_server_hello().
 *                                     *
 *                                     |
 *                                     v
 *                           (EC)DHE -> HKDF-Extract = Handshake Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "c hs traffic",
 *                                     |                     ClientHello...ServerHello)
 *                                     |                     = client_handshake_traffic_secret
 *                                     |
 *                                     +-----> Derive-Secret(., "s hs traffic",
 *                                     |                     ClientHello...ServerHello)
 *                                     |                     = server_handshake_traffic_secret
 *                                     v
 *                               Derive-Secret(., "derived", "")
 *                                     |
 *                                     *
 *                          STATE HANDSHAKE TRAFFIC
 * This state is reached by constructing Cipher_State using init_with_server_hello() or
 * advance_with_server_hello(). In this state the handshake traffic secrets are available.
 * The state can then be further advanced using advance_with_server_finished().
 *                                     *
 *                                     |
 *                                     v
 *                           0 -> HKDF-Extract = Master Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "c ap traffic",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = client_application_traffic_secret_0
 *                                     |
 *                                     +-----> Derive-Secret(., "s ap traffic",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = server_application_traffic_secret_0
 *                                     |
 *                                     +-----> Derive-Secret(., "exp master",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = exporter_master_secret
 *                                     *
 *                      STATE SERVER APPLICATION TRAFFIC
 * This state is reached by calling advance_with_server_finished(). It allows the server
 * to send application traffic and the client to receive it. The opposite direction is not
 * yet possible in this state. The state can then be further advanced using
 * advance_with_client_finished().
 *                                     *
 *                                     |
 *                                     +-----> Derive-Secret(., "res master",
 *                                                           ClientHello...client Finished)
 *                                                           = resumption_master_secret
 *                             STATE COMPLETED
 * Once this state is reached the handshake is finished, both client and server can exchange
 * application data and no further cipher state advances are possible.
 */

#include <limits>
#include <utility>

#include <botan/internal/tls_cipher_state.h>

#include <botan/aead.h>
#include <botan/assert.h>
#include <botan/hash.h>
#include <botan/secmem.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_magic.h>

#include <botan/internal/concat_util.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_impl_13.h>

#if defined(BOTAN_HAS_DTLS_13)
   #include <botan/block_cipher.h>
   #include <botan/stream_cipher.h>
   #include <botan/internal/tls_utils_dtls13.h>
#endif

namespace Botan::TLS {

namespace {
// RFC 8446 5.3
//    Each AEAD algorithm will specify a range of possible lengths for the
//    per-record nonce, from N_MIN bytes to N_MAX bytes of input [RFC5116].
//    The length of the TLS per-record nonce (iv_length) is set to the
//    larger of 8 bytes and N_MIN for the AEAD algorithm (see [RFC5116],
//    Section 4).
//
// N_MIN is 12 for AES_GCM and AES_CCM as per RFC 5116 and also 12 for ChaCha20 per RFC 8439.
constexpr size_t NONCE_LENGTH = 12;

}  // namespace

std::unique_ptr<Cipher_State> Cipher_State::init_with_server_hello(const Connection_Side side,
                                                                   secure_vector<uint8_t>&& shared_secret,
                                                                   const Ciphersuite& cipher,
                                                                   const Transcript_Hash& transcript_hash,
                                                                   const Secret_Logger& logger,
                                                                   TLS_Flavor flavor) {
   auto cs = std::unique_ptr<Cipher_State>(new Cipher_State(side, cipher.prf_algo(), flavor));
   cs->advance_without_psk();
   cs->advance_with_server_hello(cipher, std::move(shared_secret), transcript_hash, logger);
   return cs;
}

std::unique_ptr<Cipher_State> Cipher_State::init_with_psk(const Connection_Side side,
                                                          const Cipher_State::PSK_Type type,
                                                          secure_vector<uint8_t>&& psk,
                                                          std::string_view prf_algo,
                                                          TLS_Flavor flavor) {
   auto cs = std::unique_ptr<Cipher_State>(new Cipher_State(side, prf_algo, flavor));
   cs->advance_with_psk(type, std::move(psk));
   return cs;
}

void Cipher_State::advance_with_client_hello(const Transcript_Hash& transcript_hash, const Secret_Logger& logger) {
   BOTAN_ASSERT_NOMSG(m_state == State::PskBinder);
   BOTAN_DEBUG_ASSERT(current_write_epoch_number() == Epoch_Number::Unprotected);
   BOTAN_DEBUG_ASSERT(current_read_epoch_number() == Epoch_Number::Unprotected);

   zap(m_binder_key);

   // TODO: Currently 0-RTT is not yet implemented, hence we don't derive the
   //       early traffic secret for now.
   //
   // const auto client_early_traffic_secret = derive_secret(m_early_secret, "c e traffic", transcript_hash);
   // derive_write_traffic_key(client_early_traffic_secret);

   m_exporter_master_secret = derive_secret(m_early_secret, "e exp master", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label
   //    "EARLY_EXPORTER_MASTER_SECRET" to identify the secret that is using for
   //    early exporters
   logger.maybe_log_secret("EARLY_EXPORTER_MASTER_SECRET", m_exporter_master_secret);

   m_salt = derive_secret(m_early_secret, "derived", empty_hash());
   zap(m_early_secret);

   m_state = State::EarlyTraffic;
}

void Cipher_State::advance_with_server_finished(const Transcript_Hash& transcript_hash, const Secret_Logger& logger) {
   BOTAN_ASSERT_NOMSG(m_state == State::HandshakeTraffic);
   BOTAN_DEBUG_ASSERT(current_write_epoch_number() == Epoch_Number::HandshakeTraffic);
   BOTAN_DEBUG_ASSERT(current_read_epoch_number() == Epoch_Number::HandshakeTraffic);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   // We have to stash the client traffic application secret until the client's
   // Finished message is available. Only then can we update the respective
   // encryption/decryption epoch. See `advance_with_client_finished()`.
   m_client_application_traffic_secret_0 = derive_secret(master_secret, "c ap traffic", transcript_hash);
   auto server_application_traffic_secret = derive_secret(master_secret, "s ap traffic", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label "CLIENT_TRAFFIC_SECRET_0"
   //    and "SERVER_TRAFFIC_SECRET_0" to identify the secrets are using to
   //    protect the connection.
   logger.maybe_log_secret("CLIENT_TRAFFIC_SECRET_0", m_client_application_traffic_secret_0);
   logger.maybe_log_secret("SERVER_TRAFFIC_SECRET_0", server_application_traffic_secret);

   // Note: the secrets for processing client's application data
   //       are not derived before the client's Finished message
   //       was seen and the handshake can be considered finished.
   if(m_connection_side == Connection_Side::Server) {
      advance_write_epoch(server_application_traffic_secret);
   } else {
      advance_read_epoch(server_application_traffic_secret);
   }

   m_exporter_master_secret = derive_secret(master_secret, "exp master", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label "EXPORTER_SECRET" to
   //    identify the secret that is used in generating exporters(rfc8446
   //    Section 7.5).
   logger.maybe_log_secret("EXPORTER_SECRET", m_exporter_master_secret);

   m_state = State::ServerApplicationTraffic;
}

void Cipher_State::advance_with_client_finished(const Transcript_Hash& transcript_hash) {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic);
   BOTAN_DEBUG_ASSERT(/* Server => (read_epoch == Handshake && write_epoch == AppTraffic) */
                      m_connection_side != Connection_Side::Server ||
                      (current_read_epoch_number() == Epoch_Number::HandshakeTraffic &&
                       current_write_epoch_number() >= Epoch_Number::ApplicationTraffic_0));
   BOTAN_DEBUG_ASSERT(/* Client => (read_epoch == AppTraffic && write_epoch == Handshake) */
                      m_connection_side != Connection_Side::Client ||
                      (current_write_epoch_number() == Epoch_Number::HandshakeTraffic &&
                       current_read_epoch_number() >= Epoch_Number::ApplicationTraffic_0));

   // With the client's Finished message, the handshake is complete and
   // we can process client application data.
   if(m_connection_side == Connection_Side::Server) {
      advance_read_epoch(m_client_application_traffic_secret_0);
   } else {
      advance_write_epoch(m_client_application_traffic_secret_0);
   }

   // The handshake is complete, we won't need the stashed client application
   // traffic secret any longer.
   zap(m_client_application_traffic_secret_0);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   m_resumption_master_secret = derive_secret(master_secret, "res master", transcript_hash);

   // This was the final state change; the salt is no longer needed.
   zap(m_salt);

   m_state = State::Completed;
}

namespace {

auto current_nonce(const uint64_t seq_no, std::span<const uint8_t> iv) {
   // RFC 8446 5.3
   //    The per-record nonce for the AEAD construction is formed as follows:
   //
   //    1.  The 64-bit record sequence number is encoded in network byte
   //        order and padded to the left with zeros to iv_length.
   //
   //    2.  The padded sequence number is XORed with either the static
   //        client_write_iv or server_write_iv (depending on the role).
   std::array<uint8_t, NONCE_LENGTH> nonce{};
   store_be(std::span{nonce}.last<sizeof(seq_no)>(), seq_no);
   xor_buf(nonce, iv);
   return nonce;
}

}  // namespace

MarshalledRecord Cipher_State::protect_record(Record_Type type,
                                              std::span<const uint8_t> plaintext,
                                              size_t padding_bytes) {
   BOTAN_STATE_CHECK(current_write_epoch_number() > Epoch_Number::Unprotected);

   auto& epoch = *m_write_epochs.back();

   // RFC 8446 5.3
   //    Sequence numbers MUST NOT wrap.
   // RFC 9147 4.2.1
   //    Implementations MUST either abandon an association or rekey prior to
   //    allowing the sequence number to wrap.
   if(epoch.sequence_number == std::numeric_limits<uint64_t>::max()) {
      throw Invalid_State("TLS write sequence number overflow");
   }

   const size_t plaintext_payload_length = plaintext.size() + padding_bytes + 1 /* content_type byte */;
   const size_t encrypted_payload_length = encrypt_output_length(plaintext_payload_length);
   const size_t unprotected_record_length = TLS_HEADER_SIZE + plaintext_payload_length;
   const size_t protected_record_length = TLS_HEADER_SIZE + encrypted_payload_length;

   MarshalledRecord result;
   result.reserve(protected_record_length);

   // RFC 9846 5.2
   //    opaque_type: The outer opaque_type field of a TLSCiphertext record is
   //                 always set to the value 23 (application_data) [...]
   //    legacy_record_version: [...] is always 0x0303. TLS 1.3 TLSCiphertexts
   //                           are not generated until after TLS 1.3 has been
   //                           negotiated, so there are no historical
   //                           compatibility concerns [...].
   //    length: [...] of the following TLSCiphertext.encrypted_record, which is
   //            the sum of the lengths of the content and the padding, plus one
   //            for the inner content type, plus any expansion added by the
   //            AEAD algorithm.
   const auto header = Record_TLS::serialize_header(Record_Type::ApplicationData,
                                                    Protocol_Version::TLS_V12 /* = 0x0303 */,
                                                    checked_cast_to<uint16_t>(encrypted_payload_length));
   result.get().insert(result.end(), header.begin(), header.end());

   // RFC 9846 5.2
   //    struct {
   //        opaque content[TLSPlaintext.length];
   //        ContentType type;
   //        uint8 zeros[length_of_padding];
   //    } TLSInnerPlaintext;
   //
   // RFC 9846 5.4
   //    When generating a TLSCiphertext record, implementations MAY choose to
   //    pad. [...] Implementations MUST set the padding octets to all zeros
   //    before encrypting.
   result.get().insert(result.end(), plaintext.begin(), plaintext.end());  // content
   result.get().push_back(to_underlying(type));                            // type
   result.get().insert(result.end(), padding_bytes, 0x00);                 // zeros (padding)

   BOTAN_ASSERT_NOMSG(result.size() == unprotected_record_length);
   epoch.cipher->set_associated_data(std::span{result}.first<TLS_HEADER_SIZE>());
   epoch.cipher->start(current_nonce(epoch.sequence_number++, epoch.iv));
   epoch.cipher->finish(result, TLS_HEADER_SIZE);
   BOTAN_ASSERT_NOMSG(result.size() == protected_record_length);

   return result;
}

Record_Content Cipher_State::deprotect_record(Record_TLS record, size_t incoming_record_size_limit) {
   BOTAN_STATE_CHECK(current_read_epoch_number() > Epoch_Number::Unprotected);
   BOTAN_ARG_CHECK(record.type() == Record_Type::ApplicationData, "Record type must be ApplicationData");

   auto& epoch = *m_read_epochs.back();

   // RFC 9846 5.2
   //    length: The length (in bytes) [...], which is the sum of the lengths of
   //            the content and the padding, plus one for the inner content
   //            type, plus any expansion added by the AEAD algorithm.
   //    [...]
   //    If the decryption fails, the receiver MUST terminate the connection
   //    with a "bad_record_mac" alert.
   //
   // If the protected record contains less bytes than the expected AEAD tag we
   // can already fail early because the decryption will fail anyway.
   if(record.payload().size() < epoch.cipher->minimum_final_size()) {
      throw TLS_Exception(Alert::BadRecordMac, "incomplete record mac received");
   }

   // RFC 9846 6.2
   //    record_overflow: A TLSCiphertext record was received that had a length
   //    more than 2^14 + 256 bytes, or a record decrypted to a TLSPlaintext
   //    record with more than 214 bytes (or some other negotiated limit).
   //
   // RFC 8449 4.
   //    A TLS endpoint that receives a record larger than its advertised limit
   //    MUST generate a fatal "record_overflow" alert [...].
   if(decrypt_output_length(record.payload().size()) > incoming_record_size_limit) {
      throw TLS_Exception(Alert::RecordOverflow, "Received an encrypted record that exceeds maximum plaintext size");
   }

   // RFC 8446 5.3
   //    Sequence numbers MUST NOT wrap.
   if(epoch.sequence_number == std::numeric_limits<uint64_t>::max()) {
      throw Invalid_State("TLS read sequence number overflow");
   }

   auto result = Record_Content{
      .type = Record_Type::Invalid,
      .sequence_number = epoch.sequence_number++,
      .payload = record.take_payload(),
      .epoch = std::nullopt,
   };

   BOTAN_ASSERT_NOMSG(result.payload.size() <= MAX_CIPHERTEXT_SIZE_TLS13);
   epoch.cipher->set_associated_data(record.header());
   epoch.cipher->start(current_nonce(result.sequence_number.value(), epoch.iv));
   epoch.cipher->finish(result.payload);
   BOTAN_ASSERT_NOMSG(result.payload.size() <= MAX_PLAINTEXT_SIZE + 1 /* content_type byte */);

   // Remove record padding (RFC 9846 5.4). The TLSInnerPlaintext layout is
   //   content || content_type || zero_padding
   auto seen_nonzero = CT::Mask<uint8_t>::cleared();
   uint8_t content_type_byte = 0;
   size_t content_index = 0;
   for(size_t i = result.payload.size(); i-- > 0;) {
      const uint8_t b = result.payload[i];
      const auto byte_is_nonzero = CT::Mask<uint8_t>::expand(b);
      // Set on the first non-zero byte we encounter scanning right-to-left.
      const auto first_nonzero = byte_is_nonzero & ~seen_nonzero;
      content_type_byte = first_nonzero.select(b, content_type_byte);
      content_index = CT::Mask<size_t>::expand(first_nonzero.value()).select(i, content_index);
      seen_nonzero |= byte_is_nonzero;
   }

   // RFC 9846 5.4
   //   If a receiving implementation does not find a non-zero octet in the
   //   cleartext, it MUST terminate the connection with an
   //   "unexpected_message" alert.
   if(!seen_nonzero.as_bool()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "No content type found in encrypted record");
   }

   // hydrate the actual content type from TLSInnerPlaintext
   result.type = static_cast<Record_Type>(content_type_byte);

   // RFC 9846 5.
   //    An implementation [...] which receives a protected change_cipher_spec
   //    record MUST abort the handshake with an "unexpected_message" alert.
   //    [....]
   //    If a TLS implementation receives an unexpected record type, it MUST
   //    terminate the connection with an "unexpected_message" alert.
   //
   // RFC 9846 5.1
   //    enum {
   //        invalid(0),
   //        change_cipher_spec(20),
   //        alert(21),
   //        handshake(22),
   //        application_data(23),
   //        (255)
   //    } ContentType;
   if(result.type != Record_Type::ApplicationData &&  //
      result.type != Record_Type::Handshake &&        //
      result.type != Record_Type::Alert) {
      throw TLS_Exception(Alert::UnexpectedMessage, "protected TLS record type had unexpected value");
   }

   // Truncate to drop the content_type byte and padding. resize() on a
   // vector of trivially-destructible elements is bookkeeping-only and
   // does not allocate or iterate over the dropped suffix.
   result.payload.resize(content_index);

   // RFC 9846 5.4
   //    Implementations MUST NOT send Handshake and Alert records that have
   //    a zero-length TLSInnerPlaintext.content; if such a message is
   //    received, the receiving implementation MUST terminate the connection
   //    with an "unexpected_message" alert.
   if(result.payload.empty() && result.type != Record_Type::ApplicationData) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received a protected record with empty TLSInnerPlaintext content");
   }

   return result;
}

size_t Cipher_State::encrypt_output_length(const size_t input_length) const {
   BOTAN_STATE_CHECK(current_write_epoch_number() > Epoch_Number::Unprotected);
   // This assumes that the AEAD cipher's output length does not change
   // between epochs.
   return m_write_epochs.back()->cipher->output_length(input_length);
}

size_t Cipher_State::decrypt_output_length(const size_t input_length) const {
   BOTAN_STATE_CHECK(current_read_epoch_number() > Epoch_Number::Unprotected);
   // This assumes that the AEAD cipher's output length does not change
   // between epochs.
   return m_read_epochs.back()->cipher->output_length(input_length);
}

size_t Cipher_State::minimum_decryption_input_length() const {
   BOTAN_STATE_CHECK(current_read_epoch_number() > Epoch_Number::Unprotected);
   // This assumes that the AEAD cipher's minimal final size does not change
   // between epochs.
   return m_read_epochs.back()->cipher->minimum_final_size();
}

bool Cipher_State::must_expect_unprotected_alert_traffic() const {
   // Client side:
   //   After successfully receiving a Server Hello we expect servers to send
   //   alerts as protected records only, just like they start protecting their
   //   handshake data at this point.
   if(m_connection_side == Connection_Side::Client && m_state == State::EarlyTraffic) {
      return true;
   }

   // Server side:
   //   Servers must expect clients to send unprotected alerts during the hand-
   //   shake. In particular, in the response to the server's first protected
   //   flight. We don't expect the client to send alerts protected under the
   //   early traffic secret.
   //
   // TODO: when implementing PSK and/or early data for the server, we might
   //       need to reconsider this decision.
   if(m_connection_side == Connection_Side::Server &&
      (m_state == State::HandshakeTraffic || m_state == State::ServerApplicationTraffic)) {
      return true;
   }

   return false;
}

bool Cipher_State::can_encrypt_application_traffic() const {
   // TODO: when implementing early traffic (0-RTT) this will likely need
   //       to allow `State::EarlyTraffic`.
   return current_write_epoch_number() >= Epoch_Number::ApplicationTraffic_0;
}

bool Cipher_State::can_decrypt_application_traffic() const {
   // TODO: when implementing early traffic (0-RTT) this will likely need
   //       to allow `State::EarlyTraffic`.
   return current_read_epoch_number() >= Epoch_Number::ApplicationTraffic_0;
}

std::string Cipher_State::hash_algorithm() const {
   BOTAN_ASSERT_NONNULL(m_hash);
   return m_hash->name();
}

bool Cipher_State::is_compatible_with(const Ciphersuite& cipher) const {
   if(!cipher.usable_in_version(Protocol_Version::TLS_V13)) {
      return false;
   }

   if(hash_algorithm() != cipher.prf_algo()) {
      return false;
   }

   BOTAN_ASSERT_NOMSG((current_write_epoch_number() == Epoch_Number::Unprotected) ==
                      (current_read_epoch_number() == Epoch_Number::Unprotected));

   // Compare canonical AEAD names rather than substring-matching cipher_algo
   // against m_encrypt->name(). starts_with() is both too permissive (an
   // AES-128/CCM-8 instance starts with "AES-128/CCM" so it would accept the
   // CCM-16 suite) and too restrictive (cipher_algo "AES-128/CCM(8)" does not
   // prefix the canonical "AES-128/CCM(8,3)"). Re-instantiating the AEAD from
   // cipher_algo yields the same canonical name() the suite would produce.
   if(current_write_epoch_number() > Epoch_Number::Unprotected) {
      auto canonical = AEAD_Mode::create(cipher.cipher_algo(), Cipher_Dir::Encryption);
      // This assumes that the AEAD cipher does not change between epochs.
      if(!canonical || canonical->name() != m_write_epochs.back()->cipher->name()) {
         return false;
      }
   }

   return true;
}

std::vector<uint8_t> Cipher_State::psk_binder_mac(
   const Transcript_Hash& transcript_hash_with_truncated_client_hello) const {
   BOTAN_ASSERT_NOMSG(m_state == State::PskBinder);

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(m_binder_key);
   hmac.update(transcript_hash_with_truncated_client_hello);
   return hmac.final_stdvec();
}

std::vector<uint8_t> Cipher_State::finished_mac(const Transcript_Hash& transcript_hash) const {
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Server || m_state == State::HandshakeTraffic);
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Client || m_state == State::ServerApplicationTraffic);
   BOTAN_ASSERT_NOMSG(current_write_epoch_number() == Epoch_Number::HandshakeTraffic);

   auto& epoch = *m_write_epochs.back();
   BOTAN_ASSERT_NOMSG(epoch.finished_key.has_value());

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(*epoch.finished_key);
   hmac.update(transcript_hash);
   return hmac.final_stdvec();
}

bool Cipher_State::verify_peer_finished_mac(const Transcript_Hash& transcript_hash,
                                            const std::vector<uint8_t>& peer_mac) const {
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Server || m_state == State::ServerApplicationTraffic);
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Client || m_state == State::HandshakeTraffic);
   BOTAN_ASSERT_NOMSG(current_read_epoch_number() == Epoch_Number::HandshakeTraffic);

   auto& epoch = *m_read_epochs.back();
   BOTAN_ASSERT_NOMSG(epoch.finished_key.has_value());

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(*epoch.finished_key);
   hmac.update(transcript_hash);
   return hmac.verify_mac(peer_mac);
}

secure_vector<uint8_t> Cipher_State::psk(const Ticket_Nonce& nonce) const {
   BOTAN_ASSERT_NOMSG(m_state == State::Completed);

   return derive_secret(m_resumption_master_secret, "resumption", nonce.get());
}

Ticket_Nonce Cipher_State::next_ticket_nonce() {
   BOTAN_STATE_CHECK(m_state == State::Completed);
   if(m_ticket_nonce_exhausted) {
      throw Botan::Invalid_State("ticket nonce pool exhausted");
   }

   auto retval = store_be<Ticket_Nonce>(m_ticket_nonce);

   if(m_ticket_nonce == std::numeric_limits<decltype(m_ticket_nonce)>::max()) {
      m_ticket_nonce_exhausted = true;
   } else {
      ++m_ticket_nonce;
   }

   return retval;
}

secure_vector<uint8_t> Cipher_State::export_key(std::string_view label, std::string_view context, size_t length) const {
   BOTAN_ASSERT_NOMSG(can_export_keys());

   m_hash->update(context);
   const auto context_hash = m_hash->final_stdvec();
   return hkdf_expand_label(
      derive_secret(m_exporter_master_secret, label, empty_hash()), "exporter", context_hash, length);
}

namespace {

std::unique_ptr<MessageAuthenticationCode> create_hmac(std::string_view hash) {
   return std::make_unique<HMAC>(HashFunction::create_or_throw(hash));
}

}  // namespace

Cipher_State::Cipher_State(Connection_Side whoami, std::string_view hash_function, TLS_Flavor flavor) :
      m_tls_flavor(flavor),
      m_state(State::Uninitialized),
      m_connection_side(whoami),
      m_extract(std::make_unique<HKDF_Extract>(create_hmac(hash_function))),
      m_expand(std::make_unique<HKDF_Expand>(create_hmac(hash_function))),
      m_hash(HashFunction::create_or_throw(hash_function)),
      m_salt(m_hash->output_length(), 0x00),
      m_write_key_update_count(0),
      m_read_key_update_count(0),
      m_ticket_nonce(0) {}

Cipher_State::~Cipher_State() = default;

void Cipher_State::advance_without_psk() {
   BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);
   BOTAN_DEBUG_ASSERT(current_write_epoch_number() == Epoch_Number::Unprotected);
   BOTAN_DEBUG_ASSERT(current_read_epoch_number() == Epoch_Number::Unprotected);

   // We are not using `m_early_secret` here because the secret won't be needed
   // in any further state advancement methods.
   const auto early_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));
   m_salt = derive_secret(early_secret, "derived", empty_hash());

   // Without PSK we skip the `PskBinder` state and go right to `EarlyTraffic`.
   m_state = State::EarlyTraffic;
}

void Cipher_State::advance_with_psk(PSK_Type type, secure_vector<uint8_t>&& psk) {
   BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);
   BOTAN_DEBUG_ASSERT(current_write_epoch_number() == Epoch_Number::Unprotected);
   BOTAN_DEBUG_ASSERT(current_read_epoch_number() == Epoch_Number::Unprotected);

   m_early_secret = hkdf_extract(std::move(psk));

   // RFC 8446 and RFC 9258 specify these strings
   const char* binder_label = [type]() -> const char* {
      switch(type) {
         case PSK_Type::Resumption:
            return "res binder";
         case PSK_Type::External:
            return "ext binder";
         case PSK_Type::Imported:
            return "imp binder";
      }
      BOTAN_ASSERT_UNREACHABLE();
   }();

   // RFC 8446 4.2.11.2
   //    The PskBinderEntry is computed in the same way as the Finished message
   //    [...] but with the BaseKey being the binder_key derived via the key
   //    schedule from the corresponding PSK which is being offered.
   //
   // Hence we are doing the binder key derivation and expansion in one go.
   const auto binder_key = derive_secret(m_early_secret, binder_label, empty_hash());
   m_binder_key = hkdf_expand_label(binder_key, "finished", {}, m_hash->output_length());

   // TODO: Implement early data (0-RTT) and derive early traffic secrets here.

   m_state = State::PskBinder;
}

void Cipher_State::advance_with_server_hello(const Ciphersuite& cipher,
                                             secure_vector<uint8_t>&& shared_secret,
                                             const Transcript_Hash& transcript_hash,
                                             const Secret_Logger& logger) {
   BOTAN_ASSERT_NOMSG(m_state == State::EarlyTraffic);
   BOTAN_STATE_CHECK(is_compatible_with(cipher));
   BOTAN_STATE_CHECK(!m_ciphersuite.has_value());
   BOTAN_DEBUG_ASSERT(current_write_epoch_number() == Epoch_Number::Unprotected);
   BOTAN_DEBUG_ASSERT(current_read_epoch_number() == Epoch_Number::Unprotected);

   m_ciphersuite = cipher;

   const auto handshake_secret = hkdf_extract(std::move(shared_secret));

   const auto client_handshake_traffic_secret = derive_secret(handshake_secret, "c hs traffic", transcript_hash);
   const auto server_handshake_traffic_secret = derive_secret(handshake_secret, "s hs traffic", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label
   //    "CLIENT_HANDSHAKE_TRAFFIC_SECRET" and "SERVER_HANDSHAKE_TRAFFIC_SECRET"
   //    to identify the secrets are using to protect handshake messages.
   logger.maybe_log_secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_handshake_traffic_secret);
   logger.maybe_log_secret("SERVER_HANDSHAKE_TRAFFIC_SECRET", server_handshake_traffic_secret);

   if(m_connection_side == Connection_Side::Server) {
      advance_read_epoch(client_handshake_traffic_secret, Epoch_Number::HandshakeTraffic);
      advance_write_epoch(server_handshake_traffic_secret, Epoch_Number::HandshakeTraffic);
   } else {
      advance_read_epoch(server_handshake_traffic_secret, Epoch_Number::HandshakeTraffic);
      advance_write_epoch(client_handshake_traffic_secret, Epoch_Number::HandshakeTraffic);
   }

   m_salt = derive_secret(handshake_secret, "derived", empty_hash());

   m_state = State::HandshakeTraffic;
}

std::unique_ptr<Cipher_State::Epoch> Cipher_State::create_epoch(Epoch_Number epoch_number,
                                                                Cipher_Dir direction,
                                                                const secure_vector<uint8_t>& traffic_secret) const {
   auto epoch = Epoch{
      .number = epoch_number,
      .cipher = AEAD_Mode::create_or_throw(m_ciphersuite->cipher_algo(), direction),
      .iv = hkdf_expand_label(traffic_secret, "iv", {}, NONCE_LENGTH),
      .sequence_number = 0,
      .traffic_secret = traffic_secret,
   };

   epoch.cipher->set_key(hkdf_expand_label(traffic_secret, "key", {}, epoch.cipher->minimum_keylength()));

   if(epoch_number == Epoch_Number::HandshakeTraffic) {
      epoch.finished_key = hkdf_expand_label(traffic_secret, "finished", {}, m_hash->output_length());
   }

   if(m_tls_flavor == TLS_Flavor::DTLS) {
      // RFC 9147 Section 4.2.3
      epoch.sequence_number_key = hkdf_expand_label(traffic_secret, "sn", {}, epoch.cipher->minimum_keylength());
   }

   return std::make_unique<Epoch>(std::move(epoch));
}

namespace {

Epoch_Number operator+(Epoch_Number current, size_t offset) {
   return static_cast<Epoch_Number>(to_underlying(current) + offset);
}

}  // namespace

void Cipher_State::advance_write_epoch(const secure_vector<uint8_t>& traffic_secret,
                                       std::optional<Epoch_Number> epoch_number) {
   const auto next_epoch_number = epoch_number.value_or(current_write_epoch_number() + 1);
   m_write_epochs.push_back(create_epoch(next_epoch_number, Cipher_Dir::Encryption, traffic_secret));

   // TODO: How many epochs should we keep around for DTLS?
   const size_t epochs_to_keep = m_tls_flavor == TLS_Flavor::DTLS ? 2 : 1;
   BOTAN_ASSERT_NOMSG(m_write_epochs.size() <= epochs_to_keep + 1);
   if(m_write_epochs.size() > epochs_to_keep) {
      m_write_epochs.erase(m_write_epochs.begin());
   }
}

void Cipher_State::advance_read_epoch(const secure_vector<uint8_t>& traffic_secret,
                                      std::optional<Epoch_Number> epoch_number) {
   const auto next_epoch_number = epoch_number.value_or(current_read_epoch_number() + 1);
   m_read_epochs.push_back(create_epoch(next_epoch_number, Cipher_Dir::Decryption, traffic_secret));

   // TODO: How many epochs should we keep around for DTLS?
   const size_t epochs_to_keep = m_tls_flavor == TLS_Flavor::DTLS ? 2 : 1;
   BOTAN_ASSERT_NOMSG(m_read_epochs.size() <= epochs_to_keep + 1);
   if(m_read_epochs.size() > epochs_to_keep) {
      m_read_epochs.erase(m_read_epochs.begin());
   }
}

secure_vector<uint8_t> Cipher_State::hkdf_extract(std::span<const uint8_t> ikm) const {
   return m_extract->derive_key(m_hash->output_length(), ikm, m_salt, std::vector<uint8_t>());
}

secure_vector<uint8_t> Cipher_State::hkdf_expand_label(const secure_vector<uint8_t>& secret,
                                                       std::string_view label,
                                                       const std::vector<uint8_t>& context,
                                                       const size_t length) const {
   BOTAN_ARG_CHECK(length <= std::numeric_limits<uint16_t>::max(), "invalid length");
   BOTAN_ARG_CHECK(context.size() <= 255, "context too large");

   const std::string_view prefix = m_tls_flavor == TLS_Flavor::DTLS ? "dtls13" : "tls13 ";

   const auto hkdf_label = concat<secure_vector<uint8_t>>(store_be(static_cast<uint16_t>(length)),
                                                          store_be(static_cast<uint8_t>(prefix.size() + label.size())),
                                                          as_span_of_bytes(prefix),
                                                          as_span_of_bytes(label),
                                                          store_be(static_cast<uint8_t>(context.size())),
                                                          context);

   // HKDF-Expand
   return m_expand->derive_key(
      length, secret, hkdf_label, std::vector<uint8_t>() /* just pleasing botan's interface */);
}

secure_vector<uint8_t> Cipher_State::derive_secret(const secure_vector<uint8_t>& secret,
                                                   std::string_view label,
                                                   const Transcript_Hash& messages_hash) const {
   return hkdf_expand_label(secret, label, messages_hash, m_hash->output_length());
}

std::vector<uint8_t> Cipher_State::empty_hash() const {
   m_hash->update("");
   return m_hash->final_stdvec();
}

void Cipher_State::update_read_keys(const Secret_Logger& logger) {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic || m_state == State::Completed);
   BOTAN_ASSERT_NOMSG(current_read_epoch_number() >= Epoch_Number::ApplicationTraffic_0);

   auto& epoch = *m_read_epochs.back();

   const auto new_read_application_traffic_secret =
      hkdf_expand_label(epoch.traffic_secret, "traffic upd", {}, m_hash->output_length());

   const auto secret_label = fmt("{}_TRAFFIC_SECRET_{}",
                                 m_connection_side == Connection_Side::Server ? "CLIENT" : "SERVER",
                                 ++m_read_key_update_count);
   logger.maybe_log_secret(secret_label, new_read_application_traffic_secret);

   advance_read_epoch(new_read_application_traffic_secret);
}

void Cipher_State::update_write_keys(const Secret_Logger& logger) {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic || m_state == State::Completed);
   BOTAN_ASSERT_NOMSG(current_write_epoch_number() >= Epoch_Number::ApplicationTraffic_0);

   auto& epoch = *m_write_epochs.back();

   const auto new_write_application_traffic_secret =
      hkdf_expand_label(epoch.traffic_secret, "traffic upd", {}, m_hash->output_length());

   const auto secret_label = fmt("{}_TRAFFIC_SECRET_{}",
                                 m_connection_side == Connection_Side::Server ? "SERVER" : "CLIENT",
                                 ++m_write_key_update_count);
   logger.maybe_log_secret(secret_label, new_write_application_traffic_secret);

   advance_write_epoch(new_write_application_traffic_secret);
}

uint64_t Cipher_State::current_write_sequence_number() const {
   BOTAN_STATE_CHECK(current_write_epoch_number() > Epoch_Number::Unprotected);
   return m_write_epochs.back()->sequence_number;
}

uint64_t Cipher_State::current_read_sequence_number() const {
   BOTAN_STATE_CHECK(current_read_epoch_number() > Epoch_Number::Unprotected);
   return m_read_epochs.back()->sequence_number;
}

void Cipher_State::encrypt_record_fragment_dtls(uint64_t seq_no,
                                                std::span<const uint8_t> header,
                                                secure_vector<uint8_t>& fragment) {
#if defined(BOTAN_HAS_DTLS_13)
   BOTAN_ASSERT_NOMSG(m_tls_flavor == TLS_Flavor::DTLS);
   BOTAN_STATE_CHECK(current_write_epoch_number() > Epoch_Number::Unprotected);

   auto& epoch = *m_write_epochs.back();
   BOTAN_STATE_CHECK(seq_no == epoch.sequence_number);

   epoch.cipher->set_associated_data(header);
   epoch.cipher->start(current_nonce(seq_no, epoch.iv));
   epoch.cipher->finish(fragment);

   epoch.sequence_number++;
#else
   BOTAN_UNUSED(seq_no, header, fragment);
   throw Not_Implemented("DTLS 1.3 is not configured");
#endif
}

void Cipher_State::decrypt_record_fragment_dtls(uint64_t seq_no,
                                                std::span<const uint8_t> header,
                                                secure_vector<uint8_t>& fragment) {
#if defined(BOTAN_HAS_DTLS_13)
   BOTAN_ASSERT_NOMSG(m_tls_flavor == TLS_Flavor::DTLS);
   BOTAN_STATE_CHECK(current_read_epoch_number() > Epoch_Number::Unprotected);

   auto& epoch = *m_read_epochs.back();

   // TODO: implement proper out-of-order handling
   BOTAN_STATE_CHECK(seq_no == epoch.sequence_number);

   epoch.cipher->set_associated_data(header);
   epoch.cipher->start(current_nonce(seq_no, epoch.iv));
   epoch.cipher->finish(fragment);

   epoch.sequence_number++;
#else
   BOTAN_UNUSED(seq_no, header, fragment);
   throw Not_Implemented("DTLS 1.3 is not configured");
#endif
}

#if defined(BOTAN_HAS_DTLS_13)
namespace {

/**
 * Computes the record number mask (RFC 9147 Section 4.2.3) for the
 * given write epoch from a 16-byte ciphertext sample.
 */
std::array<uint8_t, 16> compute_record_number_mask(const Cipher_State::Epoch& epoch,
                                                   const Ciphersuite& ciphersuite,
                                                   std::span<const uint8_t, 16> ct) {
   BOTAN_ASSERT_NOMSG(epoch.sequence_number_key.has_value());

   auto mask = typecast_copy<std::array<uint8_t, 16>>(ct);

   // TODO: it would be helpful to provide a canonical block/stream cipher name
   //       from the Ciphersuite (e.g. "AES-128" or "ChaCha20") or any other way
   //       to avoid string comparisons here.

   if(ciphersuite.to_string() == "CHACHA20_POLY1305_SHA256") {
      auto chacha = StreamCipher::create_or_throw("ChaCha20");

      // RFC 8439 2.3
      //    chacha20_block(key, counter, nonce)
      //
      // RFC 9147 4.2.3
      //    Mask = ChaCha20(sn_key, Ciphertext[0..3], Ciphertext[4..15])

      const uint64_t counter = load_le(ct.first<4>());
      const auto nonce = ct.last<12>();

      chacha->set_key(epoch.sequence_number_key.value());
      chacha->set_iv(nonce);
      chacha->seek(counter * 64);
      chacha->write_keystream(mask);
   } else if(ciphersuite.to_string().starts_with("AES_128")) {
      auto aes = BlockCipher::create_or_throw(fmt("AES-128"));
      aes->set_key(epoch.sequence_number_key.value());
      aes->encrypt(mask);
   } else if(ciphersuite.to_string().starts_with("AES_256")) {
      auto aes = BlockCipher::create_or_throw(fmt("AES-256"));
      aes->set_key(epoch.sequence_number_key.value());
      aes->encrypt(mask);
   } else {
      throw Not_Implemented(
         fmt("Ciphersuite {} is not supported for DTLS 1.3 record number masking", ciphersuite.to_string()));
   }

   return mask;
}

/**
 * Computes the record number mask (RFC 9147 Section 4.2.3) and XORs
 * it with the given sequence number hint to (de)protect it.
 */
SequenceNumberHint xor_record_sequence_number(const Cipher_State::Epoch& epoch,
                                              const Ciphersuite& ciphersuite,
                                              std::span<const uint8_t> ciphertext,
                                              SequenceNumberHint seqno_hint) {
   BOTAN_ARG_CHECK(ciphertext.size() >= 16, "Record payload must be at least 16 bytes in DTLS 1.3");
   const auto mask = compute_record_number_mask(epoch, ciphersuite, ciphertext.first<16>());

   return std::visit(
      [&]<std::unsigned_integral T>(const T seqno) -> SequenceNumberHint {
         // RFC 9147 Section 4.2.3
         //    The encrypted sequence number is computed by XORing the leading
         //    bytes of the mask with the on-the-wire representation of the
         //    sequence number. Decryption is accomplished by the same process.
         return static_cast<T>(seqno ^ load_be(std::span{mask}.first<sizeof(T)>()));
      },
      seqno_hint);
}

}  // namespace

#endif

std::optional<Record_Content> Cipher_State::deprotect_record(ProtectedRecord_DTLS record,
                                                             size_t incoming_record_size_limit) {
   BOTAN_ASSERT_NOMSG(m_tls_flavor == TLS_Flavor::DTLS);
   BOTAN_STATE_CHECK(current_read_epoch_number() > Epoch_Number::Unprotected);

   // RFC 9147 4.2.2
   //    When receiving protected DTLS records, the recipient does not have a
   //    full epoch or sequence number value in the record and so there is some
   //    opportunity for ambiguity. Because the full sequence number is used to
   //    compute the per-record nonce and the epoch determines the keys, failure
   //    to reconstruct these values leads to failure to deprotect the record.
   auto epoch = latest_epoch_matching_epoch_hint(record.header.epoch_bits);
   if(!epoch.has_value()) {
      return std::nullopt;  // without a matching epoch, we cannot deprotect the record
   }

   record.header.sequence_number =
      xor_record_sequence_number(epoch->get(), *m_ciphersuite, record.payload, record.header.sequence_number);

   // RFC 9147 4.2.2
   //    [I]mplementations SHOULD reconstruct the sequence number by computing
   //    the full sequence number which is numerically closest to one plus the
   //    sequence number of the highest successfully deprotected record in the
   //    current epoch.
   const uint64_t sequence_number =
      reconstruct_full_sequence_number(epoch->get().sequence_number, record.header.sequence_number);

   auto result = Record_Content{
      .type = Record_Type::Invalid,
      .sequence_number = sequence_number,
      .payload = std::move(record.payload),
      .epoch = epoch->get().number,
   };

   BOTAN_ASSERT_NOMSG(result.payload.size() <= MAX_CIPHERTEXT_SIZE_TLS13);

   try {
      epoch->get().cipher->set_associated_data(record.header.serialize());
      epoch->get().cipher->start(current_nonce(result.sequence_number.value(), epoch->get().iv));
      epoch->get().cipher->finish(result.payload);
   } catch(const Invalid_Authentication_Tag&) {
      // RFC 9147 Section 4.5.2
      //    Unlike TLS, DTLS is resilient in the face of invalid records
      //    (e.g., invalid formatting, length, MAC, etc.). In general,
      //    invalid records SHOULD be silently discarded, thus preserving the
      //    association [...].
      //
      // If deprotection fails (i.e. MAC verification does not check out), we
      // silently reject the record.
      return std::nullopt;
   }

   BOTAN_ASSERT_NOMSG(result.payload.size() <= MAX_PLAINTEXT_SIZE + 1 /* content_type byte */);

   // --------------------------------------------------------------------------
   // BEYOND THIS LINE WE DEAL WITH AUTHENTICATED DATA.
   // Hence, errors are fatal and we throw TLS exceptions with appropriate
   // alerts which will terminate the association.
   // --------------------------------------------------------------------------

   // Update "the sequence number of the highest successfully deprotected record"
   // (RFC 9147 Section 4.2.2) if the current record's sequence number is higher
   // than the previous highest.
   epoch->get().sequence_number = std::max(epoch->get().sequence_number, result.sequence_number.value());

   // RFC 8449 Section 4
   //    a DTLS endpoint that receives a record larger than its advertised
   //    limit MAY either generate a fatal "record_overflow" alert or
   //    discard the record.
   //
   // We choose to generate a fatal alert, given that this error is detected
   // after decryption only. Records that are extensively too large are
   // discarded in read_datagram already.
   if(result.payload.size() > incoming_record_size_limit) {
      throw TLS_Exception(Alert::RecordOverflow, "Received an encrypted record that exceeds maximum plaintext size");
   }

   // Remove record padding (RFC 8446 5.4). The TLSInnerPlaintext layout is
   //   content || content_type || zero_padding
   auto seen_nonzero = CT::Mask<uint8_t>::cleared();
   uint8_t content_type_byte = 0;
   size_t content_index = 0;
   for(size_t i = result.payload.size(); i-- > 0;) {
      const uint8_t b = result.payload[i];
      const auto byte_is_nonzero = CT::Mask<uint8_t>::expand(b);
      // Set on the first non-zero byte we encounter scanning right-to-left.
      const auto first_nonzero = byte_is_nonzero & ~seen_nonzero;
      content_type_byte = first_nonzero.select(b, content_type_byte);
      content_index = CT::Mask<size_t>::expand(first_nonzero.value()).select(i, content_index);
      seen_nonzero |= byte_is_nonzero;
   }

   if(!seen_nonzero.as_bool()) {
      // RFC 8446 5.4
      //   If a receiving implementation does not
      //   find a non-zero octet in the cleartext, it MUST terminate the
      //   connection with an "unexpected_message" alert.
      throw TLS_Exception(Alert::UnexpectedMessage, "No content type found in encrypted record");
   }

   result.type = static_cast<Record_Type>(content_type_byte);

   // Truncate to drop the content_type byte and padding. resize() on a
   // vector of trivially-destructible elements is bookkeeping-only and
   // does not allocate or iterate over the dropped suffix.
   result.payload.resize(content_index);

   // RFC 9147 Section 4.1 Figure 5
   //    [...]
   //
   // After deprotection, the record type must be Alert (21), DTLSHandshake (22),
   // Application Data (23), Heartbeat (24), or ACK (26). Any other type should
   // result in an error and RFC 9846 Section 5 should be enforced:
   //
   // RFC 9846 Section 5
   //    If a TLS implementation receives an unexpected record type, it MUST
   //    terminate the connection with an "unexpected_message" alert.
   if(result.type != Record_Type::Alert &&            //
      result.type != Record_Type::Handshake &&        //
      result.type != Record_Type::ApplicationData &&  //
      result.type != Record_Type::Heartbeat &&        //
      result.type != Record_Type::ACK) {
      throw TLS_Exception(
         Alert::UnexpectedMessage,
         fmt("Deprotected DTLS record had unexpected content type: {}", static_cast<uint32_t>(result.type)));
   }

   return result;
}

MarshalledRecord Cipher_State::protect_record_dtls(Record_Type type,
                                                   std::span<const uint8_t> payload,
                                                   size_t padding_bytes,
                                                   std::optional<Epoch_Number> epoch_number) {
   BOTAN_ASSERT_NOMSG(m_tls_flavor == TLS_Flavor::DTLS);
   BOTAN_ARG_CHECK(!epoch_number.has_value() || *epoch_number > Epoch_Number::Unprotected,
                   "epoch_number must implicate record protection");

   auto& epoch = [&]() -> Epoch& {
      if(!epoch_number.has_value()) {
         BOTAN_STATE_CHECK(current_write_epoch_number() > Epoch_Number::Unprotected);
         return *m_write_epochs.back();
      } else {
         const auto eitr = std::find_if(m_write_epochs.rbegin(), m_write_epochs.rend(), [&](const auto& write_epoch) {
            return write_epoch->number == *epoch_number;
         });

         if(eitr == m_write_epochs.rend()) {
            throw TLS_Exception(Alert::InternalError, "No write epoch found for requested epoch number");
         }

         return *(*eitr);
      }
   }();

   // RFC 8446 5.2
   //    type:  The TLSPlaintext.type value containing the content type of the record.
   constexpr size_t content_type_tag_length = 1;

   // 1. Figure out how many encrypted bytes we will produce
   // RFC 9147 Figure 2 DTLSInnerPlaintext = content | type | zeros

   size_t plaintext_size = 0;
   size_t ciphertext_size = 0;

   // TODO: re-visit this with a clearer mind on another day
   while(true) {
      plaintext_size = payload.size() + content_type_tag_length + padding_bytes;
      ciphertext_size = encrypt_output_length(plaintext_size);

      // RFC 9147 Section 4.2.3
      //      Senders MUST pad short plaintexts out (using the conventional
      //      record padding mechanism) in order to make a suitable-length
      //      ciphertext. Note that most of the DTLS AEAD algorithms have a 16
      //      byte authentication tag and need no padding. However, some
      //      algorithms, such as TLS_AES_128_CCM_8_SHA256, have a shorter
      //      authentication tag and may require padding for short inputs.
      if(ciphertext_size >= 16) {
         break;
      } else {
         padding_bytes += 1;  // Increase padding until ciphertext is at least 16 bytes
      }
   }

   // 2. Set up *pre-encryption* unified_hdr, which serves as
   //    Associated Data (AD).

   const auto write_seq_no = epoch.sequence_number++;
   const auto ct_len = checked_cast_to<uint16_t>(ciphertext_size);
   auto unified_header = UnifiedHeader_DTLS{
      .epoch_bits = static_cast<uint8_t>(to_underlying(epoch.number) & 0b00000011),
      .connection_id = std::nullopt,                           // TODO: support CID
      .sequence_number = static_cast<uint16_t>(write_seq_no),  // TODO: support 16 and 8 bit seq_no
      .length = ct_len,                                        // TODO: support length field omission
   };

   const size_t header_size = unified_header.serialized_byte_length();
   const size_t record_size = header_size + ciphertext_size;

   // 3. Set up DTLSInnerPlaintext layout with headers, which is the plaintext
   //    to be encrypted. The layout is DTLSInnerPlaintext = content || type || zeros

   MarshalledRecord result;
   result.reserve(record_size);
   result.resize(header_size);

   result.get().insert(result.end(), payload.begin(), payload.end());  // content
   result.get().push_back(to_underlying(type));                        // type
   result.get().insert(result.end(), padding_bytes, 0x00);             // zeros
   BOTAN_ASSERT_NOMSG(result.size() == header_size + plaintext_size);

   // 4. Encrypt the record.

   epoch.cipher->set_associated_data(unified_header.serialize());
   epoch.cipher->start(current_nonce(write_seq_no, epoch.iv));
   epoch.cipher->finish(result, header_size);

   BOTAN_ASSERT_NOMSG(result.size() == header_size + ciphertext_size);

   // 5. Mask seq bytes (RFC 9147 Section 4.2.3 Record Number Encryption) and
   //    render the header into the output buffer

   unified_header.sequence_number = xor_record_sequence_number(
      epoch, *m_ciphersuite, std::span{result}.subspan(header_size), unified_header.sequence_number);
   unified_header.serialize_to(std::span{result}.first(header_size));

   return result;
}

std::optional<std::reference_wrapper<Cipher_State::Epoch>> Cipher_State::latest_epoch_matching_epoch_hint(
   uint8_t epoch_hint) const {
   BOTAN_ASSERT_NOMSG(m_tls_flavor == TLS_Flavor::DTLS);
   BOTAN_STATE_CHECK(!m_read_epochs.empty());
   BOTAN_DEBUG_ASSERT(epoch_hint <= 0b00000011);

   // RFC 9147 Section 4.2.2
   //    If the epoch bits match those of the current epoch, then
   //    implementations SHOULD [attempt to deprotect the record] in the current
   //    epoch.
   //    [...]
   //    After the handshake is complete, if the epoch bits do not match those
   //    from the current epoch, implementations SHOULD use the most recent past
   //    epoch which has matching bits [...].
   //
   // So we go through our list of available read epochs starting from the
   // newest and select the first one that matches the epoch hint.
   //
   // NOLINTNEXTLINE(modernize-loop-convert): TODO: use std::views::reverse
   for(auto it = m_read_epochs.rbegin(); it != m_read_epochs.rend(); ++it) {
      if((to_underlying((*it)->number) & 0b00000011) == epoch_hint) {
         return **it;
      }
   }

   // No matching epoch found
   return std::nullopt;
}

void Cipher_State::clear_read_keys() {
   m_read_epochs.clear();
}

void Cipher_State::clear_write_keys() {
   m_write_epochs.clear();
}

Epoch_Number Cipher_State::current_write_epoch_number() const {
   return m_write_epochs.empty() ? Epoch_Number::Unprotected : m_write_epochs.back()->number;
}

Epoch_Number Cipher_State::current_read_epoch_number() const {
   return m_read_epochs.empty() ? Epoch_Number::Unprotected : m_read_epochs.back()->number;
}

}  // namespace Botan::TLS
