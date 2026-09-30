/*
* DTLS 1.3 cipher state
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_cipher_state_dtls13.h>

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/mem_ops.h>
#include <botan/stream_cipher.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_utils_dtls13.h>

namespace Botan::TLS {

namespace {

/**
 * Computes the record number mask (RFC 9147 Section 4.2.3) for the
 * given write epoch from a 16-byte ciphertext sample.
 */
std::array<uint8_t, 16> compute_record_number_mask(const DTLS_Cipher_State::Epoch& epoch,
                                                   const Ciphersuite& ciphersuite,
                                                   std::span<const uint8_t, 16> ct) {
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

      chacha->set_key(epoch.sequence_number_key);
      chacha->set_iv(nonce);
      chacha->seek(counter * 64);
      chacha->write_keystream(mask);
   } else if(ciphersuite.to_string().starts_with("AES_128")) {
      auto aes = BlockCipher::create_or_throw(fmt("AES-128"));
      aes->set_key(epoch.sequence_number_key);
      aes->encrypt(mask);
   } else if(ciphersuite.to_string().starts_with("AES_256")) {
      auto aes = BlockCipher::create_or_throw(fmt("AES-256"));
      aes->set_key(epoch.sequence_number_key);
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
SequenceNumberHint xor_record_sequence_number(const DTLS_Cipher_State::Epoch& epoch,
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

DTLS_Cipher_State::DTLS_Cipher_State(Connection_Side side, std::string_view prf_algo) : Cipher_State(side, prf_algo) {}

DTLS_Cipher_State::~DTLS_Cipher_State() = default;

std::pair<MarshalledRecord, RecordNumber> DTLS_Cipher_State::protect_record(Record_Type type,
                                                                            std::span<const uint8_t> payload,
                                                                            size_t padding_bytes,
                                                                            std::optional<Epoch_Number> epoch_number) {
   BOTAN_ASSERT_NOMSG(!m_write_epochs.empty());
   BOTAN_ARG_CHECK(!epoch_number.has_value() || *epoch_number > Epoch_Number::Unprotected,
                   "epoch_number must implicate record protection");

   auto& epoch = [&]() -> Epoch& {
      if(!epoch_number.has_value()) {
         BOTAN_STATE_CHECK(current_write_epoch_number() > Epoch_Number::Unprotected);
         return m_write_epochs.back();
      } else {
         const auto eitr = std::find_if(m_write_epochs.rbegin(), m_write_epochs.rend(), [&](const auto& write_epoch) {
            return write_epoch.number == *epoch_number;
         });

         if(eitr == m_write_epochs.rend()) {
            throw TLS_Exception(Alert::InternalError, "No write epoch found for requested epoch number");
         }

         return *eitr;
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
      epoch, ciphersuite(), std::span{result}.subspan(header_size), unified_header.sequence_number);
   unified_header.serialize_to(std::span{result}.first(header_size));

   return {result, {.epoch = epoch.number, .sequence_number = write_seq_no}};
}

std::optional<Record> DTLS_Cipher_State::deprotect_record(ProtectedRecord_DTLS record,
                                                          size_t incoming_record_size_limit,
                                                          uint64_t current_time_ms) {
   BOTAN_STATE_CHECK(current_read_epoch_number() > Epoch_Number::Unprotected);

   prune_outdated_read_epochs(current_time_ms);

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
      xor_record_sequence_number(epoch->get(), ciphersuite(), record.payload, record.header.sequence_number);

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

   // --------------------------------------------------------------------------
   // BEYOND THIS LINE WE DEAL WITH AUTHENTICATED DATA.
   // Hence, errors are fatal and we throw TLS exceptions with appropriate
   // alerts which will terminate the association.
   // --------------------------------------------------------------------------

   // Update "the sequence number of the highest successfully deprotected record"
   // (RFC 9147 Section 4.2.2) if the current record's sequence number is higher
   // than the previous highest.
   epoch->get().sequence_number = std::max(epoch->get().sequence_number, result.sequence_number.value());

   // RFC 9147 8.
   //    Implementations SHOULD discard records from earlier epochs but MAY
   //    choose to retain keying material from previous epochs [...].
   //
   // Once an epoch was successfully used for deprotection for the first time,
   // all previous epochs can be retired. After some time, these epochs will be
   // discarded (see `prune_outdated_read_epochs()`).
   if(!std::exchange(epoch->get().used_successfully, true)) {
      retire_outdated_read_epochs(current_time_ms);
   }

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

   // RFC 9147 6.1
   //    Epoch value (3) is used for payloads protected using keys derived from
   //    the initial [sender]_application_traffic_secret_0
   //
   // We thus reject application data records received at the handshake epoch.
   if(result.type == Record_Type::ApplicationData && epoch->get().number == Epoch_Number::HandshakeTraffic) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Can't interleave application and handshake data");
   }

   return annotate_record_type(std::move(result));
}

namespace {

Epoch_Number operator+(Epoch_Number current, size_t offset) {
   return static_cast<Epoch_Number>(to_underlying(current) + offset);
}

}  // namespace

DTLS_Cipher_State::Epoch DTLS_Cipher_State::create_dtls_epoch(Epoch_Number epoch_number,
                                                              Cipher_Dir direction,
                                                              const secure_vector<uint8_t>& traffic_secret) {
   auto epoch = DTLS_Cipher_State::Epoch{create_epoch(epoch_number, direction, traffic_secret)};
   epoch.sequence_number_key = hkdf_expand_label(traffic_secret, "sn", {}, epoch.cipher->minimum_keylength());
   return epoch;
}

std::array<uint8_t, 6> DTLS_Cipher_State::expansion_label_prefix() const {
   // RFC 9147 5.9
   //    Section 7.1 of [TLS13] specifies that HKDF-Expand-Label uses a label
   //    prefix of "tls13 ". For DTLS 1.3, that label SHALL be "dtls13". This
   //    ensures key separation between DTLS 1.3 and TLS 1.3. Note that there is
   //    no trailing space [...].
   return {'d', 't', 'l', 's', '1', '3'};
}

void DTLS_Cipher_State::advance_write_epoch(const secure_vector<uint8_t>& traffic_secret,
                                            std::optional<Epoch_Number> epoch_number) {
   const auto next_epoch_number = epoch_number.value_or(current_write_epoch_number() + 1);
   m_write_epochs.push_back(create_dtls_epoch(next_epoch_number, Cipher_Dir::Encryption, traffic_secret));

   // TODO: How many epochs should we keep around for DTLS?
   const size_t epochs_to_keep = 2;
   BOTAN_ASSERT_NOMSG(m_write_epochs.size() <= epochs_to_keep + 1);
   if(m_write_epochs.size() > epochs_to_keep) {
      m_write_epochs.erase(m_write_epochs.begin());
   }
}

void DTLS_Cipher_State::advance_read_epoch(const secure_vector<uint8_t>& traffic_secret,
                                           std::optional<Epoch_Number> epoch_number) {
   const auto next_epoch_number = epoch_number.value_or(current_read_epoch_number() + 1);
   m_read_epochs.push_back(create_dtls_epoch(next_epoch_number, Cipher_Dir::Decryption, traffic_secret));

   // TODO: How many epochs should we keep around for DTLS?
   const size_t epochs_to_keep = 2;
   BOTAN_ASSERT_NOMSG(m_read_epochs.size() <= epochs_to_keep + 1);
   if(m_read_epochs.size() > epochs_to_keep) {
      m_read_epochs.erase(m_read_epochs.begin());
   }
}

void DTLS_Cipher_State::clear_write_keys() {
   m_write_epochs.clear();
}

void DTLS_Cipher_State::clear_read_keys() {
   m_read_epochs.clear();
}

std::optional<std::reference_wrapper<DTLS_Cipher_State::Epoch>> DTLS_Cipher_State::latest_epoch_matching_epoch_hint(
   uint8_t epoch_hint) {
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
      if((to_underlying(it->number) & 0b00000011) == epoch_hint) {
         return *it;
      }
   }

   // No matching epoch found
   return std::nullopt;
}

void DTLS_Cipher_State::retire_outdated_read_epochs(uint64_t current_time_ms) {
   // RFC 9147 Section 4.2.1
   //    Implementations [...] MAY choose to retain keying material from
   //    previous epochs for up to the default MSL specified for TCP [RFC0793]
   //    to allow for packet reordering.
   //
   // RFC 9293 4.
   //    MSL: Maximum Segment Lifetime, the time a TCP segment can exist in the
   //         internetwork system. Arbitrarily defined to be 2 minutes.
   constexpr uint64_t expiration_time = 2 * 60 * 1000;

   if(m_read_epochs.empty() || !m_read_epochs.back().used_successfully) {
      return;
   }

   for(auto it = m_read_epochs.begin(); it != std::prev(m_read_epochs.end()); ++it) {
      auto& epoch = *it;
      if(!epoch.expiration_timestamp.has_value()) {
         epoch.expiration_timestamp = current_time_ms + expiration_time;
      }
   }
}

void DTLS_Cipher_State::prune_outdated_read_epochs(uint64_t current_time_ms) {
   for(auto it = m_read_epochs.begin(); it != std::prev(m_read_epochs.end());) {
      auto& epoch = *it;
      if(epoch.expiration_timestamp.has_value() && current_time_ms >= *epoch.expiration_timestamp) {
         it = m_read_epochs.erase(it);
      } else {
         ++it;
      }
   }
}

void DTLS_Cipher_State::prune_outdated_write_epochs() {
   if(m_write_epochs.empty()) {
      return;
   }

   // Clear all but the last entry in the m_write_epochs list
   m_write_epochs.erase(m_write_epochs.begin(), std::prev(m_write_epochs.end()));
}

}  // namespace Botan::TLS
