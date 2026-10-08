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

// RFC 9147 5.9
//    Section 7.1 of [TLS13] specifies that HKDF-Expand-Label uses a label
//    prefix of "tls13 ". For DTLS 1.3, that label SHALL be "dtls13". This
//    ensures key separation between DTLS 1.3 and TLS 1.3. Note that there is
//    no trailing space [...].
constexpr Cipher_State::ExpansionLabelPrefix dtls_expansion_label_prefix{'d', 't', 'l', 's', '1', '3'};

}  // namespace

DTLS_Cipher_State::DTLS_Cipher_State(Connection_Side side, std::string_view prf_algo) :
      Cipher_State(side, prf_algo, dtls_expansion_label_prefix) {}

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

   // 1. Figure out how many encrypted bytes we will produce
   // RFC 9147 Figure 2 DTLSInnerPlaintext = content | type | zeros

   const size_t ciphertext_size = [&] {
      while(true) {
         const auto ciphertext_size = protected_record_length(epoch, payload.size(), padding_bytes);

         // RFC 9147 Section 4.2.3
         //      Senders MUST pad short plaintexts out (using the conventional
         //      record padding mechanism) in order to make a suitable-length
         //      ciphertext. Note that most of the DTLS AEAD algorithms have a 16
         //      byte authentication tag and need no padding. However, some
         //      algorithms, such as TLS_AES_128_CCM_8_SHA256, have a shorter
         //      authentication tag and may require padding for short inputs.
         if(ciphertext_size >= 16) {
            return ciphertext_size;
         } else {
            padding_bytes += 1;  // Increase padding until ciphertext is at least 16 bytes
         }
      }
   }();

   // 2. Set up *pre-encryption* unified_hdr, which serves as
   //    Associated Data (AD).

   auto unified_header = UnifiedHeader_DTLS{
      .epoch_bits = static_cast<uint8_t>(to_underlying(epoch.number) & 0b00000011),
      .connection_id = std::nullopt,                                    // TODO: support CID
      .sequence_number = static_cast<uint16_t>(epoch.sequence_number),  // TODO: support 16 and 8 bit seq_no
      .length = checked_cast_to<uint16_t>(ciphertext_size),             // TODO: support length field omission
   };

   // 3. Marshall and protect the record

   auto result = marshall_and_protect(epoch, unified_header.serialize(), payload, type, padding_bytes);

   // 4. Mask seq bytes (RFC 9147 Section 4.2.3 Record Number Encryption) and
   //    render the header into the output buffer

   const size_t header_size = unified_header.serialized_byte_length();
   unified_header.sequence_number = xor_record_sequence_number(
      epoch, ciphersuite(), std::span{result}.subspan(header_size), unified_header.sequence_number);
   unified_header.serialize_to(std::span{result}.first(header_size));

   return std::make_pair(std::move(result),
                         RecordNumber{
                            .epoch = epoch.number,
                            .sequence_number = epoch.sequence_number++,
                         });
}

std::optional<Record> DTLS_Cipher_State::deprotect_record(ProtectedRecord_DTLS record,
                                                          size_t incoming_record_size_limit) {
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

   try {
      deprotect_and_hydrate_content_type(epoch->get(), record.header.serialize(), result, incoming_record_size_limit);
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
   auto base_epoch = create_epoch(epoch_number, direction, traffic_secret);
   auto seqno_key = hkdf_expand_label(traffic_secret, "sn", {}, base_epoch.cipher->minimum_keylength());
   return {
      std::move(base_epoch),
      std::move(seqno_key),
   };
}

Epoch_Number DTLS_Cipher_State::advance_write_epoch(const secure_vector<uint8_t>& traffic_secret,
                                                    std::optional<Epoch_Number> epoch_number) {
   const auto next_epoch_number = epoch_number.value_or(current_write_epoch_number() + 1);
   m_write_epochs.push_back(create_dtls_epoch(next_epoch_number, Cipher_Dir::Encryption, traffic_secret));
   return next_epoch_number;
}

Epoch_Number DTLS_Cipher_State::advance_read_epoch(const secure_vector<uint8_t>& traffic_secret,
                                                   std::optional<Epoch_Number> epoch_number) {
   const auto next_epoch_number = epoch_number.value_or(current_read_epoch_number() + 1);
   m_read_epochs.push_back(create_dtls_epoch(next_epoch_number, Cipher_Dir::Decryption, traffic_secret));
   return next_epoch_number;
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

void DTLS_Cipher_State::prune_write_epochs_older_than(Epoch_Number epoch_number) {
   std::erase_if(m_write_epochs, [&](const auto& epoch) { return epoch.number < epoch_number; });
}

void DTLS_Cipher_State::prune_read_epochs_older_than(Epoch_Number epoch_number) {
   std::erase_if(m_read_epochs, [&](const auto& epoch) { return epoch.number < epoch_number; });
}

}  // namespace Botan::TLS
