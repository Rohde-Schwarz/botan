/*
* DTLS record layer implementation for DTLS 1.3
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_record_layer_dtls13.h>

#include <algorithm>
#include <iostream>  // TODO: remove
#include <utility>

#include <botan/assert.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_version.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_cipher_state.h>

namespace Botan::TLS {

namespace {

PlaintextRecord_DTLS read_plaintext_record(BufferSlicer& bs) {
   if(bs.remaining() < DTLS_HEADER_SIZE) {
      throw TLS_Exception(AlertType::DecodeError, "Received DTLSPlaintext with truncated header");
   }

   auto header = PlaintextHeader_DTLS::parse(bs.take<DTLS_HEADER_SIZE>());
   if(bs.remaining() < header.length) {
      throw TLS_Exception(AlertType::IllegalParameter, "Received DTLSPlaintext with truncated payload");
   }

   return {
      .header = header,
      .payload = bs.copy_as_secure_vector(header.length),
   };
}

ProtectedRecord_DTLS read_protected_record(BufferSlicer& bs, size_t incoming_record_size_limit) {
   auto unified_header = UnifiedHeader_DTLS::parse(bs.peek(bs.remaining()), std::nullopt /* CID NYI */);
   bs.skip(unified_header.serialized_byte_length());

   // RFC 9147 Section 4.3
   //    The length field from DTLS records containing that field can be
   //    used to determine the boundaries between records. The final
   //    record in a datagram can omit the length field.
   //
   // RFC 9147 Section 4.
   //    The length field MAY be omitted [...], which means that the
   //    record consumes the entire rest of the datagram in the lower
   //    level transport.
   const auto fragment_length = unified_header.length.value_or(checked_cast_to<uint16_t>(bs.remaining()));

   // RFC 9147 Section 4.2.3
   //    This procedure requires the ciphertext length to be at least 16 bytes.
   //    Receivers MUST reject shorter records as if they had failed deprotection,
   //    as described in Section 4.5.2.
   if(fragment_length < 16) {
      throw TLS_Exception(Alert::DecodeError, "Received an encrypted record that is too short");
   }

   // RFC 8449 Section 4
   //    a DTLS endpoint that receives a record larger than its advertised
   //    limit MAY either generate a fatal "record_overflow" alert or
   //    discard the record.
   //
   // We reject records that would exceed the maximum allowed size after
   // deprotection for sure (the AEAD can only add up to 255 bytes).
   if(fragment_length + unified_header.serialized_byte_length() >
      incoming_record_size_limit + MAX_AEAD_EXPANSION_SIZE_TLS13) {
      throw TLS_Exception(Alert::RecordOverflow, "Received a datagram that exceeds maximum size");
   }

   return {
      .header = std::move(unified_header),
      .payload = bs.copy_as_secure_vector(fragment_length),
   };
}

}  // namespace

DTLS_Record_Layer::DTLS_Record_Layer(Connection_Side side, std::shared_ptr<const Policy> policy) :
      Record_Layer(side, std::move(policy), false, true) {}

bool DTLS_Record_Layer::copy_data(std::span<const uint8_t> data_from_peer) {
   try {
      return read_datagram(data_from_peer);
   } catch(const std::exception& ex) {
      std::cout << "ERROR: " << ex.what() << std::endl;

      // RFC 9147 Section 4.5.2
      //    Unlike TLS, DTLS is resilient in the face of invalid records
      //    (e.g., invalid formatting, length, MAC, etc.). In general,
      //    invalid records SHOULD be silently discarded, thus preserving the
      //    association [...].
      //
      // In this implementation, every throw in `read_datagram` stems from
      // operations on data_from_peer, which is *unauthenticated*. Therefore,
      // every exception here results in the silent rejection of the incoming
      // datagram.
      //
      // Exceptions on authenticated plaintexts (i.e. _after_ successful
      // deprotection by the AEAD) result in an error/alert and typically
      // the termination of the DTLS association. See `next_record` and
      // `deprotect_record`.
      BOTAN_UNUSED(ex);
   }

   return false;
}

bool DTLS_Record_Layer::read_datagram(std::span<const uint8_t> datagram) {
   BufferSlicer bs(datagram);
   std::vector<IncomingRecord> records_in_this_datagram;

   // RFC 9147 Section 4.3
   //    Multiple DTLS records MAY be placed in a single datagram. Records are
   //    encoded consecutively. [...] The first byte of the datagram payload
   //    MUST be the beginning of a record. Records MUST NOT span datagrams.
   while(!bs.empty()) {
      // RFC 9147 Section 4.1
      //     Implementations can demultiplex DTLS 1.3 records by examining the
      //     first byte as follows: [...]
      const auto outer_record_type = [&] {
         const auto type_byte = bs.peek_byte();
         const auto record_type = static_cast<Record_Type>(type_byte);

         // RFC 9147 Section 4.1 (cont'd)
         // - If the first byte is alert(21), handshake(22), or ack(26), the
         //   record MUST be interpreted as a DTLSPlaintext record.
         if(record_type == Record_Type::Alert ||      //
            record_type == Record_Type::Handshake ||  //
            record_type == Record_Type::ACK) {
            return record_type;
         }

         // RFC 9147 Section 4.1 (cont'd)
         // - If the first byte is any other value, then receivers MUST check to
         //   see if the leading bits of the first byte are 001. If so, the
         //   implementation MUST process the record as DTLSCiphertext; [...].
         if((type_byte & 0b11100000) == 0b00100000) {
            return Record_Type::ApplicationData;
         }

         // RFC 9147 Section 4.1 (cont'd)
         // - Otherwise, the record MUST be rejected as if it had failed
         //   deprotection, [...].
         throw TLS_Exception(Alert::UnexpectedMessage,
                             fmt("DTLS record type had unexpected value: {}", static_cast<uint32_t>(type_byte)));
      }();

      // RFC 9147 Section 4.1
      //    If the [...] bits of the first byte are 001 [...] the implementation
      //    MUST process the record as DTLSCiphertext; the true content type
      //    will be inside the protected portion.
      if(outer_record_type == Record_Type::ApplicationData) {
         records_in_this_datagram.push_back(read_protected_record(bs, incoming_record_size_limit()));
      } else {
         auto pt_record = read_plaintext_record(bs);

         // RFC 9147 Section 4.
         //    legacy_record_version: This value MUST be set to {254, 253} for all
         //    records other than the initial ClientHello (i.e., one not generated
         //    after a HelloRetryRequest), where it may also be {254, 255} for
         //    compatibility purposes.
         //
         // TODO: Does it really make sense to make this rely on m_receiving_compat_mode of TLS?
         if(pt_record.header.legacy_version != Protocol_Version::DTLS_V12 &&
            (pt_record.header.legacy_version != Protocol_Version::DTLS_V10 || !receiving_compat_mode())) {
            throw TLS_Exception(Alert::IllegalParameter, "Received unexpected record version");
         }

         records_in_this_datagram.push_back(std::move(pt_record));
      }
   }

   BOTAN_DEBUG_ASSERT(bs.empty());

   // Only commit the records found in the passed-in datagram once the entire
   // datagram has been successfully processed. This way, records from a
   // datagram that is later found to be invalid (e.g., due to a bad MAC) will
   // not be added to the read buffer.
   m_incoming_records.insert(m_incoming_records.end(),
                             std::make_move_iterator(records_in_this_datagram.begin()),
                             std::make_move_iterator(records_in_this_datagram.end()));

   return true;
}

DTLS_Record_Layer::IncomingRecord DTLS_Record_Layer::next_incoming_record() {
   BOTAN_STATE_CHECK(!m_incoming_records.empty());

   auto next_record = std::move(m_incoming_records.front());
   m_incoming_records.erase(m_incoming_records.begin());
   return next_record;
}

Replay_Window_13& DTLS_Record_Layer::replay_window_for_epoch(Epoch_Number epoch) {
   auto it = m_replay_windows.find(epoch);
   if(it == m_replay_windows.end()) {
      it = m_replay_windows.emplace(epoch, Replay_Window_13()).first;
   }
   return it->second;
}

Record_Layer::ReadResult<Record_Content> DTLS_Record_Layer::next_record(Cipher_State* cipher_state) {
   while(!m_incoming_records.empty()) {
      auto maybe_next_record =
         std::visit(overloaded{
                       [&](PlaintextRecord_DTLS record) -> std::optional<Record_Content> {
                          return Record_Content{
                             .type = record.header.type,
                             .sequence_number = record.header.sequence_number,
                             .payload = std::move(record.payload),
                             .epoch = Epoch_Number::Unprotected,  // ossified (RFC 9147 Section 4 Figure 2)
                          };
                       },
                       [&](ProtectedRecord_DTLS record) -> std::optional<Record_Content> {
                          return cipher_state->deprotect_record(std::move(record), incoming_record_size_limit());
                       },
                    },
                    next_incoming_record());

      if(maybe_next_record.has_value()) {
         BOTAN_DEBUG_ASSERT(maybe_next_record->epoch.has_value() && maybe_next_record->sequence_number.has_value());

         // RFC 9147 Section 4.5.1
         //    For each received record, the receiver MUST verify that the
         //    record contains a sequence number that does not duplicate the
         //    sequence number of any other record received in that epoch during
         //    the lifetime of the association. This check SHOULD happen after
         //    deprotecting the record; otherwise, the record discard might
         //    itself serve as a timing channel for the record number.
         auto& window = replay_window_for_epoch(maybe_next_record->epoch.value());
         if(window.accept(maybe_next_record->sequence_number.value())) {
            // RFC 9147 Section 7.
            //    The ACK message is used by an endpoint to indicate which
            //    handshake records it has received and processed from the
            //    other side.
            //
            // Records that don't carry handshake messages (most notably
            // application data) are never acknowledged.
            if(maybe_next_record->type == Record_Type::Handshake) {
               m_record_numbers_to_ack.emplace_back(maybe_next_record->epoch.value(),
                                                    maybe_next_record->sequence_number.value());

               // RFC 9147 Section 7.1
               //    If space is limited, implementations SHOULD favor including
               //    records which have not yet been acknowledged.
               //
               // Hence, we retain only the most recently received record numbers.
               if(m_record_numbers_to_ack.size() > policy().dtls_maximum_queued_acknowledgements()) {
                  m_record_numbers_to_ack.erase(m_record_numbers_to_ack.begin());
               }
            }

            return std::move(maybe_next_record).value();
         }
      }
   }

   return BytesNeeded(0);
}

std::pair<MarshalledRecord, RecordNumber> DTLS_Record_Layer::prepare_record(Record_Type type,
                                                                            std::span<const uint8_t> fragment,
                                                                            Cipher_State* cipher_state,
                                                                            std::optional<Epoch_Number> epoch) const {
   // RFC 8446 5.1
   //    The length MUST NOT exceed 2^14 bytes.
   BOTAN_ARG_CHECK(fragment.size() <= MAX_PLAINTEXT_SIZE, "length must not exceed 2^14 bytes");
   BOTAN_ARG_CHECK(type != Record_Type::ChangeCipherSpec, "DTLS 1.3 does not use ChangeCipherSpec");

   // If the user provided a specific epoch, we protect (or not) based on that
   // wish. Otherwise (the default), we protect if a cipher_state is provided.
   const bool protect = epoch.has_value() ? *epoch > Epoch_Number::Unprotected  //
                                          : cipher_state != nullptr;

   // TODO: Could also use BOTAN_ASSERT_IMPLICATION
   BOTAN_ARG_CHECK(protect || type != Record_Type::ApplicationData,
                   "Application Data records MUST NOT be written to the wire unprotected");
   BOTAN_ARG_CHECK(!fragment.empty() || type == Record_Type::ApplicationData,
                   "zero-length fragments of types other than application data are not allowed");

   // TODO: Check that the record we create will not exceed MTU

   if(!protect) {
      // RFC 9147 Section 4 (3.)
      //    The sequence number is set to be the low order 48 bits of the 64 bit
      //    sequence number. Plaintext records MUST NOT be sent with sequence
      //    numbers that would exceed 2^48-1, so the upper 16 bits will always be 0.
      BOTAN_ASSERT_NOMSG(m_unprotected_write_seq_no < (uint64_t(1) << 48) - 1);

      // Currently, the Record_Layer handles sequence numbers for unprotected
      // records. For protected records this is handled by the Cipher_State, which
      // feels somewhat inconsistent.
      //
      // TODO: evaluate if we find a better way to handle the sequence numbers.
      const auto write_seq_no = m_unprotected_write_seq_no++;

      const auto header = PlaintextHeader_DTLS{
         .type = type,
         .legacy_version = Protocol_Version::DTLS_V12,  // TODO: perhaps use V10 for first message (compatibility)
         // .epoch = Epoch_Number::Unprotected, // ossified (RFC 9147 Section 4 Figure 2)
         .sequence_number = write_seq_no,
         .length = static_cast<uint16_t>(fragment.size()),
      };

      return {concat<MarshalledRecord>(header.serialize(), fragment),
              {.epoch = Epoch_Number::Unprotected, .sequence_number = write_seq_no}};
   } else {
      BOTAN_ARG_CHECK(cipher_state != nullptr, "cipher_state must be provided for protected records");
      BOTAN_DEBUG_ASSERT(!epoch.has_value() || *epoch > Epoch_Number::Unprotected);

      // RFC 8446 5.2
      //    type:  The TLSPlaintext.type value containing the content type of the record.
      constexpr size_t content_type_tag_length = 1;

      const size_t pt_size_with_type_tag = fragment.size() + content_type_tag_length;
      const size_t max_record_size = outgoing_record_size_limit();

      // Don't even bother consulting the policy if we already filled the
      // record fully, because then we can't add any padding anyway.
      // If the user requests more padding than we can actually add, we will
      // truncate the padding to fill up the record entirely.
      //
      // TODO: This is very similar to TLS, consider extracting it.
      const size_t padding_length =
         (pt_size_with_type_tag < max_record_size)
            ? std::min(policy().record_padding_bytes(pt_size_with_type_tag), max_record_size - pt_size_with_type_tag)
            : 0;
      BOTAN_ASSERT_NOMSG(pt_size_with_type_tag + padding_length <= max_record_size);

      return cipher_state->protect_record_dtls(type, fragment, padding_length, epoch);
   }
}

std::vector<MarshalledRecord> DTLS_Record_Layer::prepare_records(Record_Type type,
                                                                 std::span<const uint8_t> fragment,
                                                                 Cipher_State* cipher_state) const {
   return {prepare_record(type, fragment, cipher_state).first};
}

std::vector<MarshalledRecord> DTLS_Record_Layer::prepare_records(const PreparedHandshakeMessageFlight& flight,
                                                                 Cipher_State* cipher_state) const {
   const auto* fragments = std::get_if<std::vector<MarshalledHandshakeMessageFragment>>(&flight);
   BOTAN_ARG_CHECK(fragments != nullptr, "Flight must be a vector of MarshalledHandshakeMessageFragment");

   std::vector<MarshalledRecord> prepared_records;
   prepared_records.reserve(fragments->size());

   // For DTLS we assume that the Handshake_Layer fragmented the flight of
   // marshalled handshake messages so that each fragment fits into a single
   // DTLS record. Therefore, we simply prepare a record for each fragment.
   for(const auto& fragment : *fragments) {
      auto [marshalled_record, record_number] = prepare_record(Record_Type::Handshake, fragment, cipher_state);
      m_unacked_outgoing_handshake_records.push_back({
         .record_numbers = {record_number},
         .fragment = fragment,
      });

      prepared_records.emplace_back(std::move(marshalled_record));
   }
   return prepared_records;
}

std::vector<MarshalledRecord> DTLS_Record_Layer::prepare_unacknowledged_records(Cipher_State* cipher_state) const {
   std::vector<MarshalledRecord> prepared_records;
   prepared_records.reserve(m_unacked_outgoing_handshake_records.size());

   for(auto& record_info : m_unacked_outgoing_handshake_records) {
      auto [marshalled_record, retransmission_record_number] = prepare_record(
         Record_Type::Handshake, record_info.fragment, cipher_state, record_info.record_numbers.back().epoch);
      record_info.record_numbers.push_back(retransmission_record_number);
      prepared_records.push_back(std::move(marshalled_record));
   }

   return prepared_records;
}

uint16_t DTLS_Record_Layer::record_payload_size_limit(const Policy& policy, Cipher_State* cipher_state) const {
   const auto mtu = policy.dtls_default_mtu();
   const bool protect = (cipher_state != nullptr);

   const auto overhead = [&]() -> size_t {
      if(!protect) {
         return DTLS_HEADER_SIZE;
      } else {
         constexpr size_t content_type_length = 1;
         // This assumes no padding is needed for the cipher, so for CCM we lose a
         // few bytes of the maximum possible size limit.
         const size_t tag_length = cipher_state->encrypt_output_length(0);
         return UnifiedHeader_DTLS::expected_length(policy, std::nullopt /* TODO: support CID */) +
                content_type_length + tag_length;
      }
   }();

   // Cap the record payload at the specified hard limit if the user-provided MTU
   // is exorbitantly large.
   return static_cast<uint16_t>(std::min<size_t>(MAX_PLAINTEXT_SIZE, mtu - overhead));
}

void DTLS_Record_Layer::clear_read_buffer() {
   m_incoming_records.clear();
}

ACKs DTLS_Record_Layer::acknowledgements() const {
   return ACKs(m_record_numbers_to_ack);
}

bool DTLS_Record_Layer::handle_acknowledgements(const ACKs& acks) {
   std::erase_if(m_unacked_outgoing_handshake_records, [&](const auto& record_info) {
      return std::any_of(
         acks.record_numbers().begin(), acks.record_numbers().end(), [&](const auto& acked_record_number) {
            return value_exists(record_info.record_numbers, acked_record_number);
         });
   });
   return m_unacked_outgoing_handshake_records.empty();
}

void DTLS_Record_Layer::clear_resend_buffer() {
   m_unacked_outgoing_handshake_records.clear();
}

void DTLS_Record_Layer::clear_outstanding_acknowledgements() {
   m_record_numbers_to_ack.clear();
}

}  // namespace Botan::TLS
