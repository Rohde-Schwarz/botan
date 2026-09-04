/*
* DTLS record structures of DTLS 1.3
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_record_dtls13.h>

#include <botan/tls_exceptn.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>

namespace Botan::TLS {

namespace {

constexpr uint64_t load_be48(std::span<const uint8_t, 6> bytes) {
   std::array<uint8_t, 8> padded_bytes{};
   copy_mem(std::span{padded_bytes}.last<6>(), bytes);
   return load_be(padded_bytes);
}

constexpr std::array<uint8_t, 6> store_be48(const uint64_t value) {
   const auto padded_bytes = store_be(value);
   BOTAN_ARG_CHECK(padded_bytes[0] == 0 && padded_bytes[1] == 0, "Value too large to store in 48 bits");

   std::array<uint8_t, 6> bytes{};
   copy_mem(bytes, std::span{padded_bytes}.last<6>());
   return bytes;
}

}  // namespace

UnifiedHeader_DTLS UnifiedHeader_DTLS::parse(BufferSlicer& bs, std::optional<size_t> cid_length) {
   if(bs.empty()) {
      throw TLS_Exception(AlertType::DecodeError, "DTLS unified header cannot be empty");
   }

   // RFC 9147 Section 4.
   //    The three high bits of the first byte of the unified header are set to
   //    001. [...]
   const uint8_t first = bs.take_byte();
   if((first & 0b11100000) != 0b00100000) {
      throw TLS_Exception(AlertType::DecodeError, "DTLS unified header must start with 0b001xxxxx");
   }

   UnifiedHeader_DTLS header;

   // RFC 9147 Section 4 Figure 3
   //
   //        0 1 2 3 4 5 6 7
   //       +-+-+-+-+-+-+-+-+
   //       |0|0|1|C|S|L|E E|
   //       +-+-+-+-+-+-+-+-+
   //
   //     C: The C bit (0x10) is set if the Connection ID is present.
   //     S: The S bit (0x08) indicates the size of the sequence number.
   //        0 means an 8-bit sequence number, 1 means 16-bit. [...]
   //     L: The L bit (0x04) is set if the length is present.
   //     E: The two low bits (0x03) include the low-order two bits of
   //        the epoch.
   const bool cid_bit = (first & 0b00010000) != 0;
   const bool seqno_bit = (first & 0b00001000) != 0;
   const bool length_bit = (first & 0b00000100) != 0;
   header.epoch_bits = first & 0b00000011;

   const size_t expected_length = cid_length.value_or(0) + (seqno_bit ? 2 : 1) + (length_bit ? 2 : 0);
   if(bs.remaining() < expected_length) {
      throw TLS_Exception(AlertType::DecodeError, "DTLS unified header is truncated");
   }

   // RFC 9147 Section 4
   //    If a Connection ID is negotiated, then it MUST be contained in all
   //    datagrams.
   //
   // RFC 9147 Section 9.1
   //    If no CID is negotiated, then the receiver MUST reject any records it
   //    receives that contain a CID.
   BOTAN_STATE_CHECK(cid_bit == cid_length.has_value());
   if(cid_bit) {
      header.connection_id = bs.copy<ConnectionID>(cid_length.value());
   }

   if(seqno_bit) {
      header.sequence_number = load_be(bs.take<2>());
   } else {
      header.sequence_number = bs.take_byte();
   }

   if(length_bit) {
      header.length = load_be(bs.take<2>());
      if(bs.remaining() < *header.length) {
         throw TLS_Exception(AlertType::DecodeError, "Received protected DTLS record with truncated data");
      }
   }

   BOTAN_DEBUG_ASSERT(header.serialized_byte_length() == 1 + expected_length);

   return header;
}

size_t UnifiedHeader_DTLS::serialized_byte_length() const noexcept {
   const size_t connection_id_length = connection_id.has_value() ? connection_id->size() : 0;
   const size_t seq_no_length = std::visit([](auto&& arg) -> size_t { return sizeof(arg); }, sequence_number);
   const size_t length_length = length.has_value() ? sizeof(decltype(length)::value_type) : 0;
   return 1 + connection_id_length + seq_no_length + length_length;
}

void UnifiedHeader_DTLS::serialize_to(std::span<uint8_t> output) const {
   const auto expected_length = serialized_byte_length();

   BOTAN_ARG_CHECK(output.size() >= expected_length, "Output buffer is too small");
   BufferStuffer bs(output.first(expected_length));

   constexpr uint8_t preamble = 0b00100000;
   const uint8_t cid_bit = static_cast<uint8_t>(connection_id.has_value()) << 4;
   const uint8_t seqno_bit = static_cast<uint8_t>(std::holds_alternative<uint16_t>(sequence_number)) << 3;
   const uint8_t length_bit = static_cast<uint8_t>(length.has_value()) << 2;
   const uint8_t epoch = epoch_bits & 0b00000011;

   bs.append(preamble | cid_bit | seqno_bit | length_bit | epoch);

   if(connection_id.has_value()) {
      bs.append(*connection_id);
   }

   std::visit([&](auto&& arg) { bs.append(store_be(arg)); }, sequence_number);

   if(length.has_value()) {
      bs.append(store_be(*length));
   }

   BOTAN_DEBUG_ASSERT(bs.full());
}

PlaintextHeader_DTLS PlaintextHeader_DTLS::parse(BufferSlicer& bs) {
   if(bs.remaining() < DTLS_HEADER_SIZE) {
      throw TLS_Exception(AlertType::DecodeError, "Received DTLSPlaintext with truncated header");
   }

   const auto type = static_cast<Record_Type>(bs.take_byte());
   const auto legacy_version = Protocol_Version(load_be(bs.take<2>()));
   const auto epoch = static_cast<Epoch_Number>(load_be(bs.take<2>()));
   const auto sequence_number = load_be48(bs.take<6>());
   const auto length = load_be(bs.take<2>());

   if(bs.remaining() < length) {
      throw TLS_Exception(AlertType::DecodeError, "Received DTLSPlaintext with truncated payload");
   }

   // - - - - - -  - - - - - -  - - - - - -  - - - - - -  - - - - - -  - - - - -
   // After this point we're sure that the input buffer contained something that
   // roughly resembles a DTLSPlaintext record. Below we're checking the
   // semantics of the record header's fields as far as we can.
   //
   // * Any of the Decode_Errors above would lead to the input datagram being
   //   discarded by the DTLS_Record_Layer, and
   // * Any other errors below would lead to the connection being terminated
   //   with an alert.
   //

   // RFC 9147 Figure 2 DTLSPlaintext
   if(epoch != Epoch_Number::Unprotected) {
      throw TLS_Exception(AlertType::IllegalParameter, "Received DTLSPlaintext with epoch != 0");
   }

   // RFC 9846 5.1
   //    The length (in bytes) of the following TLSPlaintext.fragment. The
   //    length MUST NOT exceed 2^14 bytes. An endpoint that receives a record
   //    that exceeds this length MUST terminate the connection with a
   //    "record_overflow" alert.
   if(MAX_PLAINTEXT_SIZE < length) {
      throw TLS_Exception(AlertType::RecordOverflow, "Received DTLSPlaintext with too much plaintext data");
   }

   // RFC 8446 5.1
   //    Implementations MUST NOT send zero-length fragments of Handshake
   //    types, even if those fragments contain padding.
   //
   //    Zero-length fragments of Application Data MAY be sent, as they are
   //    potentially useful as a traffic analysis countermeasure.
   //
   // Hence, the payload length must always be non-null. Even for application
   // data, the protected payload would contain at least the authentication
   // tag and won't ever be empty either.
   if(length == 0) {
      throw TLS_Exception(AlertType::IllegalParameter, "Received DTLSPlaintext with empty payload");
   }

   // The legacy major version is essentially ossified to 0xFE and anything
   // else can be rejected right away.
   if(legacy_version.major_version() != 0xFE) {
      throw TLS_Exception(AlertType::IllegalParameter, "Received DTLSPlaintext with unexpected record version");
   }

   // RFC 9147 Section 4.1 (cont'd)
   //    If the first byte is alert(21), handshake(22), or ack(26), the
   //    record MUST be interpreted as a DTLSPlaintext record.
   //
   // Additionally, we let ChangeCipherSpec records pass through and
   // handle them explicitly in `process_dummy_change_cipher_spec()`
   // in TLS::Channel_Impl_13.
   if(type != Record_Type::ChangeCipherSpec &&  //
      type != Record_Type::Alert &&             //
      type != Record_Type::Handshake &&         //
      type != Record_Type::ACK) {
      throw TLS_Exception(AlertType::UnexpectedMessage,
                          fmt("Received DTLSPlaintext with unexpected content type: {}", static_cast<uint32_t>(type)));
   }

   return {
      .type = type,
      .legacy_version = legacy_version,
      .sequence_number = sequence_number,
      .length = length,
   };
}

std::array<uint8_t, DTLS_HEADER_SIZE> PlaintextHeader_DTLS::serialize() const {
   return concat(store_be(type),
                 store_be(legacy_version.version_code()),
                 store_be(static_cast<uint16_t>(Epoch_Number::Unprotected)),  // ossified (RFC 9147 Section 4 Figure 2)
                 store_be48(sequence_number),
                 store_be(length));
}

}  // namespace Botan::TLS
