/*
* DTLS record structures of DTLS 1.3
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_DTLS_RECORD_13_H_
#define BOTAN_TLS_DTLS_RECORD_13_H_

#include <botan/assert.h>
#include <botan/secmem.h>
#include <botan/tls_magic.h>
#include <botan/tls_policy.h>
#include <botan/tls_version.h>
#include <botan/internal/tls_types_13.h>
#include <botan/internal/tls_types_dtls13.h>
#include <optional>
#include <variant>

namespace Botan {
class BufferSlicer;
}

namespace Botan::TLS {

/**
 * Unified header structure for DTLS 1.3 records (RFC 9147 Section 4 Figure 3)
 */
struct BOTAN_TEST_API UnifiedHeader_DTLS {
      /// NOLINTBEGIN(*-non-private-member-variables-in-classes)

      /// The two low-order bits of the epoch
      uint8_t epoch_bits;

      /// The connection ID (if any) of the record
      std::optional<ConnectionID> connection_id;

      /// The low-order bits of the sequence number (either 8 or 16 bits)
      SequenceNumberHint sequence_number;

      /// The (optional) length of the record. If this is not present, the
      /// length is assumed to be the remaining bytes in the datagram.
      std::optional<uint16_t> length;

      /// NOLINTEND(*-non-private-member-variables-in-classes)

      static size_t expected_length(const Policy& policy, std::optional<size_t> cid_length) {
         BOTAN_UNUSED(policy);

         // RFC 9147 Section 4 Figure 3
         constexpr size_t header_byte = 1;
         constexpr size_t sequence_number_bytes = 2;  // currently hard-coded (TODO: make this configurable via policy)
         constexpr size_t length_bytes = 2;           // hard-coded (likely forever)
         return header_byte + (cid_length.has_value() ? *cid_length : 0) + sequence_number_bytes + length_bytes;
      }

      /**
       * Parses a unified header from the given @p record_bytes. Typically the
       * @p record_bytes will contain more than just the unified header.
       *
       * @param record_bytes The buffer slicer to parse the unified header from
       * @param cid_length   The negotiated length of the connection ID or
       *                     std::nullopt if no connection ID was negotiated.
       *
       * @throws if parsing fails
       */
      static UnifiedHeader_DTLS parse(BufferSlicer& record_bytes, std::optional<size_t> cid_length);

      size_t serialized_byte_length() const noexcept;
      void serialize_to(std::span<uint8_t> output) const;

      template <concepts::resizable_byte_buffer ContainerT = std::vector<uint8_t>>
      auto serialize() const {
         ContainerT output;
         output.resize(serialized_byte_length());
         serialize_to(output);
         return output;
      }
};

/**
 * Plaintext header of unprotected records "DTLSPlaintext" RFC 9147 4. Figure 2.
 * This encapsulates the header fields without the payload.
 */
struct PlaintextHeader_DTLS {
      /// NOLINTBEGIN(*-non-private-member-variables-in-classes)

      Record_Type type;
      Protocol_Version legacy_version;
      /* RFC 9147 4. Figure 2: epoch = 0 */
      uint64_t sequence_number;
      uint16_t length;

      /// NOLINTEND(*-non-private-member-variables-in-classes)

      /**
       * Reads a PlaintextHeader_DTLS from the given @p bs buffer slicer.
       */
      static PlaintextHeader_DTLS parse(BufferSlicer& bs);

      std::array<uint8_t, DTLS_HEADER_SIZE> serialize() const;
};

// RFC 9147 Section 4 Figure 2 "DTLSCiphertext"
struct ProtectedRecord_DTLS {
      UnifiedHeader_DTLS header;
      secure_vector<uint8_t> payload;
};

// RFC 9147 Section 4 Figure 2 "DTLSPlaintext"
struct PlaintextRecord_DTLS {
      PlaintextHeader_DTLS header;
      secure_vector<uint8_t> payload;
};

}  // namespace Botan::TLS

#endif
