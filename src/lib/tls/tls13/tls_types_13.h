/**
 * TLS 1.3 Strong Type Wrappers
 * (C) 2026 Jack Lloyd
 *     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_TYPES_13_H_
#define BOTAN_TLS_TYPES_13_H_

#include <botan/secmem.h>
#include <botan/strong_type.h>
#include <variant>
#include <vector>

namespace Botan::TLS {

/// Holds the serialization of a single TLS 1.3 handshake message along
/// with the handshake protocol header.
using MarshalledHandshakeMessage = Strong<std::vector<uint8_t>, struct MarshalledHandshakeMessage_>;

/// Holds the serialization of a TLS 1.3 handshake message flight containing
/// multiple handshake messages along with their handshake protocol headers.
using MarshalledHandshakeMessageFlight = Strong<std::vector<uint8_t>, struct MarshalledHandshakeMessageFlight_>;

/// Holds the serialization of a single TLS 1.3 handshake message fragment along
/// with the handshake protocol header. This is used in DTLS' fragmentation.
using MarshalledHandshakeMessageFragment = Strong<std::vector<uint8_t>, struct MarshalledHandshakeMessageFragment_>;

/// Holds either a single TLS 1.3 handshake message or a vector of handshake
/// fragments of a single handshake message in the DTLS case.
using PreparedHandshakeMessage =
   std::variant<MarshalledHandshakeMessage, std::vector<MarshalledHandshakeMessageFragment>>;

/// Holds the entire serialization of a handshake message flight. Either as a
/// flat vector of bytes or as a vector of handshake message fragments in DTLS.
using PreparedHandshakeMessageFlight =
   std::variant<MarshalledHandshakeMessageFlight, std::vector<MarshalledHandshakeMessageFragment>>;

/// Holds the serialization of a single TLS 1.3 record along with the record
/// protocol header. Protected records hold the encrypted payload and AEAD tag.
using MarshalledRecord = Strong<secure_vector<uint8_t>, struct MarshalledRecord_>;

enum class Epoch_Number /* NOLINT(*-enum-size) */ : uint64_t {
   Unprotected = 0,
   EarlyTraffic = 1,
   HandshakeTraffic = 2,
   ApplicationTraffic_0 = 3,
   // ApplicationTrafic_1 = 4
   // ApplicationTraffic_2 = 5
   // ...
   // ApplicationTraffic_N = N + 3
};

/**
 * Wraps the epoch0 (unprotected) sequence numbers that are being handed down
 * from a DTLS 1.3 handshake to a DTLS 1.2 handshake during protocol downgrade.
 */
struct Epoch0_SequenceNumbers {
      uint64_t read;
      uint64_t write;
};

}  // namespace Botan::TLS

#endif
