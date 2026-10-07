/**
 * DTLS 1.3 Strong Type Wrappers
 * (C) 2026 Jack Lloyd
 *     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_TLS_TYPES_DTLS13_H_
#define BOTAN_TLS_TYPES_DTLS13_H_

#include <botan/strong_type.h>

#include <variant>
#include <vector>

namespace Botan::TLS {

using SequenceNumberHint = std::variant<uint16_t, uint8_t>;

using ConnectionID = Strong<std::vector<uint8_t>, struct ConnectionIDTag_>;

}  // namespace Botan::TLS

#endif
