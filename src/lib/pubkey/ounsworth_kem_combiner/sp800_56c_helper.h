/**
* NIST.SP.800-56C rev. 2 - One-Step Key Derivation Function
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_56C_HELPER_H
#define BOTAN_SP800_56C_HELPER_H

#include <botan/hybrid_kem.h>
#include <botan/mac.h>
#include <botan/pk_algs.h>
#include <botan/internal/kmac.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

namespace Botan::Sp800_56C {

/**
 * @brief One-Step Key Derivation (SP800-56Cr2, Section 4, Option 1) with
 *        a hash function
 *
 * @param output_buffer output buffer. Also defines the output length.
 * @param hash the hash function to use
 * @param z shared secret
 * @param fixed_info context-specific data
 */
BOTAN_TEST_API void kdm(std::span<uint8_t> output_buffer,
                        HashFunction& hash,
                        std::span<const uint8_t> z,
                        std::span<const uint8_t> fixed_info);

/**
 * @brief One-Step Key Derivation (SP800-56Cr2, Section 4, Option 2 and 3) with
 *        HMAC or KMAC.
 *
 * Note that no default_salt is used. The caller must provide the default salt
 *
 * @param output_buffer output buffer. Also defines the output length.
 * @param mac the mac function to use. Allowed are KMAC and HMAC instances.
 * @param z shared secret
 * @param fixed_info context-specific data
 * @param salt a salt which is used for the MAC's key. See SP800-56Cr2
 *             Section 4.1 Input 2.a.
 */
BOTAN_TEST_API void kdm(std::span<uint8_t> output_buffer,
                        MessageAuthenticationCode& mac,
                        std::span<const uint8_t> z,
                        std::span<const uint8_t> fixed_info,
                        std::span<const uint8_t> salt);

}  // namespace Botan::Sp800_56C

#endif  // BOTAN_SP800_56C_HELPER_H
