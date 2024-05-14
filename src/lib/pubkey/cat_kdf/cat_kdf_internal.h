/**
* CatKDF Internals
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CAT_KDF_INTERNAL_H_
#define BOTAN_CAT_KDF_INTERNAL_H_

#include <botan/secmem.h>
#include <span>

namespace Botan::Cat_Kdf {
// TS 103 744 - V1.1.1, Section 7.2, Context formatting function (f)
std::vector<uint8_t> f_context_func(std::string_view hash_function, const std::vector<std::span<const uint8_t>>& val);

// TS 103 744 - V1.1.1, Section 8.2, Concatenate hybrid key agreement scheme
void BOTAN_TEST_API cat_kdf_secret_combiner(std::span<uint8_t> out_shared_secret /* also defines length */,
                                            std::string_view hash_function,
                                            std::span<const uint8_t> public_key_bytes /* MA */,
                                            std::span<const uint8_t> ciphertexts /* MB */,
                                            const std::vector<secure_vector<uint8_t>>& shared_secrets /* k_i */,
                                            std::span<const uint8_t> psk,
                                            std::span<const uint8_t> context,
                                            std::span<const uint8_t> label);
}  // namespace Botan::Cat_Kdf

#endif  // BOTAN_CAT_KDF_INTERNAL_H_
