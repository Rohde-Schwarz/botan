/**
* CatKDF Internals
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include <botan/internal/cat_kdf_internal.h>

#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan::Cat_Kdf {
// TS 103 744 - V1.1.1, Section 7.2, Context formatting function (f)
std::vector<uint8_t> f_context_func(std::string_view hash_function, const std::vector<std::span<const uint8_t>>& val) {
   auto hash = HashFunction::create_or_throw(hash_function);  // TODO Generalize
   for(const auto& v : val) {
      auto len = checked_cast_to_or_throw<uint32_t, Invalid_Argument>(v.size(), "Invalid value length");
      hash->update_be(len);
      hash->update(v);
   }
   return hash->final_stdvec();
}

// TS 103 744 - V1.1.1, Section 8.2, Concatenate hybrid key agreement scheme
void cat_kdf_secret_combiner(std::span<uint8_t> out_shared_secret /* also defines length */,
                             std::string_view hash_function,
                             std::span<const uint8_t> public_key_bytes /* MA */,
                             std::span<const uint8_t> ciphertexts /* MB */,
                             const std::vector<secure_vector<uint8_t>>& shared_secrets /* k_i */,
                             std::span<const uint8_t> psk,
                             std::span<const uint8_t> context,
                             std::span<const uint8_t> label) {
   // TS 103 744 - V1.1.1, Section 8.2
   // 1) Form secret = psk || k_1 || k_2 || … || k_n.
   auto secret_len = reduce(shared_secrets, psk.size(), [](size_t acc, const auto& v) { return acc + v.size(); });
   secure_vector<uint8_t> secret;
   secret.reserve(secret_len);
   secret.insert(secret.end(), psk.begin(), psk.end());
   for(const auto& k_i : shared_secrets) {
      secret.insert(secret.end(), k_i.begin(), k_i.end());
   }
   BOTAN_ASSERT_NOMSG(secret.size() == secret_len);

   // 2) Set f_context = f(context, MA, MB), where f is a context formatting function.
   const auto f_context = f_context_func(hash_function, {context, public_key_bytes, ciphertexts});

   // 3) key_material = KDF(secret, label, f_context, length).
   auto kdf = KDF::create_or_throw(fmt("HKDF({})", hash_function));  // TODO: Generalize
   kdf->derive_key(out_shared_secret, secret, label, f_context);
}

}  // namespace Botan::Cat_Kdf