/*
* Classic McEliece Encapsulation
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include "botan/rng.h"
#include <botan/internal/cmce_encaps.h>

namespace Botan {

bitvector Classic_McEliece_Encryptor::encode(const Classic_McEliece_Parameters& params,
                                             const secure_bitvector& e,
                                             const Classic_McEliece_Matrix& mat) {
   return mat.mul(params, e);
}

std::optional<secure_bitvector> Classic_McEliece_Encryptor::fixed_weight_vector_gen(
   const Classic_McEliece_Parameters& params, const secure_vector<uint8_t>& rand) {
   BOTAN_ASSERT_NOMSG(rand.size() == params.tau() * params.sigma1() / 8);
   uint16_t mask_m = (uint32_t(1) << params.m()) - 1;  // Only take m least significant bits
   std::vector<uint16_t> a_values;
   a_values.reserve(params.tau());
   a_values.clear();
   BufferSlicer rand_slicer(rand);

   // Steps 2 & 3: Create d_j from uniform random bits. The first t d_j entries
   //              in range {0,...,n-1} are defined as a_0,...,a_(t-1). ...
   for(size_t j = 0; j < params.tau(); ++j) {
      uint16_t d = load_le<uint16_t>(rand_slicer.take(params.sigma1() / 8).data(), 0);
      //TODO: This is not CT, but neither is the reference implementation here.
      // This side channel only leaks which random elements are selected and which are dropped,
      // but no information about their content is leaked.
      d &= mask_m;
      if(d < params.n() && a_values.size() < params.t()) {
         a_values.push_back(d);
      }
   }
   if(a_values.size() < params.t()) {
      // Step 3: ... If fewer than t of such elements exist restart
      return std::nullopt;
   }

   // Step 4: Restart if not all a_i are distinct
   for(size_t i = 1; i < params.t(); ++i) {
      for(size_t j = 0; j < i; ++j) {
         if(a_values.at(i) == a_values.at(j)) {
            return std::nullopt;
         }
      }
   }

   secure_bitvector e(params.n());

   // Step 5: Set all bits of e at the positions of a_values
   for(auto& a : a_values) {
      for(size_t i = 0; i < params.n(); i++) {
         e.at(i) |= (i == a);
      }
   }

   return e;
}

void Classic_McEliece_Encryptor::kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                                             std::span<uint8_t> out_shared_key,
                                             RandomNumberGenerator& rng,
                                             size_t desired_shared_key_len,  // Whats up with these?
                                             std::span<const uint8_t> salt) {
   BOTAN_UNUSED(desired_shared_key_len, salt);
   BOTAN_ASSERT(out_encapsulated_key.size() == m_key->params().ciphertext_size(),
                "Correct encapsulated key output length");
   BOTAN_ASSERT(out_shared_key.size() == m_key->params().hash_out_bytes(), "Correct shared key output length");

   // Call fixed_weight until it is successful
   auto& params = m_key->params();
   secure_bitvector e;
   // TODO: Remove Counter - Only for debugging - For emergency break - Compute sensible max_attempts
   int ctr = 100;
   while(true) {
      if(ctr-- <= 0) {
         throw Internal_Error("Cannot created fixed weight vector.");
      }
      auto weight_gen = fixed_weight_vector_gen(params, rng.random_vec((params.sigma1() / 8) * params.tau()));

      if(weight_gen.has_value()) {
         e = weight_gen.value();
         break;
      }
   }

   auto big_c = encode(params, e, m_key->matrix()).to_bytes();
   auto hash_func = params.hash_func();

   if(params.is_pc()) {
      hash_func->update(2);
      hash_func->update(e.to_bytes());
      auto big_c_1 = hash_func->final_stdvec();
      big_c = Botan::concat(big_c, big_c_1);
      hash_func->clear();
   }

   hash_func->update(1);
   hash_func->update(e.to_bytes());
   hash_func->update(big_c);

   auto big_k = hash_func->final<secure_vector<uint8_t>>();
   hash_func->clear();

   std::ranges::copy(big_c, out_encapsulated_key.begin());
   std::ranges::copy(big_k, out_shared_key.begin());
}

}  // namespace Botan