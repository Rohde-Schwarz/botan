/*
* Classic McEliece key generation with Internal Private and Public Key classes
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/cmce_keys_internal.h>

namespace Botan {

std::pair<Classic_McEliece_PrivateKeyInternal, Classic_McEliece_PublicKeyInternal> cmce_key_gen(
   const Classic_McEliece_Parameters& params, const secure_vector<uint8_t>& seed) {
   BOTAN_ASSERT_EQUAL(seed.size(), 32, "Valid seed length");

   auto field = params.poly_ring();

   auto delta = secure_vector<uint8_t>(seed);

   // TODO: Remove Counter - Only for debugging
   int ctr = 10;
   while(true) {
      if(ctr-- <= 0) {
         throw Internal_Error("Cannot generate key.");
      }
      auto big_e = params.prg(delta);

      BufferSlicer big_e_slicer(big_e);

      auto s = big_e_slicer.take(params.n() / 8);
      auto ordering_seed = big_e_slicer.take((params.sigma2() * params.q()) / 8);
      auto irreducible_seed = big_e_slicer.take((params.sigma1() * params.t()) / 8);
      auto delta_p = big_e_slicer.take(params.ell() / 8);
      BOTAN_ASSERT_NOMSG(big_e_slicer.empty());

      auto field_ordering = Classic_McEliece_Field_Ordering::create_field_ordering(params, ordering_seed);
      //auto pi = field_ordering(params, ordering_seed);  // ord = FieldOrdering(params, ordering_seed)
      if(!field_ordering.has_value()) {
         delta = secure_vector<uint8_t>(delta_p.begin(), delta_p.end());
         continue;
      }

      //Irreducible algorithm 8.1
      auto beta = field.create_element_from_bytes(irreducible_seed);
      auto g = beta.compute_minimal_polynomial(params.poly_ring());  //TODO: Check if degree is t and optional return?

      if(!g.has_value()) {
         delta = secure_vector<uint8_t>(delta_p.begin(), delta_p.end());
         continue;
      }

      // Create pk, possibly update field_ordering
      auto pk_matrix_opt = Classic_McEliece_Matrix::create_matrix(params, field_ordering.value(), g.value());
      if(!pk_matrix_opt.has_value()) {
         delta = secure_vector<uint8_t>(delta_p.begin(), delta_p.end());
         continue;
      }
      auto& [pk_matrix, pivots] = pk_matrix_opt.value();
      auto pk_bytes_value = pk_matrix.bytes();

      auto sk = Classic_McEliece_PrivateKeyInternal(params,
                                                    delta,
                                                    pivots,
                                                    std::move(g.value()),
                                                    std::move(field_ordering.value()),
                                                    secure_vector<uint8_t>(s.begin(), s.end()));

      auto pk = Classic_McEliece_PublicKeyInternal(params, std::move(pk_bytes_value));

      return std::make_pair(std::move(sk), std::move(pk));
   }
   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan