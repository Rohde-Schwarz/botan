/*
* Classic McEliece key generation with Internal Private and Public Key classes
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/cmce_keys_internal.h>

namespace Botan {

Classic_McEliece_PrivateKeyInternal Classic_McEliece_PrivateKeyInternal::from_bytes(
   const Classic_McEliece_Parameters& params, std::span<const uint8_t> sk_bytes) {
   BOTAN_ASSERT(sk_bytes.size() == params.sk_size_bytes(), "Valid private key size");
   BufferSlicer sk_slicer(sk_bytes);

   auto delta = sk_slicer.copy_as_secure_vector(params.seed_len());
   auto c = secure_bitvector(sk_slicer.take(params.sk_c_bytes()));

   auto g_bytes = sk_slicer.take(params.sk_poly_g_bytes());
   auto g = Classic_McEliece_Minimal_Polynomial::from_bytes(g_bytes, params.poly_f());

   auto alpha_control_bits = sk_slicer.take(params.sk_alpha_control_bytes());
   auto field_ordering = Classic_McEliece_Field_Ordering::create_from_control_bits(params, alpha_control_bits);

   auto s = sk_slicer.copy_as_secure_vector(params.sk_s_bytes());
   BOTAN_ASSERT_NOMSG(sk_slicer.empty());
   return Classic_McEliece_PrivateKeyInternal(
      params, std::move(delta), std::move(c), std::move(g), std::move(field_ordering), std::move(s));
}

secure_vector<uint8_t> Classic_McEliece_PrivateKeyInternal::serialize() const {
   return concat(m_delta, m_c.to_bytes(), m_g.serialize(), m_field_ordering.alphas_control_bits().to_bytes(), m_s);
}

std::shared_ptr<Classic_McEliece_PublicKeyInternal> Classic_McEliece_PublicKeyInternal::create_from_sk(
   const Classic_McEliece_PrivateKeyInternal& sk) {
   // TODO: Must be copied, because field ordering must be passed mutable (because pivot stuff). Can we prevent this?
   Classic_McEliece_Field_Ordering field_ord(sk.field_ordering());
   auto pk_matrix_opt = Classic_McEliece_Matrix::create_matrix(sk.params(), field_ord, sk.g());
   if(!pk_matrix_opt.has_value()) {
      throw Decoding_Error("Cannot create public key from private key. Private key is invalid.");
   }
   // TODO: Do we want to check that there is no pivot?
   auto& [pk_matrix, _] = pk_matrix_opt.value();
   auto pk_bytes_value = pk_matrix.bytes();

   auto pk = std::make_shared<Classic_McEliece_PublicKeyInternal>(sk.params(), std::move(pk_bytes_value));

   return pk;
}

Classic_McEliece_KeyPair_Internal Classic_McEliece_KeyPair_Internal::generate(const Classic_McEliece_Parameters& params,
                                                                              const secure_vector<uint8_t>& seed) {
   BOTAN_ASSERT_EQUAL(seed.size(), 32, "Valid seed length");

   auto field = params.poly_ring();

   // TODO: Remove Counter - Only for debugging. Keep this for emergency abort.
   int ctr = 30;

   auto delta = secure_vector<uint8_t>(seed);

   while(true) {
      if(ctr-- <= 0) {
         throw Internal_Error("Cannot generate key.");
      }

      auto big_e = params.prg(delta);

      // TODO: Return XOF for PRG and pull data directly from xof object
      //       e.g. xof->output<secure_vector<uint8_t>>(params.n() / 8)
      //       Advantage: params.prg() doesn't need to know anything about its output structure
      BufferSlicer big_e_slicer(big_e);

      auto s = big_e_slicer.take(params.n() / 8);
      auto ordering_seed = big_e_slicer.take((params.sigma2() * params.q()) / 8);
      auto irreducible_seed = big_e_slicer.take((params.sigma1() * params.t()) / 8);
      auto delta_p = big_e_slicer.take(params.ell() / 8);
      BOTAN_ASSERT_NOMSG(big_e_slicer.empty());

      auto field_ordering = Classic_McEliece_Field_Ordering::create_field_ordering(params, ordering_seed);
      if(!field_ordering.has_value()) {
         // TODO: maybe: copy_mem(delta, delta_p) or delta.assign(delta_p.begin(), delta_p.end())
         // TODO: Only once at the start of the loop
         delta = secure_vector<uint8_t>(delta_p.begin(), delta_p.end());

         // TODO: maybe avoid `continue`. Not at all cost! That's really nit-picky.
         //       Instead, consider using a method that early-returns
         //
         //   if(auto sk = try_generate_sk()) {
         //      if(auto pk = try_generate_pk(sk.value())) {
         //         return {sk, pk};
         //      }
         //   }
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

      auto sk = std::make_shared<Classic_McEliece_PrivateKeyInternal>(params,
                                                                      delta,
                                                                      pivots,
                                                                      std::move(g.value()),
                                                                      std::move(field_ordering.value()),
                                                                      secure_vector<uint8_t>(s.begin(), s.end()));

      auto pk = std::make_shared<Classic_McEliece_PublicKeyInternal>(params, std::move(pk_bytes_value));

      return Classic_McEliece_KeyPair_Internal{.private_key = sk, .public_key = pk};
   }
   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan
