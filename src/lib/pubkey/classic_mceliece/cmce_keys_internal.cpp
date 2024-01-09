/*
* Classic McEliece key generation with Internal Private and Public Key classes
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/cmce_keys_internal.h>

namespace Botan {

namespace {

std::optional<Classic_McEliece_KeyPair_Internal> try_generate_keypair(std::span<uint8_t> out_next_seed,
                                                                      const Classic_McEliece_Parameters& params,
                                                                      std::span<const uint8_t> seed) {
   BOTAN_ASSERT_EQUAL(seed.size(), 32, "Valid seed length");
   BOTAN_ASSERT_EQUAL(out_next_seed.size(), 32, "Valid output seed length");

   auto field = params.poly_ring();

   auto big_e_xof = params.prg(seed);

   auto s = big_e_xof->output<secure_vector<uint8_t>>(params.n() / 8);
   auto ordering_seed = big_e_xof->output<secure_vector<uint8_t>>((params.sigma2() * params.q()) / 8);
   auto irreducible_seed = big_e_xof->output<secure_vector<uint8_t>>((params.sigma1() * params.t()) / 8);
   big_e_xof->output(out_next_seed);

   // Field-ordering generation - Classic McEliece ISO 8.2
   auto field_ordering = Classic_McEliece_Field_Ordering::create_field_ordering(params, ordering_seed);
   if(!field_ordering) {
      return std::nullopt;
   }

   // Irreducible-polynomial generation - Classic McEliece ISO 8.1
   auto beta = field.create_element_from_bytes(irreducible_seed);
   auto g = params.poly_ring().compute_minimal_polynomial(beta);
   if(!g) {
      return std::nullopt;
   }

   // Matrix generation for Goppa codes - Classic McEliece ISO 7.2
   auto pk_matrix_opt = Classic_McEliece_Matrix::create_matrix(params, field_ordering.value(), g.value());
   if(!pk_matrix_opt) {
      return std::nullopt;
   }
   auto& [pk_matrix, pivots] = pk_matrix_opt.value();
   // Possibly, field_ordering is updated if semi-systematic form is used
   if(params.is_f()) {
      field_ordering.value().permute_with_pivots(params, pivots);
   }
   auto pk_bytes_value = pk_matrix.bytes();

   auto sk = std::make_shared<Classic_McEliece_PrivateKeyInternal>(params,
                                                                   secure_vector<uint8_t>(seed.begin(), seed.end()),
                                                                   pivots,
                                                                   std::move(g.value()),
                                                                   std::move(field_ordering.value()),
                                                                   std::move(s));

   auto pk = std::make_shared<Classic_McEliece_PublicKeyInternal>(params, std::move(pk_bytes_value));

   return Classic_McEliece_KeyPair_Internal{.private_key = sk, .public_key = pk};
}

}  // namespace

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

std::shared_ptr<Classic_McEliece_PublicKeyInternal> Classic_McEliece_PublicKeyInternal::create_from_private_key(
   const Classic_McEliece_PrivateKeyInternal& sk) {
   // TODO: Must be copied, because field ordering must be passed mutable (because pivot stuff). Can we prevent this?
   //Classic_McEliece_Field_Ordering field_ord(sk.field_ordering());
   auto pk_matrix_opt = Classic_McEliece_Matrix::create_matrix(sk.params(), sk.field_ordering(), sk.g());
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
                                                                              std::span<const uint8_t> seed) {
   BOTAN_ASSERT_EQUAL(seed.size(), 32, "Valid seed length");

   secure_vector<uint8_t> next_seed(32);

   // Emergency abort in case unexpected logical error to prevent endless loops
   //   Success probability: >29% per attempt [>98% for 'f' instances]
   //   => 162 [15] attempts for 2^(-80) fail probability
   const size_t MAX_ATTEMPTS = params.is_f() ? 15 : 162;
   for(size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
      if(auto keypair = try_generate_keypair(next_seed, params, seed)) {
         return keypair.value();
      }
      seed = next_seed;
   }
   throw Internal_Error("Key generation fails consistently. Something went wrong.");
}

}  // namespace Botan
