/*
 * Classic McEliece Key Generation
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/cmce.h>
#include <botan/rng.h>
#include <botan/internal/bitvector.h>
#include <botan/internal/cmce_debug_utils.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/pk_ops.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

class Classic_McEliece_Encryptor final : public PK_Ops::KEM_Encryption {
   public:
      Classic_McEliece_Encryptor(std::shared_ptr<Classic_McEliece_PublicKeyInternal> key) : m_key(std::move(key)) {}

      size_t shared_key_length(size_t desired_shared_key_len) const override {
         // TODO: Desired shared key length?
         BOTAN_UNUSED(desired_shared_key_len);
         return m_key->params().hash_out_bytes();
      }

      size_t encapsulated_key_length() const override { return m_key->params().ciphertext_size(); }

      virtual void kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                               std::span<uint8_t> out_shared_key,
                               RandomNumberGenerator& rng,
                               size_t desired_shared_key_len,  // Whats up with these?
                               std::span<const uint8_t> salt) override {
         BOTAN_UNUSED(desired_shared_key_len, salt);
         BOTAN_ASSERT(out_encapsulated_key.size() == m_key->params().ciphertext_size(),
                      "Correct encapsulated key output length");
         BOTAN_ASSERT(out_shared_key.size() == m_key->params().hash_out_bytes(), "Correct shared key output length");
         auto [encaps_key, shared_key] = cmce_encaps(*m_key, rng);

         std::ranges::copy(encaps_key, out_encapsulated_key.begin());
         std::ranges::copy(shared_key, out_shared_key.begin());
      }

   private:
      std::shared_ptr<Classic_McEliece_PublicKeyInternal> m_key;
};

class Classic_McEliece_Decryptor final : public PK_Ops::KEM_Decryption {
   public:
      Classic_McEliece_Decryptor(std::shared_ptr<Classic_McEliece_PrivateKeyInternal> key) : m_key(std::move(key)) {}

      size_t shared_key_length(size_t desired_shared_key_len) const override {
         // TODO: Desired shared key length?
         BOTAN_UNUSED(desired_shared_key_len);
         return m_key->params().hash_out_bytes();
      }

      size_t encapsulated_key_length() const override { return m_key->params().ciphertext_size(); }

      void kem_decrypt(std::span<uint8_t> out_shared_key,
                       std::span<const uint8_t> encapsulated_key,
                       size_t desired_shared_key_len,  // TODO: Whats up with these?
                       std::span<const uint8_t> salt) override {
         BOTAN_UNUSED(desired_shared_key_len, salt);
         BOTAN_ASSERT(encapsulated_key.size() == m_key->params().ciphertext_size(), "Correct encapsulated key length");
         BOTAN_ASSERT(out_shared_key.size() == m_key->params().hash_out_bytes(), "Correct shared key output length");
         throw Not_Implemented("TODO");
      }

   private:
      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> m_key;
};

//------------------------------------------------------------------------------------------------------
namespace {
bitvector<uint64_t> cmce_encode(const Classic_McEliece_Parameters& params,
                                const secure_bitvector<uint64_t>& e,
                                const Classic_McEliece_Matrix& mat) {
   return mat.mul(params, e);
}

}  // namespace

std::vector<Classic_McEliece_GF> compute_goppa_syndrome(const Classic_McEliece_Minimal_Polynomial& goppa_poly,
                                                        const Classic_McEliece_Field_Ordering& ordering,
                                                        std::span<const uint8_t> word_to_decaps) {
   BOTAN_UNUSED(goppa_poly, ordering, word_to_decaps);
   throw Not_Implemented("TODO");
}

std::vector<Classic_McEliece_GF> berlekamp_massey(const Classic_McEliece_Parameters& params,
                                                  const std::vector<Classic_McEliece_GF>& syndrome) {
   BOTAN_UNUSED(params, syndrome);
   throw Not_Implemented("TODO");
}

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
      auto beta = field->create_element_from_bytes(irreducible_seed);
      auto g = beta.compute_minimal_polynomial();  //TODO: Check if degree is t and optional return?

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

/**
* Fixed-weight-vector generation algorithm according to ISO McEliece.
*/
std::optional<secure_bitvector<uint64_t>> cmce_fixed_weight_vector_gen(const Classic_McEliece_Parameters& params,
                                                                       const secure_vector<uint8_t>& rand) {
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

   secure_bitvector<uint64_t> e(params.n());

   // Step 5: Set all bits of e at the positions of a_values
   for(auto& a : a_values) {
      for(size_t i = 0; i < params.n(); i++) {
         e.at(i) |= (i == a);
      }
   }

   return e;
}

/// @returns (C,K)
std::pair<std::vector<uint8_t>, secure_vector<uint8_t>> cmce_encaps(const Classic_McEliece_PublicKeyInternal& pk,
                                                                    RandomNumberGenerator& rng) {
   // Call fixed_weight until it is successful
   auto& params = pk.params();
   secure_bitvector<uint64_t> e;
   // TODO: Remove Counter - Only for debugging
   int ctr = 10;
   while(true) {
      if(ctr-- <= 0) {
         throw Internal_Error("Cannot created fixed weight vector.");
      }
      auto weight_gen = cmce_fixed_weight_vector_gen(params, rng.random_vec((params.sigma1() / 8) * params.tau()));

      if(weight_gen.has_value()) {
         e = weight_gen.value();
         break;
      }
   }

   auto big_c = cmce_encode(params, e, pk.matrix()).to_bytes();
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

   return std::make_pair(big_c, big_k);
}

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(Classic_McEliece_Parameter_Set set,
                                                       std::vector<uint8_t> pub_key) {
   // TODO: ASSERT Correct key length + correct zero padding in matrix?
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(Classic_McEliece_Parameters::create(set),
                                                                   Classic_McEliece_Matrix(std::move(pub_key)));
}

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(const AlgorithmIdentifier& alg_id,
                                                       std::vector<uint8_t> key_bits) {
   // TODO: ASSERT Correct key length + correct zero padding in matrix?
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(Classic_McEliece_Parameters::create(alg_id.oid()),
                                                                   Classic_McEliece_Matrix(std::move(key_bits)));
}

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(const Classic_McEliece_PublicKey& other) {
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(*other.m_public);
}

Classic_McEliece_PublicKey& Classic_McEliece_PublicKey::operator=(const Classic_McEliece_PublicKey& other) {
   if(this != &other) {
      m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(*other.m_public);
   }
   return *this;
}

AlgorithmIdentifier Classic_McEliece_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Classic_McEliece_PublicKey::object_identifier() const {
   return m_public->params().object_identifier();
}

size_t Classic_McEliece_PublicKey::key_length() const {
   return m_public->matrix().bytes().size();
}

size_t Classic_McEliece_PublicKey::estimated_strength() const {
   throw Not_Implemented("TODO");
}

std::vector<uint8_t> Classic_McEliece_PublicKey::public_key_bits() const {
   return m_public->matrix().bytes();
}

bool Classic_McEliece_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   //TODO: How to check CMCE key
   return true;
}

std::unique_ptr<Private_Key> Classic_McEliece_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Classic_McEliece_PrivateKey>(rng, m_public->params().set());
}

std::unique_ptr<PK_Ops::KEM_Encryption> Classic_McEliece_PublicKey::create_kem_encryption_op(
   std::string_view, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      return std::make_unique<Classic_McEliece_Encryptor>(this->m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(RandomNumberGenerator& rng,
                                                         Classic_McEliece_Parameter_Set param_set) {
   auto params = Classic_McEliece_Parameters::create(param_set);
   auto [sk_internal, pk_internal] = cmce_key_gen(params, rng.random_vec(params.seed_len()));
   m_private = std::make_shared<Classic_McEliece_PrivateKeyInternal>(std::move(sk_internal));
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(std::move(pk_internal));
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(std::span<const uint8_t> sk,
                                                         Classic_McEliece_Parameter_Set param_set) {
   auto params = Classic_McEliece_Parameters::create(param_set);
   auto sk_internal = Classic_McEliece_PrivateKeyInternal::from_bytes(std::move(params), sk);
   m_private = std::make_shared<Classic_McEliece_PrivateKeyInternal>(std::move(sk_internal));
   m_public = nullptr;  // TODO: Create public key from sk
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(const AlgorithmIdentifier& alg_id,
                                                         std::span<const uint8_t> key_bits) :
      Classic_McEliece_PrivateKey(key_bits, Classic_McEliece_Parameters::param_set_from_oid(alg_id.oid())) {}

std::unique_ptr<Public_Key> Classic_McEliece_PrivateKey::public_key() const {
   return std::make_unique<Classic_McEliece_PublicKey>(*this);
}

secure_vector<uint8_t> Classic_McEliece_PrivateKey::private_key_bits() const {
   return raw_private_key_bits();
}

secure_vector<uint8_t> Classic_McEliece_PrivateKey::raw_private_key_bits() const {
   return m_private->serialize();
}

std::unique_ptr<PK_Ops::KEM_Decryption> Classic_McEliece_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view params, std::string_view provider) const {
   BOTAN_UNUSED(rng, params);
   if(provider.empty() || provider == "base") {
      return std::make_unique<Classic_McEliece_Decryptor>(this->m_private);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
