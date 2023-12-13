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

#include <algorithm>

namespace Botan {

namespace {
std::pair<CT::Mask<uint8_t>, secure_bitvector> cmce_decode(const Classic_McEliece_PrivateKeyInternal& sk,
                                                           bitvector big_c);
}

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

         auto [decode_success_mask, maybe_e] = cmce_decode(*m_key, bitvector(encapsulated_key));  //TODO: pc variant
         secure_vector<uint8_t> e_bytes(m_key->s().size());
         decode_success_mask.select_n(e_bytes.data(), maybe_e.to_bytes().data(), m_key->s().data(), m_key->s().size());

         auto hash_func = m_key->params().hash_func();
         hash_func->update(decode_success_mask.select(1, 0));
         hash_func->update(e_bytes);
         hash_func->update(encapsulated_key);

         std::ranges::copy(hash_func->final_stdvec(), out_shared_key.begin());
      }

   private:
      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> m_key;
};

//------------------------------------------------------------------------------------------------------
namespace {
bitvector cmce_encode(const Classic_McEliece_Parameters& params,
                      const secure_bitvector& e,
                      const Classic_McEliece_Matrix& mat) {
   return mat.mul(params, e);
}

std::pair<CT::Mask<uint8_t>, secure_bitvector> cmce_decode(const Classic_McEliece_PrivateKeyInternal& sk,
                                                           bitvector big_c) {
   big_c.resize(sk.params().n());

   auto syndrome = compute_goppa_syndrome(sk.params(), sk.g(), sk.alpha(), big_c.as_locked());
   auto locator = berlekamp_massey(sk.params(), syndrome);

   std::vector<Classic_McEliece_GF> images;
   //TODO: Avoid alpha().alphas()
   auto alphas = sk.alpha().alphas();
   auto n_alphas = std::ranges::subrange(alphas.begin(), alphas.begin() + sk.params().n());
   std::transform(
      n_alphas.begin(), n_alphas.end(), std::back_inserter(images), [&](const auto& alpha) { return locator(alpha); });

   // Obtain e and check whether wt(e) = t
   secure_bitvector e;
   size_t hamming_weight_e = 0;
   auto decode_success = CT::Mask<uint8_t>::set();  // Avoid bool to avoid compiler optimizations
   for(auto& image : images) {
      auto is_zero_mask = CT::Mask<uint16_t>::is_zero(image.elem());
      e.push_back(is_zero_mask.as_bool());
      hamming_weight_e += is_zero_mask.if_set_return(1);
   }
   decode_success &= CT::Mask<uint8_t>::is_equal(hamming_weight_e, sk.params().t());

   // Check the error vector
   auto syndrome_from_e = compute_goppa_syndrome(sk.params(), sk.g(), sk.alpha(), e);
   auto syndromes_are_eq = CT::Mask<uint16_t>::set();
   for(size_t i = 0; i < syndrome.size(); ++i) {
      syndromes_are_eq &= CT::Mask<uint16_t>::is_equal(syndrome.at(i).elem(), syndrome_from_e.at(i).elem());
   }

   decode_success &= syndromes_are_eq;

   return std::make_pair(decode_success, std::move(e));
}

}  // namespace

std::vector<Classic_McEliece_GF> compute_goppa_syndrome(const Classic_McEliece_Parameters& params,
                                                        const Classic_McEliece_Minimal_Polynomial& goppa_poly,
                                                        const Classic_McEliece_Field_Ordering& ordering,
                                                        const secure_bitvector& code_word) {
   BOTAN_ASSERT(params.n() == code_word.size(), "Correct code word size");
   std::vector<Classic_McEliece_GF> syndrome(2 * params.t(), Classic_McEliece_GF(0, params.poly_f()));

   auto all_alphas = ordering.alphas();
   auto n_alphas = std::span(all_alphas).subspan(0, params.n());

   for(size_t i = 0; i < params.n(); ++i) {
      auto e = goppa_poly(n_alphas[i]);
      auto e_inv = (e * e).inv();

      auto c_mask = CT::Mask<uint16_t>::expand(code_word.at(i));

      // TODO: Is this CT for all compiler optimizations? A smart compiler could skip the XOR if code_word[i] == 0.
      for(size_t j = 0; j < 2 * params.t(); ++j) {
         syndrome.at(j) = (syndrome.at(j).elem() ^ c_mask.if_set_return(e_inv.elem()));
         e_inv = e_inv * n_alphas[i];
      }
   }

   return syndrome;
}

Classic_McEliece_Polynomial berlekamp_massey(const Classic_McEliece_Parameters& params,
                                             const std::vector<Classic_McEliece_GF>& syndrome) {
   std::vector<Classic_McEliece_GF> output(params.t() + 1, Classic_McEliece_GF(0, params.poly_f()));

   std::vector<Classic_McEliece_GF> big_t(params.t() + 1, Classic_McEliece_GF(0, params.poly_f()));
   std::vector<Classic_McEliece_GF> big_c(params.t() + 1, Classic_McEliece_GF(0, params.poly_f()));
   std::vector<Classic_McEliece_GF> big_b(params.t() + 1, Classic_McEliece_GF(0, params.poly_f()));
   auto b = Classic_McEliece_GF(1, params.poly_f());

   //
   big_b.at(1) = 1;
   big_c.at(0) = 1;

   //

   for(size_t big_n = 0, big_l = 0; big_n < 2 * params.t(); ++big_n) {
      auto d = Classic_McEliece_GF(0, params.poly_f());

      for(size_t i = 0; i <= std::min(big_n, params.t()); ++i) {
         d += big_c.at(i) * syndrome.at(big_n - i);
      }

      auto mne = CT::Mask<size_t>::expand(d.elem());
      auto mle = CT::Mask<size_t>::is_lte(2 * big_l, big_n);
      mle &= mne;

      big_t = big_c;  // Copy
      auto f = d / b;

      for(size_t i = 0; i <= params.t(); ++i) {
         //TODO: Integrate CT below into Classic_McEliece_GF
         big_c.at(i) = big_c.at(i).elem() ^ CT::Mask<uint16_t>(mne).if_set_return((f * big_b.at(i)).elem());
      }

      big_l = mle.select((big_n + 1) - big_l, big_l);

      for(size_t i = 0; i <= params.t(); ++i) {
         big_b.at(i) = CT::Mask<uint16_t>(mle).select(big_t.at(i).elem(), big_b.at(i).elem());
      }

      b = CT::Mask<uint16_t>(mle).select(d.elem(), b.elem());

      for(size_t i = params.t(); i >= 1; --i) {
         big_b.at(i) = big_b.at(i - 1);
      }
      big_b.at(0) = 0;
   }

   std::reverse(big_c.begin(), big_c.end());

   return Classic_McEliece_Polynomial(big_c);
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
      auto beta = field.create_element_from_bytes(irreducible_seed);
      auto g = compute_minimal_polynomial(params, beta);  //TODO: Check if degree is t and optional return?

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
std::optional<secure_bitvector> cmce_fixed_weight_vector_gen(const Classic_McEliece_Parameters& params,
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

   secure_bitvector e(params.n());

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
   secure_bitvector e;
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
   auto sk_internal = Classic_McEliece_PrivateKeyInternal::from_bytes(params, sk);
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
