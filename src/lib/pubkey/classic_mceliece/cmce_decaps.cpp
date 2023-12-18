/*
* Classic McEliece Decapsulation
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/cmce_decaps.h>

namespace Botan {

std::vector<Classic_McEliece_GF> Classic_McEliece_Decryptor::compute_goppa_syndrome(
   const Classic_McEliece_Parameters& params,
   const Classic_McEliece_Minimal_Polynomial& goppa_poly,
   const Classic_McEliece_Field_Ordering& ordering,
   const secure_bitvector& code_word) {
   BOTAN_ASSERT(params.n() == code_word.size(), "Correct code word size");
   std::vector<Classic_McEliece_GF> syndrome(2 * params.t(), params.gf(0));

   auto all_alphas = ordering.alphas();
   auto n_alphas = std::span(all_alphas).subspan(0, params.n());

   for(size_t i = 0; i < params.n(); ++i) {
      auto e = goppa_poly(n_alphas[i]);
      auto e_inv = (e * e).inv();

      auto c_mask = GF_Mask(CT::Mask<uint16_t>::expand(code_word.at(i)));

      // TODO: Is this CT for all compiler optimizations? A smart compiler could skip the XOR if code_word[i] == 0.
      for(size_t j = 0; j < 2 * params.t(); ++j) {
         syndrome.at(j) += c_mask.if_set_return(e_inv);
         e_inv = e_inv * n_alphas[i];
      }
   }

   return syndrome;
}

Classic_McEliece_Polynomial Classic_McEliece_Decryptor::berlekamp_massey(
   const Classic_McEliece_Parameters& params, const std::vector<Classic_McEliece_GF>& syndrome) {
   std::vector<Classic_McEliece_GF> output(params.t() + 1, params.gf(0));

   std::vector<Classic_McEliece_GF> big_t(params.t() + 1, params.gf(0));
   std::vector<Classic_McEliece_GF> big_c(params.t() + 1, params.gf(0));
   std::vector<Classic_McEliece_GF> big_b(params.t() + 1, params.gf(0));
   auto b = params.gf(1);

   big_b.at(1) = 1;
   big_c.at(0) = 1;

   for(size_t big_n = 0, big_l = 0; big_n < 2 * params.t(); ++big_n) {
      auto d = params.gf(0);

      for(size_t i = 0; i <= std::min(big_n, params.t()); ++i) {
         d += big_c.at(i) * syndrome.at(big_n - i);
      }

      auto mne = GF_Mask::expand(d);
      auto mle = GF_Mask(CT::Mask<uint16_t>::is_lte(2 * big_l, big_n));
      mle &= mne;

      big_t = big_c;  // Copy
      auto f = d / b;

      for(size_t i = 0; i <= params.t(); ++i) {
         //TODO: Integrate CT below into Classic_McEliece_GF
         big_c.at(i) += mne.if_set_return((f * big_b.at(i)));
      }

      big_l = mle.elem_mask().select((big_n + 1) - big_l, big_l);

      for(size_t i = 0; i <= params.t(); ++i) {
         big_b.at(i) = mle.select(big_t.at(i), big_b.at(i));
      }

      b = mle.select(d, b);

      // Rotate big_b one to the right
      std::rotate(big_b.rbegin(), big_b.rbegin() + 1, big_b.rend());
   }

   std::reverse(big_c.begin(), big_c.end());

   return Classic_McEliece_Polynomial(big_c);
}

std::pair<CT::Mask<uint8_t>, secure_bitvector> Classic_McEliece_Decryptor::decode(
   const Classic_McEliece_PrivateKeyInternal& sk, bitvector big_c) {
   BOTAN_ASSERT(big_c.size() == sk.params().m() * sk.params().t(), "Correct ciphertext input size");
   big_c.resize(sk.params().n());

   auto syndrome = compute_goppa_syndrome(sk.params(), sk.g(), sk.field_ordering(), big_c.as_locked());
   auto locator = berlekamp_massey(sk.params(), syndrome);

   std::vector<Classic_McEliece_GF> images;
   //TODO: Avoid alpha().alphas() -> field_ordering().alphas()
   auto alphas = sk.field_ordering().alphas();
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
   auto syndrome_from_e = compute_goppa_syndrome(sk.params(), sk.g(), sk.field_ordering(), e);
   auto syndromes_are_eq = CT::Mask<uint16_t>::set();
   for(size_t i = 0; i < syndrome.size(); ++i) {
      syndromes_are_eq &= GF_Mask::is_equal(syndrome.at(i), syndrome_from_e.at(i)).elem_mask();
   }

   decode_success &= syndromes_are_eq;

   return std::make_pair(decode_success, std::move(e));
}

void Classic_McEliece_Decryptor::kem_decrypt(std::span<uint8_t> out_shared_key,
                                             std::span<const uint8_t> encapsulated_key,
                                             size_t desired_shared_key_len,  // TODO: Whats up with these?
                                             std::span<const uint8_t> salt) {
   BOTAN_UNUSED(desired_shared_key_len, salt);
   // TODO: Throw exception on failure
   BOTAN_ASSERT(encapsulated_key.size() == m_key->params().ciphertext_size(), "Correct encapsulated key length");
   BOTAN_ASSERT(out_shared_key.size() == m_key->params().hash_out_bytes(), "Correct shared key output length");

   bitvector ct;
   std::span<const uint8_t> c1;
   if(m_key->params().is_pc()) {
      BufferSlicer encaps_key_slicer(encapsulated_key);
      auto c0 = encaps_key_slicer.take(m_key->params().encode_out_size());
      c1 = encaps_key_slicer.take(m_key->params().hash_out_bytes());
      BOTAN_ASSERT_NOMSG(encaps_key_slicer.empty());
      ct = bitvector(c0, m_key->params().m() * m_key->params().t());
   } else {
      ct = bitvector(encapsulated_key, m_key->params().m() * m_key->params().t());
   }

   auto [decode_success_mask, maybe_e] = decode(*m_key, ct);

   secure_vector<uint8_t> e_bytes(m_key->s().size());
   decode_success_mask.select_n(e_bytes.data(), maybe_e.to_bytes().data(), m_key->s().data(), m_key->s().size());
   uint8_t b = decode_success_mask.select(1, 0);

   auto hash_func = m_key->params().hash_func();

   if(m_key->params().is_pc()) {
      hash_func->update(2);
      hash_func->update(e_bytes);
      auto c1_p = hash_func->final_stdvec();
      CT::Mask<uint8_t> eq_mask = CT::is_equal(c1.data(), c1_p.data(), c1.size());
      eq_mask.select_n(e_bytes.data(), e_bytes.data(), m_key->s().data(), m_key->s().size());
      b = eq_mask.select(b, 0);
   }

   hash_func->update(b);
   hash_func->update(e_bytes);
   hash_func->update(encapsulated_key);

   std::ranges::copy(hash_func->final_stdvec(), out_shared_key.begin());
}

}  // namespace Botan