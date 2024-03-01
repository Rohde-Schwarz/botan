/*
 * Crystals Kyber Internal Key Types
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_keys.h>

#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, Kyber::PolyVecNTT t, KyberSeedRho rho) :
      m_mode(std::move(mode)),
      m_t(std::move(t)),
      m_rho(std::move(rho)),
      m_public_key_bits_raw(concat(Kyber::to_bytes<std::vector<uint8_t>>(m_t), m_rho)),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)) {}

/**
 * NIST FIPS 203 IPD, Algorithm 13 (K-PKE.Encrypt)
 */
Ciphertext Kyber_PublicKeyInternal::indcpa_encrypt(StrongSpan<const KyberMessage> m,
                                                   StrongSpan<const KyberEncryptionRandomness> r) const {
   const auto At = Kyber::sample_matrix(m_rho, true /* transposed */, m_mode);

   Kyber::PolynomialSampler ps(r, m_mode);

   const auto rv = ntt(ps.sample_vector_eta1());
   const auto e1 = ps.sample_vector_eta2();
   const auto e2 = ps.sample_poly_eta2();

   auto u = (inverse_ntt(At * rv) + e1).reduce();

   const auto mu = Kyber::from_message(m);
   auto v = (inverse_ntt(m_t * rv) + e2 + mu).reduce();

   return Ciphertext(std::move(u), std::move(v), m_mode);
}

/**
 * NIST FIPS 203 IPD, Algorithm 14 (K-PKE.Decrypt)
 */
KyberMessage Kyber_PrivateKeyInternal::indcpa_decrypt(Ciphertext ct) const {
   auto& u = ct.b();
   const auto& v = ct.v();

   u.ntt();
   auto w = PolynomialVector::pointwise_acc_montgomery(m_s, u);
   w.invntt_tomont();

   w -= v;
   w.reduce();
   return w.to_message();
}

}  // namespace Botan
