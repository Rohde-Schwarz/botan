/*
 * Crystals Kyber Internal Algorithms
 * Based on the public domain reference implementation by the
 * designers (https://github.com/pq-crystals/kyber)
 *
 * Further changes
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_KYBER_ALGOS_H_
#define BOTAN_KYBER_ALGOS_H_

#include <botan/xof.h>
#include <botan/internal/fmt.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/pqcrystals.h>

namespace Botan {

using KyberPolyNTT = CRYSTALS::Polynomial<New_Kyber_Constants, CRYSTALS::Domain::NTT>;
using KyberPolyVecNTT = CRYSTALS::PolynomialVector<New_Kyber_Constants, CRYSTALS::Domain::NTT>;
using KyberPolyMat = CRYSTALS::PolynomialMatrix<New_Kyber_Constants>;

using KyberPoly = CRYSTALS::Polynomial<New_Kyber_Constants, CRYSTALS::Domain::Normal>;
using KyberPolyVec = CRYSTALS::PolynomialVector<New_Kyber_Constants, CRYSTALS::Domain::Normal>;

/**
 * NIST FIPS 203 IPD, Algorithm 6 (SampleNTT)
 */
inline void sample_ntt_uniform(KyberPolyNTT& p, std::unique_ptr<XOF> xof) {
   size_t count = 0;
   while(count < p.size()) {
      std::array<uint8_t, 3> buf;
      xof->output(buf);  // TODO: Pulling bytes in bigger chunks might yield better performance

      const uint16_t d1 = ((buf[0] >> 0) | (static_cast<uint16_t>(buf[1]) << 8)) & 0xFFF;
      const uint16_t d2 = ((buf[1] >> 4) | (static_cast<uint16_t>(buf[2]) << 4)) & 0xFFF;

      if(d1 < KyberConstants::Q) {
         p[count++] = d1;
      }
      if(count < p.size() && d2 < KyberConstants::Q) {
         p[count++] = d2;
      }
   }
}

inline KyberPolyMat sample_matrix(StrongSpan<const KyberSeedRho> seed,
                                  const bool transposed,
                                  const KyberConstants& mode) {
   BOTAN_ASSERT(seed.size() == KyberConstants::kSymBytes, "unexpected seed size");

   KyberPolyMat mat(mode.k(), mode.k());

   for(uint8_t i = 0; i < mode.k(); ++i) {
      for(uint8_t j = 0; j < mode.k(); ++j) {
         const auto pos = (transposed) ? std::tuple(i, j) : std::tuple(j, i);
         sample_ntt_uniform(mat[i][j], mode.symmetric_primitives().XOF(seed, pos));
      }
   }

   return mat;
}

/**
 * Allows sampling multiple polynomials from a single seed and takes care of the
 * nonce value internally.
 */
class PolynomialSampler {
   public:
      PolynomialSampler(KyberSeedSigma seed, const KyberConstants& mode) :
            m_seed(std::move(seed)), m_mode(mode), m_nonce(0) {}

      KyberPolyVec sample_vector_eta1() {
         KyberPolyVec vec(m_mode.k());
         for(auto& poly : vec) {
            sample_poly_eta1(poly);
         }
         return vec;
      }

   private:
      KyberSamplingRandomness prf(size_t bytes) { return m_mode.symmetric_primitives().PRF(m_seed, m_nonce++, bytes); }

      /**
       * NIST FIPS 203 IPD, Algorithm 7 (SamplePolyCBD)
       */
      void sample_poly_eta1(KyberPoly& poly) {
         const auto eta1 = m_mode.eta1();

         if(eta1 == 2) {
            cbd2(poly);
         } else if(eta1 == 3) {
            cbd3(poly);
         } else {
            throw Invalid_Argument("Invalid eta1 value");
         }
      }

      void cbd2(KyberPoly& poly);
      void cbd3(KyberPoly& poly);

   private:
      KyberSeedSigma m_seed;
      const KyberConstants& m_mode;
      uint8_t m_nonce;
};

}  // namespace Botan

#endif
