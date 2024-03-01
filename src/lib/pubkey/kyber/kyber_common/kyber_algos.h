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
#include <botan/internal/loadstor.h>
#include <botan/internal/pqcrystals.h>

namespace Botan::Kyber {

using PolyNTT = Botan::CRYSTALS::Polynomial<New_Kyber_Constants, Botan::CRYSTALS::Domain::NTT>;
using PolyVecNTT = Botan::CRYSTALS::PolynomialVector<New_Kyber_Constants, Botan::CRYSTALS::Domain::NTT>;
using PolyMat = Botan::CRYSTALS::PolynomialMatrix<New_Kyber_Constants>;

using Poly = Botan::CRYSTALS::Polynomial<New_Kyber_Constants, Botan::CRYSTALS::Domain::Normal>;
using PolyVec = Botan::CRYSTALS::PolynomialVector<New_Kyber_Constants, Botan::CRYSTALS::Domain::Normal>;

/**
 * NIST FIPS 203 IPD, Algorithm 6 (SampleNTT)
 */
inline void sample_ntt_uniform(PolyNTT& p, std::unique_ptr<XOF> xof) {
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

inline PolyMat sample_matrix(StrongSpan<const KyberSeedRho> seed, const bool transposed, const KyberConstants& mode) {
   BOTAN_ASSERT(seed.size() == KyberConstants::kSymBytes, "unexpected seed size");

   PolyMat mat(mode.k(), mode.k());

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
template <typename SeedT>
   requires std::same_as<KyberSeedSigma, SeedT> || std::same_as<KyberEncryptionRandomness, SeedT>
class PolynomialSampler {
   public:
      PolynomialSampler(StrongSpan<const SeedT> seed, const KyberConstants& mode) :
            m_seed(seed), m_mode(mode), m_nonce(0) {}

      PolyVec sample_vector_eta1() {
         PolyVec vec(m_mode.k());
         for(auto& poly : vec) {
            sample_poly_eta1(poly);
         }
         return vec;
      }

      Poly sample_poly_eta2()
         requires std::same_as<KyberEncryptionRandomness, SeedT>
      {
         Poly poly;
         cbd2(poly);
         return poly;
      }

      PolyVec sample_vector_eta2()
         requires std::same_as<KyberEncryptionRandomness, SeedT>
      {
         PolyVec vec(m_mode.k());
         for(auto& poly : vec) {
            cbd2(poly);
         }
         return vec;
      }

   private:
      KyberSamplingRandomness prf(size_t bytes) { return m_mode.symmetric_primitives().PRF(m_seed, m_nonce++, bytes); }

      /**
       * NIST FIPS 203 IPD, Algorithm 7 (SamplePolyCBD)
       */
      void sample_poly_eta1(Poly& poly) {
         const auto eta1 = m_mode.eta1();

         if(eta1 == 2) {
            cbd2(poly);
         } else if(eta1 == 3) {
            cbd3(poly);
         } else {
            throw Invalid_Argument("Invalid eta1 value");
         }
      }

      // Note: load_le<> does not support loading a 3-byte value
      uint32_t load_le(std::span<const uint8_t, 3> in) { return make_uint32(0, in[2], in[1], in[0]); };

      void cbd2(Poly& poly) {
         const auto randomness = prf(2 * poly.size() / 4);

         BufferSlicer bs(randomness);
         for(size_t i = 0; i < poly.size() / 8; ++i) {
            uint32_t t = Botan::load_le(bs.take<4>());
            uint32_t d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;

            for(size_t j = 0; j < 8; ++j) {
               int16_t a = (d >> (4 * j + 0)) & 0x3;
               int16_t b = (d >> (4 * j + 2)) & 0x3;
               poly[8 * i + j] = a - b;
            }
         }

         BOTAN_ASSERT_NOMSG(bs.empty());
      }

      void cbd3(Poly& poly) {
         const auto randomness = prf(3 * poly.size() / 4);

         BufferSlicer bs(randomness);

         for(size_t i = 0; i < poly.size() / 4; ++i) {
            uint32_t t = load_le(bs.take<3>());
            uint32_t d = t & 0x00249249;
            d += (t >> 1) & 0x00249249;
            d += (t >> 2) & 0x00249249;

            for(size_t j = 0; j < 4; ++j) {
               int16_t a = (d >> (6 * j + 0)) & 0x7;
               int16_t b = (d >> (6 * j + 3)) & 0x7;
               poly[4 * i + j] = a - b;
            }
         }

         BOTAN_ASSERT_NOMSG(bs.empty());
      }

   private:
      StrongSpan<const SeedT> m_seed;
      const KyberConstants& m_mode;
      uint8_t m_nonce;
};

template <typename T>
PolynomialSampler(T, const KyberConstants&) -> PolynomialSampler<T>;

/**
 * NIST FIPS 203 IPD, Algorithm 4 (ByteEncode) for d == 12
 */
inline void to_bytes(std::span<uint8_t> out, const PolyNTT& p) {
   BufferStuffer bs(out);
   for(size_t i = 0; i < p.size() / 2; ++i) {
      const uint16_t t0 = p[2 * i];
      const uint16_t t1 = p[2 * i + 1];
      auto buf = bs.next<3>();
      buf[0] = static_cast<uint8_t>(t0 >> 0);
      buf[1] = static_cast<uint8_t>((t0 >> 8) | (t1 << 4));
      buf[2] = static_cast<uint8_t>(t1 >> 4);
   }
   BOTAN_ASSERT_NOMSG(bs.full());
}

template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
T to_bytes(const PolyVecNTT& vec) {
   T r(vec.size() * KyberConstants::kSerializedPolynomialByteLength);

   BufferStuffer bs(r);
   for(auto& v : vec) {
      to_bytes(bs.next(KyberConstants::kSerializedPolynomialByteLength), v);
   }
   BOTAN_ASSERT_NOMSG(bs.full());

   return r;
}

/**
 * NIST FIPS 203 IPD, Algorithm 4 (ByteDecode) for d == 12
 */
inline void poly_from_bytes(PolyNTT& p, std::span<const uint8_t> a) {
   for(size_t i = 0; i < p.size() / 2; ++i) {
      p[2 * i] = ((a[3 * i + 0] >> 0) | (static_cast<uint16_t>(a[3 * i + 1]) << 8)) & 0xFFF;
      p[2 * i + 1] = ((a[3 * i + 1] >> 4) | (static_cast<uint16_t>(a[3 * i + 2]) << 4)) & 0xFFF;
   }
}

inline PolyVecNTT polyvec_from_bytes(std::span<const uint8_t> a, const KyberConstants& mode) {
   BOTAN_ASSERT(a.size() == mode.polynomial_vector_byte_length(), "wrong byte length for frombytes");

   PolyVecNTT r(mode.k());

   BufferSlicer bs(a);
   for(size_t i = 0; i < mode.k(); ++i) {
      poly_from_bytes(r[i], bs.take(KyberConstants::kSerializedPolynomialByteLength));
   }
   BOTAN_ASSERT_NOMSG(bs.empty());

   return r;
}

inline Poly from_message(StrongSpan<const KyberMessage> msg) {
   BOTAN_ASSERT(msg.size() == KyberConstants::N / 8, "message length must be Kyber_N/8 bytes");

   Poly r;
   for(size_t i = 0; i < r.size() / 8; ++i) {
      for(size_t j = 0; j < 8; ++j) {
         const auto mask = -static_cast<int16_t>((msg[i] >> j) & 1);
         r[8 * i + j] = mask & ((KyberConstants::Q + 1) / 2);
      }
   }
   return r;
}

}  // namespace Botan::Kyber

#endif
