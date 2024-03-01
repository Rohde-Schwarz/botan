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

#include <botan/internal/kyber_algos.h>
#include <botan/internal/loadstor.h>

namespace Botan::Kyber {

void PolynomialSampler::cbd2(Poly& poly) {
   const auto randomness = prf(2 * poly.size() / 4);

   BufferSlicer bs(randomness);
   for(size_t i = 0; i < poly.size() / 8; ++i) {
      uint32_t t = load_le(bs.take<4>());
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

namespace {

// Note: load_le<> does not support loading a 3-byte value
uint32_t load_le(std::span<const uint8_t, 3> in) {
   return make_uint32(0, in[2], in[1], in[0]);
};

}  // namespace

void PolynomialSampler::cbd3(Poly& poly) {
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

}  // namespace Botan::Kyber
