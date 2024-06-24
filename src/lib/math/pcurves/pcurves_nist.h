/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_NIST_REDC_HELPER_H_
#define BOTAN_PCURVES_NIST_REDC_HELPER_H_

#include <botan/internal/mp_core.h>

namespace Botan {

template <size_t OutN, WordType W, size_t N>
constexpr std::array<int64_t, OutN> into_32bit_words(const std::array<W, N>& xw) {
   static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);
   std::array<int64_t, OutN> result = {};
   if constexpr(WordInfo<W>::bits == 32) {
      for(size_t i = 0; i != N; ++i) {
         result[i] = xw[i];
      }
   } else {
      for(size_t i = 0; i != N * 2; ++i) {
         result[i] = static_cast<uint32_t>(xw[i / 2] >> ((i % 2) * 32));
      }
   }
   return result;
}

template <WordType W, size_t N>
   requires(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64)
auto accumulate_with_carry(std::array<int64_t, N * WordInfo<W>::bits / 32 + 1> vs) -> std::pair<std::array<W, N>, W> {
   std::array<W, N> result = {};
   int64_t S = 0;

   for(size_t i = 0; i != vs.size() - 1; ++i) {
      S += vs[i];
      const uint32_t r = static_cast<uint32_t>(S);
      S >>= 32;

      if constexpr(WordInfo<W>::bits == 32) {
         result[i] = r;
      } else {
         result[i / 2] |= static_cast<uint64_t>(r) << (32 * (i % 2));
      }
   };

   const int64_t final_carry = S + vs.back();
   BOTAN_DEBUG_ASSERT(final_carry >= 0);
   return {result, static_cast<W>(final_carry)};
}

}  // namespace Botan

#endif
