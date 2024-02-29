/*
 * PQ CRYSTALS Common Helpers
 *
 * Further changes
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_PQ_CRYSTALS_HELPERS_H_
#define BOTAN_PQ_CRYSTALS_HELPERS_H_

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <tuple>

namespace Botan {

template <std::integral T>
   requires(sizeof(T) <= 4)
using next_longer_int_t =
   std::conditional_t<sizeof(T) == 1, int16_t, std::conditional_t<sizeof(T) == 2, int32_t, int64_t>>;

/**
 * Result structure for the extended Euclidean algorithm
 */
template <std::integral T>
struct eea_result {
      T gcd;
      T u;
      T v;
};

/**
 * Run the extended Euclidean algorithm to find the greatest common divisor of a
 * and b and the Bézout coefficients, u and v.
 */
template <std::integral T>
constexpr eea_result<T> extended_euclidean_algorithm(T a, T b) {
   if(a > b) {
      std::swap(a, b);
   }

   T u1 = 0, v1 = 1, u2 = 1, v2 = 0;

   if(a != b) {
      while(a != 0) {
         const T q = b / a;
         std::tie(a, b) = std::make_tuple(b - q * a, a);
         std::tie(u1, v1, u2, v2) = std::make_tuple(u2, v2, u1 - q * u2, v1 - q * v2);
      }
   }

   return {.gcd = b, .u = u1, .v = v1};
}

/**
 * Calculate the modular multiplacative inverse of q modulo m.
 * By default, this assumes m to be 2^bitlength of T for application in a
 * Montgomery reduction.
 */
template <std::integral T, std::integral T2 = next_longer_int_t<T>>
   requires(sizeof(T) <= 4)
constexpr T modular_inverse(T q, T2 m = T2(1) << sizeof(T) * 8) {
   return static_cast<T>(extended_euclidean_algorithm<T2>(q, m).u);
}

}  // namespace Botan

#endif
