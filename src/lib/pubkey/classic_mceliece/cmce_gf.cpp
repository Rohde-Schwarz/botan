/*
* Classic McEliece GF arithmetic
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/cmce_gf.h>

namespace Botan {

Classic_McEliece_GF Classic_McEliece_GF::operator/(const Classic_McEliece_GF& other) const {
   return *this * other.inv();
}

Classic_McEliece_GF Classic_McEliece_GF::operator+(const Classic_McEliece_GF& other) const {
   BOTAN_ASSERT_NOMSG(m_modulus == other.m_modulus);
   return Classic_McEliece_GF(m_elem ^ other.m_elem, m_modulus);
}

Classic_McEliece_GF& Classic_McEliece_GF::operator+=(const Classic_McEliece_GF& other) {
   BOTAN_ASSERT_NOMSG(m_modulus == other.m_modulus);
   m_elem ^= other.m_elem;
   return *this;
}

Classic_McEliece_GF& Classic_McEliece_GF::operator^=(uint16_t other) {
   m_elem ^= other;
   return *this;
}

Classic_McEliece_GF& Classic_McEliece_GF::operator*=(const Classic_McEliece_GF& other) {
   BOTAN_ASSERT_NOMSG(m_modulus == other.m_modulus);
   *this = *this * other;
   return *this;
}

Classic_McEliece_GF Classic_McEliece_GF::operator*(const Classic_McEliece_GF& other) const {
   BOTAN_ASSERT_NOMSG(m_modulus == other.m_modulus);

   uint16_t result = 0;
   uint16_t a = m_elem;
   uint16_t b = other.m_elem;

   size_t m = log_q();

   for(size_t i = 0; i < m; i++) {
      // XOR a with result if the LSB of b is 1
      result ^= CT::Mask<uint16_t>::expand(b & 1).if_set_return(a);

      a <<= 1;  // Left shift a

      // XOR a with the modulus if there was a carry
      a ^= CT::Mask<uint16_t>::expand(a >> m).if_set_return(m_modulus);

      b >>= 1;  // Right shift b
   }
   return Classic_McEliece_GF(result, m_modulus);
}

Classic_McEliece_GF Classic_McEliece_GF::square() const {
   // TODO: Optimize
   return (*this) * (*this);
}

Classic_McEliece_GF Classic_McEliece_GF::inv() const {
   size_t exponent = (1 << log_q()) - 2;  // This is public information
   Classic_McEliece_GF base = *this;

   Classic_McEliece_GF result = {1, m_modulus};
   while(exponent > 0) {
      if(exponent % 2 == 1) {
         // multiply
         result = (result * base);
      }
      // square
      base = base.square();
      exponent /= 2;
   }

   return result;
}
}  // namespace Botan
