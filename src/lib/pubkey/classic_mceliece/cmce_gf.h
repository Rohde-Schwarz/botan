/*
* Classic McEliece GF arithmetic
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_GF_H_
#define BOTAN_CMCE_GF_H_

#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

#include <bitset>

namespace Botan {

//Implements FF_q via FF_2[z]/f(z)
class BOTAN_TEST_API Classic_McEliece_GF {
   public:
      Classic_McEliece_GF(uint16_t elem, uint16_t modulus) : m_elem(elem), m_modulus(modulus) {
         m_elem &= ((size_t(1) << log_q()) - 1);
      }

      static size_t log_q(u_int16_t modulus) { return high_bit(modulus) - 1; }

      /**
       * @brief If q is the field order this returns m s.t. 2^m = q.
       */
      size_t log_q() const { return log_q(m_modulus); }

      uint16_t elem() const { return m_elem; }

      uint16_t modulus() const { return m_modulus; }

      Classic_McEliece_GF& operator=(const uint16_t elem) {
         m_elem = elem & ((size_t(1) << log_q()) - 1);
         return *this;
      }

      Classic_McEliece_GF operator/(const Classic_McEliece_GF& other) const;

      Classic_McEliece_GF operator+(const Classic_McEliece_GF& other) const;

      Classic_McEliece_GF& operator+=(const Classic_McEliece_GF& other);

      Classic_McEliece_GF& operator^=(uint16_t other);

      Classic_McEliece_GF& operator*=(const Classic_McEliece_GF& other);

      Classic_McEliece_GF operator*(const Classic_McEliece_GF& other) const;

      bool operator==(const Classic_McEliece_GF& other) const { return elem() == other.elem(); }

      Classic_McEliece_GF square() const;

      Classic_McEliece_GF inv() const;

   private:
      uint16_t m_elem;

      uint16_t m_modulus;
};

class GF_Mask final {
   public:
      static GF_Mask expand(const Classic_McEliece_GF& v) { return GF_Mask(CT::Mask<uint16_t>::expand(v.elem())); }

      static GF_Mask is_lte(const Classic_McEliece_GF& a, const Classic_McEliece_GF& b) {
         return GF_Mask(CT::Mask<uint16_t>::is_lte(a.elem(), b.elem()));
      }

      static GF_Mask is_equal(Classic_McEliece_GF a, Classic_McEliece_GF b) {
         return GF_Mask(CT::Mask<uint16_t>::is_equal(a.elem(), b.elem()));
      }

      static GF_Mask set() { return GF_Mask(CT::Mask<uint16_t>::set()); }

      GF_Mask(CT::Mask<uint16_t> underlying_mask) : m_mask(underlying_mask) {}

      Classic_McEliece_GF if_set_return(const Classic_McEliece_GF& x) const {
         return Classic_McEliece_GF(m_mask.if_set_return(x.elem()), x.modulus());
      }

      Classic_McEliece_GF select(const Classic_McEliece_GF& x, const Classic_McEliece_GF& y) const {
         return Classic_McEliece_GF(m_mask.select(x.elem(), y.elem()), x.modulus());
      }

      GF_Mask& operator&=(const GF_Mask& o) {
         m_mask &= o.m_mask;
         return (*this);
      }

      CT::Mask<uint16_t>& elem_mask() { return m_mask; }

   private:
      CT::Mask<uint16_t> m_mask;
};

}  // namespace Botan
#endif
