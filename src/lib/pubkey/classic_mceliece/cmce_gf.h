/*
* Classic McEliece GF arithmetic
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
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

/**
 * @brief Represents an element of the finite field GF(q) for q = 2^m.
 *
 * This class implements the finite field GF(q) for q = 2^m via the irreducible
 * polynomial f(z) of degree m. The elements of GF(q) are represented as polynomials
 * of degree m-1 with coefficients in GF(2). Each element and the modulus is
 * represented by a uint16_t, where the i-th least significant bit corresponds to
 * the coefficient of z^i. For example, the element (z^3 + z^2 + 1) is represented
 * by the uint16_t 0b1101.
 */
class BOTAN_TEST_API Classic_McEliece_GF {
   public:
      /**
       * @brief Creates an element of GF(q) from a uint16_t.
       *
       * Each element and the modulus is represented by a uint16_t, where the i-th least significant bit
       * corresponds to the coefficient of z^i.
       *
       * @param elem The element as a uint16_t.
       * @param modulus The modulus of GF(q).
       */
      Classic_McEliece_GF(uint16_t elem, uint16_t modulus) : m_elem(elem), m_modulus(modulus) {
         m_elem &= ((size_t(1) << log_q()) - 1);
      }

      /**
       * @brief Get m.
       *
       * For a given irreducible polynomial @p modulus f(z) representing the modulus of a finite field GF(q) = GF(2^m),
       * get the degree log_q of f(z) which corresponds to m.
       *
       * @param modulus The modulus of GF(q).
       * @return size_t The degree log_q of the modulus (m for GF(2^m)).
       */
      static size_t log_q(u_int16_t modulus) { return high_bit(modulus) - 1; }

      /**
       * @brief Get m.
       *
       * For a given irreducible polynomial @p modulus f(z) representing the modulus of a finite field GF(q) = GF(2^m),
       * get the degree log_q of f(z) which corresponds to m.
       *
       * @param modulus The modulus of GF(q).
       * @return size_t The degree log_q of the modulus (m for GF(2^m)).
       */
      size_t log_q() const { return log_q(m_modulus); }

      /**
       * @brief Get the GF(q) element as a uint16_t.
       *
       * @return the element as a uint16_t.
       */
      uint16_t elem() const { return m_elem; }

      /**
       * @brief Get the modulus f(z) of GF(q) as a uint16_t.
       *
       * @return the modulus as a uint16_t.
       */
      uint16_t modulus() const { return m_modulus; }

      /**
       * @brief Change the element to @param elem.
       */
      Classic_McEliece_GF& operator=(const uint16_t elem) {
         m_elem = elem & ((size_t(1) << log_q()) - 1);
         return *this;
      }

      /**
       * @brief Divide the element by @param other in GF(q). Constant time.
       */
      Classic_McEliece_GF operator/(const Classic_McEliece_GF& other) const;

      /**
       * @brief Add @param other to the element. Constant time.
       */
      Classic_McEliece_GF operator+(const Classic_McEliece_GF& other) const;

      /**
       * @brief Add @param other to the element. Constant time.
       */
      Classic_McEliece_GF& operator+=(const Classic_McEliece_GF& other);

      /**
       * @brief XOR assign an uint16_t to the element of this. Constant time.
       */
      Classic_McEliece_GF& operator^=(uint16_t other);

      /**
       * @brief Multiply the element by @param other in GF(q). Constant time.
       */
      Classic_McEliece_GF& operator*=(const Classic_McEliece_GF& other);

      /**
       * @brief Multiply the element by @param other in GF(q). Constant time.
       */
      Classic_McEliece_GF operator*(const Classic_McEliece_GF& other) const;

      /**
       * @brief Check if the element is equal to @param other. Modulus is ignored.
       */
      bool operator==(const Classic_McEliece_GF& other) const { return elem() == other.elem(); }

      /**
       * @brief Square the element. Constant time.
       */
      Classic_McEliece_GF square() const;

      /**
       * @brief Invert the element. Constant time.
       */
      Classic_McEliece_GF inv() const;

   private:
      uint16_t m_elem;

      uint16_t m_modulus;
};

/**
 * @brief Constant time mask wrapper for GF(q) elements.
 */
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
