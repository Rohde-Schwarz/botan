/*
* Classic McEliece Polynomials
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_POLY_H_
#define BOTAN_CMCE_POLY_H_

#include <botan/cmce_parameters.h>
#include <botan/secmem.h>
#include <botan/internal/cmce_gf.h>
#include <botan/internal/loadstor.h>

namespace Botan {

class Classic_McEliece_Polynomial_Ring;

namespace concepts::details {
template <typename Ring, typename Elem>
concept HasMult = requires(Ring r, Elem a, Elem b, Elem c) {
                     { r.multiply(a, b) } -> std::same_as<Elem>;
                  };

}

// Implements minimal polynomial g over FF_q.
// The coefficient x^t is stored implicitly
// g = coef[0] + coef[1]*x + ... + coef[t-1]*x^(t-1) + x^t
// class BOTAN_TEST_API Classic_McEliece_Minimal_Polynomial {
//    public:
//       Classic_McEliece_Minimal_Polynomial(std::vector<Classic_McEliece_GF> coef) : m_coef(std::move(coef)) {}

//       // Evaluates the polynomial on a
//       Classic_McEliece_GF operator()(const Classic_McEliece_GF& a) const;

//       // t is the degree of the polynomial, but we only store coefs for x^0, x^1, ..., x^(t-1) since there is always coef[t] = 1
//       size_t degree() const { return m_coef.size(); }

//       const Classic_McEliece_GF& coef_at(size_t i) const { return m_coef.at(i); }

//       const std::vector<Classic_McEliece_GF>& coef() const { return m_coef; }

//       secure_vector<uint8_t> to_bytes() const;

//       static Classic_McEliece_Minimal_Polynomial from_bytes(std::span<const uint8_t> bytes, uint16_t poly_f);

//    private:
//       std::vector<Classic_McEliece_GF> m_coef;
// };

//Implements FF_(q^t) via FF_q[y]/F(y)
// TODO: Do we want to create any hierarchy/connection between CMCE_Polynomial and CMCE_Minimal_Polynomial?
template <typename PolyRing>
class BOTAN_TEST_API Classic_McEliece_Polynomial_Base {
   public:
      Classic_McEliece_Polynomial_Base(std::vector<Classic_McEliece_GF> coef, std::shared_ptr<const PolyRing> ring) :
            m_coef(std::move(coef)), m_ring(std::move(ring)) {}

      //std::optional<Classic_McEliece_Minimal_Polynomial_Base> compute_minimal_polynomial() const;

      Classic_McEliece_GF operator()(const Classic_McEliece_GF& a) const {
         BOTAN_ASSERT(a.modulus() == coef_at(0).modulus(), "Unmatching Galois fields");

         Classic_McEliece_GF r(0, a.modulus());
         for(auto it = m_coef.rbegin(); it != m_coef.rend(); ++it) {
            r *= a;
            r += *it;
         }

         return r;
      }

      // TODO: Pass ring to multiplication and drop template param.
      Classic_McEliece_Polynomial_Base operator*(const Classic_McEliece_Polynomial_Base& other) const
         requires concepts::details::HasMult<PolyRing, Classic_McEliece_Polynomial_Base<PolyRing>>
      {
         return m_ring->multiply(*this, other);
      }

      bool operator==(const Classic_McEliece_Polynomial_Base<PolyRing>& other) const {
         bool res = true;
         for(size_t i = 0; i < m_coef.size(); ++i) {
            res = res && m_coef.at(i) == other.m_coef.at(i);
         }
         return res;
      }

      std::shared_ptr<const PolyRing> ring() const { return m_ring; }

      Classic_McEliece_GF& coef_at(size_t i) { return m_coef.at(i); }

      const Classic_McEliece_GF& coef_at(size_t i) const { return m_coef.at(i); }

      const std::vector<Classic_McEliece_GF>& coef() const { return m_coef; }

      size_t degree() const { return m_coef.size() + 1; }

   private:
      std::vector<Classic_McEliece_GF> m_coef;
      std::shared_ptr<const PolyRing> m_ring;
};

// Stores all auxiliary information and logic of FF_(q^t) via FF_q[y]/F(y)
class BOTAN_TEST_API Classic_McEliece_Polynomial_Ring
      : public std::enable_shared_from_this<Classic_McEliece_Polynomial_Ring> {
   public:
      struct BOTAN_TEST_API Big_F_Coefficient {
            size_t idx;
            Classic_McEliece_GF coeff;
      };

      Classic_McEliece_Polynomial_Ring(const std::vector<Big_F_Coefficient>& poly_big_f_coef,
                                       uint16_t poly_f,
                                       size_t t) :
            m_position_map(poly_big_f_coef), m_t(t), m_poly_f(poly_f) {}

      bool operator==(const Classic_McEliece_Polynomial_Ring& other) const;

      uint16_t poly_f() const { return m_poly_f; }

      size_t t() const { return m_t; }

      Classic_McEliece_Polynomial_Base<Classic_McEliece_Polynomial_Ring> multiply(
         const Classic_McEliece_Polynomial_Base<Classic_McEliece_Polynomial_Ring>& a,
         const Classic_McEliece_Polynomial_Base<Classic_McEliece_Polynomial_Ring>& b) const;

      Classic_McEliece_Polynomial_Base<Classic_McEliece_Polynomial_Ring> create_element_from_bytes(
         std::span<const uint8_t> bytes) const;

      // TODO: create_elements_from_coef should be private / max. be accessible for tests.
      Classic_McEliece_Polynomial_Base<Classic_McEliece_Polynomial_Ring> create_element_from_coef(
         std::vector<Classic_McEliece_GF> coeff_vec) const;

      Classic_McEliece_Polynomial_Base<Classic_McEliece_Polynomial_Ring> create_element_from_coef(
         std::vector<uint16_t> coeff_vec) const;

   private:
      /// Represents F(y) by storing the non-zero terms
      std::vector<Big_F_Coefficient> m_position_map;

      /// t in spec, i.e., degree of F(y)
      size_t m_t;

      // f(z) in spec
      uint16_t m_poly_f;
};

using Classic_McEliece_Polynomial = Classic_McEliece_Polynomial_Base<Classic_McEliece_Polynomial_Ring>;

class BOTAN_TEST_API Minimal_Polynomial_Ring {
      // Multiplication for the minimal Polynomial Ring is not supported
};

using Classic_McEliece_Minimal_Polynomial = Classic_McEliece_Polynomial_Base<Minimal_Polynomial_Ring>;

bool operator==(const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& first,
                const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& second);

std::optional<Classic_McEliece_Minimal_Polynomial> compute_minimal_polynomial(const Classic_McEliece_Polynomial& f);

secure_vector<uint8_t> to_bytes(const Classic_McEliece_Minimal_Polynomial& poly);

Classic_McEliece_Minimal_Polynomial from_bytes(std::span<const uint8_t> bytes, uint16_t poly_f);

}  // namespace Botan
#endif
