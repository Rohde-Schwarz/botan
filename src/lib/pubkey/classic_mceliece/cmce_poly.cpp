/*
 * Classic McEliece Polynomials
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/cmce_poly.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Classic_McEliece_GF Classic_McEliece_Minimal_Polynomial::operator()(const Classic_McEliece_GF& a) const {
   BOTAN_ASSERT(a.modulus() == coef_at(0).modulus(), "Unmatching Galois fields");

   auto r = Classic_McEliece_GF(1, a.modulus());  // coef for x^t is always 1

   for(int i = degree() - 1; i >= 0; --i) {
      r *= a;
      r += coef_at(i);
   }

   return r;
}

secure_vector<uint8_t> Classic_McEliece_Minimal_Polynomial::to_bytes() const {
   secure_vector<uint8_t> bytes(sizeof(u_int16_t) * m_coef.size());
   BufferStuffer bytes_stuf(bytes);
   for(auto& coef : m_coef) {
      store_le(coef.elem(), bytes_stuf.next(sizeof(u_int16_t)).data());
   }
   BOTAN_ASSERT_NOMSG(bytes_stuf.full());
   return bytes;
}

Classic_McEliece_Minimal_Polynomial Classic_McEliece_Minimal_Polynomial::from_bytes(std::span<const uint8_t> bytes,
                                                                                    uint16_t poly_f) {
   BOTAN_ASSERT_NOMSG(bytes.size() % 2 == 0);
   size_t len = bytes.size() / 2;
   std::vector<uint16_t> coef_vec(len);
   load_le<uint16_t>(coef_vec.data(), bytes.data(), len);
   std::vector<Classic_McEliece_GF> coeff_vec_gf;
   std::transform(coef_vec.begin(), coef_vec.end(), std::back_inserter(coeff_vec_gf), [poly_f](auto& coeff) {
      return Classic_McEliece_GF(coeff, poly_f);
   });
   //TODO: This can be generalized to also cover the Poly field create element functions

   return Classic_McEliece_Minimal_Polynomial(coeff_vec_gf);
}

std::optional<Classic_McEliece_Minimal_Polynomial> Classic_McEliece_Polynomial::compute_minimal_polynomial() const {
   const Classic_McEliece_Polynomial& f = *this;
   std::vector<Classic_McEliece_Polynomial> mat;

   mat.push_back(m_ring->create_element_from_coef(
      concat_as<std::vector<uint16_t>>(std::vector<uint16_t>{1}, std::vector<uint16_t>(ring()->t() - 1, 0))));

   mat.push_back(Classic_McEliece_Polynomial(f));

   for(size_t j = 2; j <= ring()->t(); ++j) {
      mat.push_back(mat.at(j - 1) * f);
   }

   // Gaussian
   for(size_t j = 0; j < ring()->t(); ++j) {
      for(size_t k = j + 1; k < ring()->t(); ++k) {
         auto cond = CT::Mask<uint16_t>::is_zero(mat.at(j).coef_at(j).elem());

         for(size_t c = j; c < ring()->t() + 1; ++c) {
            auto acc = cond.select(mat.at(c).coef_at(k).elem(), 0);
            mat.at(c).coef_at(j) += Classic_McEliece_GF(acc, m_ring->poly_f());
         }
      }

      if(mat.at(j).coef_at(j).elem() == 0) {  // Fail if not systematic. TODO: make an appropriate member function
         return std::nullopt;
      }

      auto inv = mat.at(j).coef_at(j).inv();

      for(size_t c = j; c < ring()->t() + 1; ++c) {
         mat.at(c).coef_at(j) *= inv;
      }

      for(size_t k = 0; k < ring()->t(); ++k) {
         if(k != j) {
            auto t = mat.at(j).coef_at(k);

            for(size_t c = j; c < ring()->t() + 1; ++c) {
               mat.at(c).coef_at(k) += mat.at(c).coef_at(j) * t;
            }
         }
      }
   }

   return Classic_McEliece_Minimal_Polynomial(mat.at(ring()->t()).coef());
}

Classic_McEliece_GF Classic_McEliece_Polynomial::operator()(const Classic_McEliece_GF& a) const {
   BOTAN_ASSERT(a.modulus() == coef_at(0).modulus(), "Unmatching Galois fields");

   Classic_McEliece_GF r(0, a.modulus());
   for(auto it = m_coef.rbegin(); it != m_coef.rend(); ++it) {
      r *= a;
      r += *it;
   }

   return r;
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial::operator*(const Classic_McEliece_Polynomial& other) const {
   return m_ring->multiply(*this, other);
}

bool Classic_McEliece_Polynomial::operator==(const Classic_McEliece_Polynomial& other) const {
   bool res = true;
   for(size_t i = 0; i < m_coef.size(); ++i) {
      res = res && m_coef.at(i) == other.m_coef.at(i);
   }
   return res;
}

bool Classic_McEliece_Polynomial_Ring::operator==(const Classic_McEliece_Polynomial_Ring& other) const {
   return m_poly_f == other.m_poly_f && m_t == other.m_t && m_position_map == other.m_position_map;
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::multiply(const Classic_McEliece_Polynomial& a,
                                                                       const Classic_McEliece_Polynomial& b) const {
   std::vector<Classic_McEliece_GF> prod((m_t * 2 - 1), Classic_McEliece_GF(0, m_poly_f));

   for(size_t i = 0; i < m_t; ++i) {
      for(size_t j = 0; j < m_t; ++j) {
         prod.at(i + j) += (a.coef_at(i) * b.coef_at(j));
      }
   }

   for(size_t i = (m_t - 1) * 2; i >= m_t; --i) {
      for(auto& [idx, coef] : m_position_map) {
         prod.at(i - m_t + idx) += coef * prod.at(i);
      }
   }

   prod.erase(prod.begin() + m_t, prod.end());

   return Classic_McEliece_Polynomial(prod, shared_from_this());
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::create_element_from_bytes(
   std::span<const uint8_t> bytes) const {
   BOTAN_ARG_CHECK(bytes.size() == m_t * 2, "Correct input size");
   std::vector<uint16_t> coef(m_t);
   load_le<uint16_t>(coef.data(), bytes.data(), m_t);
   return create_element_from_coef(coef);
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::create_element_from_coef(
   std::vector<Classic_McEliece_GF> coeff_vec) const {
   return Classic_McEliece_Polynomial(std::move(coeff_vec), shared_from_this());
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::create_element_from_coef(
   std::vector<uint16_t> coeff_vec) const {
   std::vector<Classic_McEliece_GF> coeff_vec_gf;
   std::transform(coeff_vec.begin(), coeff_vec.end(), std::back_inserter(coeff_vec_gf), [this](auto& coeff) {
      return Classic_McEliece_GF(coeff, m_poly_f);
   });
   return Classic_McEliece_Polynomial(coeff_vec_gf, shared_from_this());
}

bool operator==(const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& first,
                const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& second) {
   return first.coeff == second.coeff && first.idx == second.idx;
}

}  // namespace Botan
