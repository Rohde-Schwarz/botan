/*
 * Classic McEliece Polynomials
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/cmce_poly.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan {

Classic_McEliece_GF Classic_McEliece_Polynomial_Base::operator()(const Classic_McEliece_GF& a) const {
   BOTAN_ASSERT(a.modulus() == coef_at(0).modulus(), "Unmatching Galois fields");

   Classic_McEliece_GF r(0, a.modulus());
   for(auto it = m_coef.rbegin(); it != m_coef.rend(); ++it) {
      r *= a;
      r += *it;
   }

   return r;
}

bool Classic_McEliece_Polynomial_Ring::operator==(const Classic_McEliece_Polynomial_Ring& other) const {
   return m_poly_f == other.m_poly_f && m_t == other.m_t && m_position_map == other.m_position_map;
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::multiply(const Classic_McEliece_Polynomial& a,
                                                                       const Classic_McEliece_Polynomial& b) const {
   std::vector<Classic_McEliece_GF> prod((m_t * 2 - 1), {0, m_poly_f});

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

   return Classic_McEliece_Polynomial(prod);
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
   return Classic_McEliece_Polynomial(std::move(coeff_vec));
}

Classic_McEliece_Polynomial Classic_McEliece_Polynomial_Ring::create_element_from_coef(
   const std::vector<uint16_t>& coeff_vec) const {
   std::vector<Classic_McEliece_GF> coeff_vec_gf;
   std::transform(coeff_vec.begin(), coeff_vec.end(), std::back_inserter(coeff_vec_gf), [this](auto& coeff) {
      return Classic_McEliece_GF(coeff, m_poly_f);
   });
   return Classic_McEliece_Polynomial(coeff_vec_gf);
}

bool operator==(const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& lhs,
                const Classic_McEliece_Polynomial_Ring::Big_F_Coefficient& rhs) {
   return lhs.coeff == rhs.coeff && lhs.idx == rhs.idx;
}

std::optional<Classic_McEliece_Minimal_Polynomial> Classic_McEliece_Polynomial::compute_minimal_polynomial(
   const Classic_McEliece_Polynomial_Ring& ring) const {
   std::vector<Classic_McEliece_Polynomial> mat;

   mat.push_back(ring.create_element_from_coef(
      concat_as<std::vector<uint16_t>>(std::vector<uint16_t>{1}, std::vector<uint16_t>(ring.t() - 1, 0))));

   mat.emplace_back(*this);

   for(size_t j = 2; j <= ring.t(); ++j) {
      mat.push_back(ring.multiply(mat.at(j - 1), *this));
   }

   // Gaussian
   for(size_t j = 0; j < ring.t(); ++j) {
      for(size_t k = j + 1; k < ring.t(); ++k) {
         auto cond = CT::Mask<uint16_t>::is_zero(mat.at(j).coef_at(j).elem());

         for(size_t c = j; c < ring.t() + 1; ++c) {
            auto acc = cond.select(mat.at(c).coef_at(k).elem(), 0);
            mat.at(c).coef_at(j) += Classic_McEliece_GF(acc, ring.poly_f());
         }
      }

      if(mat.at(j).coef_at(j).elem() == 0) {  // Fail if not systematic. TODO: make an appropriate member function
         return std::nullopt;
      }

      auto inv = mat.at(j).coef_at(j).inv();

      for(size_t c = j; c < ring.t() + 1; ++c) {
         mat.at(c).coef_at(j) *= inv;
      }

      for(size_t k = 0; k < ring.t(); ++k) {
         if(k != j) {
            auto t = mat.at(j).coef_at(k);

            for(size_t c = j; c < ring.t() + 1; ++c) {
               mat.at(c).coef_at(k) += mat.at(c).coef_at(j) * t;
            }
         }
      }
   }

   auto minimal_poly_coeffs = mat.at(ring.t()).coef();
   minimal_poly_coeffs.emplace_back(1, ring.poly_f());

   return Classic_McEliece_Minimal_Polynomial(std::move(minimal_poly_coeffs));
}

secure_vector<uint8_t> Classic_McEliece_Minimal_Polynomial::serialize() const {
   BOTAN_ASSERT_NOMSG(!coef().empty());
   auto coeffs_to_store = std::ranges::subrange(coef().begin(), coef().end() - 1);
   secure_vector<uint8_t> bytes(sizeof(u_int16_t) * coeffs_to_store.size());
   BufferStuffer bytes_stuf(bytes);
   for(auto& coef : coeffs_to_store) {
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

   coeff_vec_gf.emplace_back(1, poly_f);

   return Classic_McEliece_Minimal_Polynomial(coeff_vec_gf);
}

}  // namespace Botan
