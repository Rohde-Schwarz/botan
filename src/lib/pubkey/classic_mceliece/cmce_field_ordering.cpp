/*
* Classic McEliece Field Ordering Generation
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/
#include "cmce_field_ordering.h"

#include <botan/cmce.h>
#include <botan/internal/loadstor.h>

#include <botan/mem_ops.h>
#include <iostream>
#include <numeric>
#include <utility>
#include <vector>

namespace Botan {

namespace CMCE_CT {
namespace {

template <typename T1, typename T2>
void cond_swap_pair(CT::Mask<uint64_t> cond_mask, std::pair<T1, T2>& a, std::pair<T1, T2>& b) {
   cond_mask.conditional_swap(a.first, b.first);
   cond_mask.conditional_swap(a.second, b.second);
}

template <typename T1, typename T2>
void ct_compare_and_swap_pair(std::span<std::pair<T1, T2>> a, size_t i, size_t k, size_t l) {
   if((i & k) == 0) {  // i and k do not depend on secret data
      auto swap_required_mask = CT::Mask<uint64_t>::is_lt(a[l].first, a[i].first);
      cond_swap_pair(swap_required_mask, a[i], a[l]);
   } else {
      auto swap_required_mask = CT::Mask<uint64_t>::is_gt(a[l].first, a[i].first);
      cond_swap_pair(swap_required_mask, a[i], a[l]);
   }
}

// Sorts a vector of pairs after the first element
template <typename T1, typename T2>
void ct_bitonic_sort_pair(std::span<std::pair<T1, T2>> a) {
   size_t n = a.size();
   BOTAN_ARG_CHECK(is_power_of_2(n), "Input vector size must be a power of 2");

   for(size_t k = 2; k <= n; k *= 2) {
      for(size_t j = k / 2; j > 0; j /= 2) {
         for(size_t i = 0; i < n; i++) {
            size_t l = i ^ j;
            if(l > i) {
               ct_compare_and_swap_pair(a, i, k, l);
            }
         }
      }
   }
}

template <typename T>
T min(const T& a, const T& b) {
   auto mask = CT::Mask<T>::is_lt(a, b);
   return mask.select(a, b);
}

}  // namespace
}  // namespace CMCE_CT

namespace {
template <typename T1, typename T2>
std::vector<std::pair<T1, T2>> zip(const secure_vector<T1>& vec_1, const secure_vector<T2>& vec_2) {
   BOTAN_ARG_CHECK(vec_1.size() == vec_2.size(), "Vectors' dimensions do not match");
   std::vector<std::pair<T1, T2>> vec_zipped;
   vec_zipped.reserve(vec_1.size());
   for(size_t i = 0; i < vec_1.size(); ++i) {
      vec_zipped.push_back(std::make_pair(vec_1.at(i), vec_2.at(i)));
   }
   return vec_zipped;
}

template <typename T1, typename T2>
std::pair<secure_vector<T1>, secure_vector<T2>> unzip(std::vector<std::pair<T1, T2>> vec_zipped) {
   secure_vector<T1> vec_1;
   secure_vector<T2> vec_2;

   vec_1.reserve(vec_zipped.size());
   vec_2.reserve(vec_zipped.size());

   for(auto& [elem1, elem2] : vec_zipped) {
      vec_1.push_back(elem1);
      vec_2.push_back(elem2);
   }
   return std::make_pair(std::move(vec_1), std::move(vec_2));
}

secure_vector<uint16_t> create_pi(secure_vector<uint32_t>& a) {
   secure_vector<uint16_t> pi(a.size());
   std::iota(pi.begin(), pi.end(), 0);  // contains 0, 1, ..., q-1

   auto a_pi_zipped = zip(a, pi);
   CMCE_CT::ct_bitonic_sort_pair(std::span(a_pi_zipped));

   auto [a_sorted, pi_sorted] = unzip(std::move(a_pi_zipped));
   a = std::move(a_sorted);

   return pi_sorted;
}

/**
* @brief Create a GF element from pi as in (Section 8.2, Step 4).
* Corresponds to the reverse bits of pi.
*/
Classic_McEliece_GF from_pi(uint16_t pi_elem, uint16_t modulus, size_t m) {
   //TODO: Possibly use reverse_bits from utils
   std::bitset<16> bits(pi_elem);
   std::bitset<16> reversed_bits;

   for(int i = 0; i < 16; ++i) {
      reversed_bits[i] = bits[15 - i];
   }

   reversed_bits >>= (sizeof(uint16_t) * 8 - m);

   return Classic_McEliece_GF(static_cast<uint16_t>(reversed_bits.to_ulong()), modulus);
}

}  // anonymous namespace

std::optional<Classic_McEliece_Field_Ordering> Classic_McEliece_Field_Ordering::create_field_ordering(
   const Classic_McEliece_Parameters& params, std::span<const uint8_t> random_bits) {
   BOTAN_ARG_CHECK(random_bits.size() == (params.sigma2() * params.q()) / 8, "Wrong random bits size");

   secure_vector<uint32_t> a;  // contains a_0, a_1, ...
   for(size_t i = 0; i < params.q(); ++i) {
      a.push_back(load_le<uint32_t>(random_bits.data(), i));
   }

   auto pi = create_pi(a);

   for(size_t i = 1; i < params.q(); ++i) {
      if(a.at(i - 1) == a.at(i)) {  // Check for duplicate elements utilizing sorting
         return std::nullopt;       // Abort
      }
   }

   return Classic_McEliece_Field_Ordering(std::move(pi), params.poly_f());
}

std::vector<Classic_McEliece_GF> Classic_McEliece_Field_Ordering::alphas(size_t n) const {
   BOTAN_ASSERT_NOMSG(m_poly_f != 0);
   BOTAN_ASSERT_NOMSG(m_pi.size() >= n);

   std::vector<Classic_McEliece_GF> n_alphas_vec;

   std::transform(m_pi.begin(), m_pi.begin() + n, std::back_inserter(n_alphas_vec), [this](uint16_t pi_elem) {
      return from_pi(pi_elem, m_poly_f, Classic_McEliece_GF::log_q_from_mod(m_poly_f));
   });

   return n_alphas_vec;
}

secure_bitvector Classic_McEliece_Field_Ordering::alphas_control_bits() const {
   // Each vector element contains one bit of the control bits
   auto control_bits_as_words = generate_control_bits_internal(m_pi);
   auto control_bits = secure_bitvector(control_bits_as_words.size());
   for(size_t i = 0; i < control_bits.size(); ++i) {
      control_bits.at(i) = control_bits_as_words.at(i);
   }
   return control_bits;
}

secure_vector<uint16_t> Classic_McEliece_Field_Ordering::composeinv(const secure_vector<uint16_t>& c,
                                                                    const secure_vector<uint16_t>& pi) {
   //TODO: Use secure_vector ?
   auto pi_c_zipped = zip(pi, c);
   CMCE_CT::ct_bitonic_sort_pair(std::span(pi_c_zipped));
   auto [pi_sorted, c_sorted] = unzip(pi_c_zipped);

   return c_sorted;
}

// p,q = composeinv(p,q),composeinv(q,p)
void Classic_McEliece_Field_Ordering::simultaneous_composeinv(secure_vector<uint16_t>& p, secure_vector<uint16_t>& q) {
   auto p_new = composeinv(p, q);
   q = composeinv(q, p);
   p = std::move(p_new);
}

secure_vector<uint16_t> Classic_McEliece_Field_Ordering::generate_control_bits_internal(
   const secure_vector<uint16_t>& pi) {
   auto n = pi.size();
   size_t m = 1;

   while(size_t(1) << m < n) {
      m += 1;
   }

   BOTAN_ASSERT_NOMSG(size_t(1) << m == n);

   if(m == 1) {
      return secure_vector<uint16_t>({pi.at(0)});
   }
   secure_vector<uint16_t> p(n);
   for(size_t x = 0; x < n; ++x) {
      p.at(x) = pi.at(x ^ 1);
   }
   secure_vector<uint16_t> q(n);
   for(size_t x = 0; x < n; ++x) {
      q.at(x) = pi.at(x) ^ 1;
   }

   secure_vector<uint16_t> range_n(n);
   std::iota(range_n.begin(), range_n.end(), 0);
   auto piinv = composeinv(range_n, pi);

   simultaneous_composeinv(p, q);

   secure_vector<uint16_t> c(n);
   for(uint16_t x = 0; size_t(x) < n; ++x) {
      c.at(x) = CMCE_CT::min(x, p.at(x));
   }

   simultaneous_composeinv(p, q);

   for(size_t i = 1; i < m - 1; ++i) {
      auto cp = composeinv(c, q);
      simultaneous_composeinv(p, q);
      for(uint16_t x = 0; size_t(x) < n; ++x) {
         c.at(x) = CMCE_CT::min(c.at(x), cp.at(x));
      }
   }

   secure_vector<uint16_t> f(n / 2);
   for(size_t j = 0; j < n / 2; ++j) {
      f.at(j) = c.at(2 * j) % 2;
   }

   secure_vector<uint16_t> big_f(n);
   for(size_t x = 0; x < n; ++x) {
      big_f.at(x) = x ^ f.at(x / 2);
   }

   auto fpi = composeinv(big_f, piinv);

   secure_vector<uint16_t> l(n / 2);
   for(size_t k = 0; k < n / 2; ++k) {
      l.at(k) = fpi.at(2 * k) % 2;
   }

   secure_vector<uint16_t> big_l(n);
   for(size_t y = 0; y < n; ++y) {
      big_l.at(y) = y ^ l.at(y / 2);
   }

   auto big_m = composeinv(fpi, big_l);

   secure_vector<uint16_t> subm0(n / 2);
   secure_vector<uint16_t> subm1(n / 2);
   for(size_t j = 0; j < n / 2; ++j) {
      subm0.at(j) = big_m.at(2 * j) / 2;
      subm1.at(j) = big_m.at(2 * j + 1) / 2;
   }

   auto subz0 = generate_control_bits_internal(subm0);
   auto subz1 = generate_control_bits_internal(subm1);

   secure_vector<uint16_t> z(subz0.size() + subz1.size());
   for(size_t j = 0; j < subz0.size(); ++j) {
      z.at(2 * j) = subz0.at(j);
      z.at(2 * j + 1) = subz1.at(j);
   }
   // TODO: Preallocate buffer?
   //BOTAN_ASSERT_NOMSG(z.size() == (n / 2) * (2 * m - 3));
   return Botan::concat(f, z, l);
}

// Based on the Python code "permutation(c)" from Bernstein
// "Verified fast formulas for control bits for permutation networks"
Classic_McEliece_Field_Ordering Classic_McEliece_Field_Ordering::create_from_control_bits(
   const Classic_McEliece_Parameters& params, const secure_bitvector& control_bits) {
   BOTAN_ASSERT_NOMSG(control_bits.size() == (2 * params.m() - 1) << (params.m() - 1));
   uint16_t n = 1 << params.m();
   secure_vector<uint16_t> pi(n);
   std::iota(pi.begin(), pi.end(), 0);
   for(size_t i = 0; i < 2 * params.m() - 1; ++i) {
      size_t gap = 1 << std::min(i, 2 * params.m() - 2 - i);
      for(size_t j = 0; j < n / 2; ++j) {
         size_t pos = (j % gap) + 2 * gap * (j / gap);
         auto mask = CT::Mask<uint16_t>::expand(control_bits[i * n / 2 + j]);
         mask.conditional_swap(pi[pos], pi[pos + gap]);
      }
   }

   return Classic_McEliece_Field_Ordering(std::move(pi), params.poly_f());
}

void Classic_McEliece_Field_Ordering::permute_with_pivots(const Classic_McEliece_Parameters& params,
                                                          const secure_bitvector& pivots) {
   auto col_offset = params.pk_no_rows() - Classic_McEliece_Parameters::mu();

   for(uint64_t p_idx = 1; p_idx <= Classic_McEliece_Parameters::mu(); ++p_idx) {
      uint64_t p_counter = 0;
      for(uint64_t col = 0; col < Classic_McEliece_Parameters::nu(); ++col) {
         auto mask_is_pivot_set = CT::Mask<uint64_t>::expand(pivots.at(col));
         p_counter += CT::Mask<uint64_t>::expand(pivots.at(col)).if_set_return(1);
         auto mask_is_current_pivot = CT::Mask<uint64_t>::is_equal(p_idx, p_counter);
         (mask_is_pivot_set & mask_is_current_pivot)
            .conditional_swap(m_pi.at(col_offset + col), m_pi.at(col_offset + p_idx - 1));
      }
   }
}

}  // namespace Botan
