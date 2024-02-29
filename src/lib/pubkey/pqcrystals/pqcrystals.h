/*
 * PQ CRYSTALS Common Structures
 * Based on the public domain reference implementations by the
 * designers (https://github.com/pq-crystals/kyber and https://github.com/pq-crystals/dilithium)
 *
 * Further changes
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_PQ_H_
#define BOTAN_PQ_H_

#include <array>
#include <bit>
#include <concepts>
#include <cstdint>
#include <span>
#include <vector>

#include <botan/internal/pqcrystals_helpers.h>

namespace Botan::CRYSTALS {

enum class Domain { Normal, NTT, Montgomery };

// clang-format off

template <typename Consts>
concept constants =
   std::integral<typename Consts::T> &&
   sizeof(typename Consts::T) <= 4 &&
   Consts::N % 2 == 0 &&
   std::same_as<std::array<typename Consts::T, Consts::N / 2>, std::remove_cvref_t<decltype(Consts::zetas)>> &&
   std::same_as<std::array<typename Consts::T, Consts::N / 2>, std::remove_cvref_t<decltype(Consts::zetas_inverse)>> &&
   std::same_as<typename Consts::T, std::remove_cvref_t<decltype(Consts::N)>> &&
   std::same_as<typename Consts::T, std::remove_cvref_t<decltype(Consts::Q)>>;

// clang-format on

template <constants Consts>
class constants_trait {
   public:
      using T = typename Consts::T;
      using T2 = Botan::next_longer_int_t<T>;

      constexpr static auto N = Consts::N;
      constexpr static auto Q = Consts::Q;
      constexpr static auto Q_inverse = modular_inverse(Consts::Q);

      constexpr static T montgomery_reduce(T2 a) {
         const auto u = static_cast<T>(a * Q_inverse);
         auto t = static_cast<T2>(u) * Q;
         t = a - t;
         t >>= sizeof(T) * 8;
         return static_cast<T>(t);
      }

      constexpr static T barrett_reduce(T a) {
         BOTAN_ASSERT(Q == 3329, "Only implemented for Kyber, at the moment");
         constexpr int32_t v = ((1U << 26) + Q / 2) / Q;
         const int16_t t = (v * a >> 26) * Q;
         return a - t;
      }

      constexpr static T fqmul(T a, T b) { return montgomery_reduce(static_cast<T2>(a) * b); }
};

template <constants Consts, Domain D = Domain::Normal>
class Polynomial {
   private:
      using ThisPolynomial = Polynomial<Consts, D>;

      using T = typename Consts::T;

   private:
      std::array<T, Consts::N> m_coeffs;

   public:
      Polynomial() : m_coeffs({0}) {}

      constexpr size_t size() const { return m_coeffs.size(); }

      T& operator[](size_t i) { return m_coeffs[i]; }

      const T& operator[](size_t i) const { return m_coeffs[i]; }

      decltype(auto) begin() { return m_coeffs.begin(); }

      decltype(auto) begin() const { return m_coeffs.begin(); }

      decltype(auto) end() { return m_coeffs.end(); }

      decltype(auto) end() const { return m_coeffs.end(); }

      /**
       * Adds two polynomials element-wise. Does not perform a reduction after the addition.
       * Therefore this operation might cause an integer overflow.
       */
      decltype(auto) operator+=(const ThisPolynomial& other) {
         for(size_t i = 0; i < this->size(); ++i) {
            this->m_coeffs[i] = this->m_coeffs[i] + other.m_coeffs[i];
         }
         return *this;
      }

      /**
       * Subtracts two polynomials element-wise. Does not perform a reduction after the subtraction.
       * Therefore this operation might cause an integer underflow.
       */
      decltype(auto) operator-=(const ThisPolynomial& other) {
         for(size_t i = 0; i < this->size(); ++i) {
            this->m_coeffs[i] = other.m_coeffs[i] - this->m_coeffs[i];
         }
         return *this;
      }

      // void to_invntt_montgomery() {
      //    for(size_t len = 2, k = 0; len <= size() / 2; len *= 2) {
      //       for(size_t start = 0, j = 0; start < size(); start = j + len) {
      //          const auto zeta = Consts::zetas_inverse[k++];
      //          for(j = start; j < start + len; ++j) {
      //             const auto t = m_coeffs[j];
      //             m_coeffs[j] = reduce(t + m_coeffs[j + len]);
      //             m_coeffs[j + len] = fqmul(zeta, t - m_coeffs[j + len]);
      //          }
      //       }
      //    }

      //    for(auto& c : m_coeffs) {
      //       c = fqmul(c, Consts::zetas_inv[127]);
      //    }
      // }

      // void to_montgomery() {
      //    constexpr auto f = static_cast<T>((uint64_t(1) << (sizeof(T2) * 8)) % Q);
      //    for(size_t i = 0; i < size(); ++i) {
      //       m_coeffs[i] = montgomery_reduce(static_cast<T2>(m_coeffs[i]) * f);
      //    }
      // }
};

template <constants Consts, Domain D = Domain::Normal>
class PolynomialVector {
   private:
      using ThisPolynomialVector = PolynomialVector<Consts, D>;

   private:
      std::vector<Polynomial<Consts, D>> m_vec;

   public:
      PolynomialVector(size_t size) : m_vec(size) {}

      size_t size() const { return m_vec.size(); }

      ThisPolynomialVector& operator+=(const ThisPolynomialVector& other) {
         BOTAN_ASSERT(m_vec.size() == other.m_vec.size(), "cannot add polynomial vectors of differing lengths");

         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i] += other.m_vec[i];
         }
         return *this;
      }

      ThisPolynomialVector& operator-=(const ThisPolynomialVector& other) {
         BOTAN_ASSERT(m_vec.size() == other.m_vec.size(), "cannot subtract polynomial vectors of differing lengths");

         for(size_t i = 0; i < m_vec.size(); ++i) {
            m_vec[i] -= other.m_vec[i];
         }
         return *this;
      }

      void reduce() {
         for(auto& v : m_vec) {
            v.reduce();
         }
      }

      void to_ntt() {
         for(auto& v : m_vec) {
            v.to_ntt();
         }
      }

      Polynomial<Consts, D>& operator[](size_t i) { return m_vec[i]; }

      const Polynomial<Consts, D>& operator[](size_t i) const { return m_vec[i]; }

      decltype(auto) begin() { return m_vec.begin(); }

      decltype(auto) begin() const { return m_vec.begin(); }

      decltype(auto) end() { return m_vec.end(); }

      decltype(auto) end() const { return m_vec.end(); }
};

template <constants Consts>
class PolynomialMatrix {
   private:
      using ThisPolynomialMatrix = PolynomialMatrix<Consts>;

   private:
      std::vector<PolynomialVector<Consts, Domain::NTT>> m_mat;

   public:
      PolynomialMatrix(std::vector<PolynomialVector<Consts>> mat) : m_mat(std::move(mat)) {}

      size_t size() const { return m_mat.size(); }

      PolynomialMatrix(size_t rows, size_t cols) : m_mat(rows, PolynomialVector<Consts, Domain::NTT>(cols)) {}

      PolynomialVector<Consts, Domain::NTT>& operator[](size_t i) { return m_mat[i]; }

      const PolynomialVector<Consts, Domain::NTT>& operator[](size_t i) const { return m_mat[i]; }
};

namespace detail {

template <constants Consts>
void ntt(Polynomial<Consts, Domain::NTT>& p_ntt) {
   using Trait = constants_trait<Consts>;

   for(size_t len = p_ntt.size() / 2, k = 0; len >= 2; len /= 2) {
      for(size_t start = 0, j = 0; start < p_ntt.size(); start = j + len) {
         const auto zeta = Consts::zetas[++k];
         for(j = start; j < start + len; ++j) {
            const auto t = Trait::fqmul(zeta, p_ntt[j + len]);
            p_ntt[j + len] = p_ntt[j] - t;
            p_ntt[j] = p_ntt[j] + t;
         }
      }
   }

   for(auto& c : p_ntt) {
      c = Trait::barrett_reduce(c);
   }
}

}  // namespace detail

template <constants Consts>
Polynomial<Consts, Domain::NTT> ntt(Polynomial<Consts, Domain::Normal> p) {
   // TODO: Is there a way to avoid this copy? p goes out of scope anyway,
   //       can we somehow instruct the compiler to just reuse the memory?
   auto p_ntt = std::bit_cast<Polynomial<Consts, Domain::NTT>>(p);
   detail::ntt(p_ntt);
   return p_ntt;
}

// TODO: This has to copy the data from polyvec to polyvec_ntt. Can we avoid
//       this? The only difference is the Domain annotation which does not
//       change the data structure itself. Is there a way to let vector scavenge
//       the data from polyvec, but still annotate it as Domain::NTT?
template <constants Consts>
PolynomialVector<Consts, Domain::NTT> ntt(PolynomialVector<Consts, Domain::Normal> polyvec) {
   PolynomialVector<Consts, Domain::NTT> polyvec_ntt(polyvec.size());
   for(size_t i = 0; i < polyvec.size(); ++i) {
      polyvec_ntt[i] = std::bit_cast<Polynomial<Consts, Domain::NTT>>(polyvec[i]);
      detail::ntt(polyvec_ntt[i]);
   }
   return polyvec_ntt;
}

}  // namespace Botan::CRYSTALS

#endif
