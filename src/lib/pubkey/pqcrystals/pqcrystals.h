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

      // TODO: reconsider, in case there are no more virtual methods
      Polynomial(const ThisPolynomial&) = default;
      Polynomial(ThisPolynomial&&) noexcept = default;
      ThisPolynomial& operator=(const ThisPolynomial&) = default;
      ThisPolynomial& operator=(ThisPolynomial&&) noexcept = default;
      virtual ~Polynomial() = default;

      auto size() const { return m_coeffs.size(); }

      T& operator[](size_t i) { return m_coeffs[i]; }

      const T& operator[](size_t i) const { return m_coeffs[i]; }

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

      // TODO: reconsider...
      //       Perhaps using CRTP or a delegate in the Consts
      virtual void reduce() = 0;

      // TODO: reconsider...
      //       Perhaps using CRTP or a delegate in the Consts
      virtual T reduce(T x) const = 0;

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
      std::vector<Polynomial<Consts>> m_vec;

   public:
      PolynomialVector(std::vector<Polynomial<Consts>> vec) : m_vec(std::move(vec)) {}

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
};

template <constants Consts>
class PolynomialMatrix {
   private:
      using ThisPolynomialMatrix = PolynomialMatrix<Consts>;

   private:
      std::vector<PolynomialVector<Consts>> m_mat;

   public:
      PolynomialMatrix(std::vector<PolynomialVector<Consts>> mat) : m_mat(std::move(mat)) {}
};

template <constants Consts>
Polynomial<Consts, Domain::NTT> ntt(Polynomial<Consts, Domain::Normal> p) {
   Polynomial<Consts, Domain::NTT> p_ntt;

   using Trait = constants_trait<Consts>;

   for(size_t len = p.size() / 2, k = 0; len >= 2; len /= 2) {
      for(size_t start = 0, j = 0; start < p.size(); start = j + len) {
         const auto zeta = Consts::zetas[++k];
         for(j = start; j < start + len; ++j) {
            const auto t = reduce(static_cast<typename Trait::T2>(zeta) * p[j + len]);
            p_ntt[j + len] = p[j] - t;
            p_ntt[j] = p[j] + t;
         }
      }
   }

   p_ntt.reduce();

   return p_ntt;
}

}  // namespace Botan::CRYSTALS

#endif
