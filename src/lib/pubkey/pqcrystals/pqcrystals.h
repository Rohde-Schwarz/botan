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

#ifndef BOTAN_PQ_CRYSTALS_H_
#define BOTAN_PQ_CRYSTALS_H_

#include <array>
#include <concepts>
#include <cstdint>
#include <span>
#include <vector>

#include <botan/internal/pqcrystals_helpers.h>

namespace Botan {

enum class Crystals_Domain { Normal, NTT, Montgomery };

// clang-format off

template <typename Consts>
concept crystals_constants =
   std::integral<typename Consts::T> &&
   sizeof(typename Consts::T) <= 4 &&
   Consts::N % 2 == 0 &&
   std::same_as<std::array<typename Consts::T, Consts::N / 2>, std::remove_cvref_t<decltype(Consts::zetas)>> &&
   std::same_as<std::array<typename Consts::T, Consts::N / 2>, std::remove_cvref_t<decltype(Consts::zetas_inverse)>> &&
   std::same_as<typename Consts::T, std::remove_cvref_t<decltype(Consts::N)>> &&
   std::same_as<typename Consts::T, std::remove_cvref_t<decltype(Consts::Q)>>;

// clang-format on

template <crystals_constants Consts>
class Crystals_Polynomial {
   private:
      using ThisPolynomial = Crystals_Polynomial<Consts>;
      using T = typename Consts::T;
      using T2 = next_longer_uint_t<T>;

      constexpr static auto N = Consts::N;
      constexpr static auto Q = Consts::Q;
      constexpr static auto Q_inverse = modular_inverse(Consts::Q);

   private:
      std::array<T, N> m_coeffs;
      Crystals_Domain m_domain;

   public:
      Crystals_Polynomial(Crystals_Domain domain = Crystals_Domain::Normal) : m_coeffs({0}), m_domain(domain) {}

      // TODO: reconsider, in case there are no more virtual methods
      Crystals_Polynomial(const ThisPolynomial&) = default;
      Crystals_Polynomial(ThisPolynomial&&) noexcept = default;
      ThisPolynomial& operator=(const ThisPolynomial&) = default;
      ThisPolynomial& operator=(ThisPolynomial&&) noexcept = default;
      virtual ~Crystals_Polynomial() = default;

      auto size() const { return m_coeffs.size(); }

      Crystals_Domain domain() const { return m_domain; }

      std::array<T, N>& coefficients() { return m_coeffs; }

      const std::array<T, N>& coefficients() const { return m_coeffs; }

      T& operator[](size_t i) { return m_coeffs[i]; }

      const T& operator[](size_t i) const { return m_coeffs[i]; }

      /**
       * Adds two polynomials element-wise. Does not perform a reduction after the addition.
       * Therefore this operation might cause an integer overflow.
       */
      decltype(auto) operator+=(const ThisPolynomial& other) {
         BOTAN_DEBUG_ASSERT(domain() == other.domain());
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
         BOTAN_DEBUG_ASSERT(domain() == other.domain());
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

      void to_ntt() {
         BOTAN_STATE_CHECK(domain() == Crystals_Domain::Normal);

         for(size_t len = size() / 2, k = 0; len >= 2; len /= 2) {
            for(size_t start = 0, j = 0; start < size(); start = j + len) {
               const auto zeta = Consts::zetas[++k];
               for(j = start; j < start + len; ++j) {
                  const auto t = reduce(static_cast<T2>(zeta) * m_coeffs[j + len]);
                  m_coeffs[j + len] = m_coeffs[j] - t;
                  m_coeffs[j] = m_coeffs[j] + t;
               }
            }
         }

         reduce();
         m_domain = Crystals_Domain::NTT;
      }

      void to_invntt_montgomery() {
         for(size_t len = 2, k = 0; len <= size() / 2; len *= 2) {
            for(size_t start = 0, j = 0; start < size(); start = j + len) {
               const auto zeta = Consts::zetas_inverse[k++];
               for(j = start; j < start + len; ++j) {
                  const auto t = m_coeffs[j];
                  m_coeffs[j] = reduce(t + m_coeffs[j + len]);
                  m_coeffs[j + len] = fqmul(zeta, t - m_coeffs[j + len]);
               }
            }
         }

         for(auto& c : m_coeffs) {
            c = fqmul(c, Consts::zetas_inv[127]);
         }
      }

      void to_montgomery() {
         constexpr auto f = static_cast<T>((uint64_t(1) << (sizeof(T2) * 8)) % Q);
         for(size_t i = 0; i < size(); ++i) {
            m_coeffs[i] = montgomery_reduce(static_cast<T2>(m_coeffs[i]) * f);
         }

         m_domain = Crystals_Domain::Montgomery;
      }

   protected:
      static T montgomery_reduce(T2 a) {
         const auto u = static_cast<T>(a * Q_inverse);
         auto t = static_cast<T2>(u) * Q;
         t = a - t;
         t >>= sizeof(T) * 8;
         return static_cast<T>(t);
      }

      static T fqmul(T a, T b) { return montgomery_reduce(static_cast<T2>(a) * b); }
};

template <crystals_constants Consts>
class Crystals_PolynomialVector {
   private:
      using ThisPolynomialVector = Crystals_PolynomialVector<Consts>;

   private:
      std::vector<Crystals_Polynomial<Consts>> m_vec;

   public:
      Crystals_PolynomialVector(std::vector<Crystals_Polynomial<Consts>> vec) : m_vec(std::move(vec)) {}

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

template <crystals_constants Consts>
class Crystals_PolynomialMatrix {
   private:
      using ThisPolynomialMatrix = Crystals_PolynomialMatrix<Consts>;

   private:
      std::vector<Crystals_PolynomialVector<Consts>> m_mat;

   public:
      Crystals_PolynomialMatrix(std::vector<Crystals_PolynomialVector<Consts>> mat) : m_mat(std::move(mat)) {}
};

}  // namespace Botan

#endif
