/*
 * Ed448 Scalar
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */
#ifndef BOTAN_CURVE448_SCALAR_H_
#define BOTAN_CURVE448_SCALAR_H_

#include <botan/strong_type.h>
#include <botan/types.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>

namespace Botan {

constexpr size_t words_for_bits(size_t x) {
   constexpr size_t word_bits = sizeof(word) * 8;
   return (x + word_bits - 1) / word_bits;
}

constexpr size_t WORDS_446 = words_for_bits(446);
constexpr size_t BYTES_446 = ceil_tobytes(446);

/**
 * @brief Representation of a scalar for Curve448.
 *
 * The scalar is an element in 0 <= s < L, where L is the group
 * order of Curve448. The constructor and all operations on
 * scalars reduce the element mod L internally. All operations are
 * constant time.
 *
 * L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
 * (RFC 7748 4.2)
 */
class BOTAN_TEST_API Scalar448 {
   public:
      /// @brief Construct a new scalar from (max. 114) bytes. Little endian.
      Scalar448(std::span<const uint8_t> x);

      /// @brief Convert the scalar to bytes in little endian.
      template <size_t S = BYTES_446>
      std::array<uint8_t, S> to_bytes() const
         requires(S >= BYTES_446)
      {
         std::array<uint8_t, S> result = {0};
         store_le(std::span(result).template first<BYTES_446>(), m_scalar_words);
         return result;
      }

      /// @brief Access the i-th bit of the scalar. From 0 (lsb) to 445 (msb).
      bool get_bit(size_t i) const;

      /// @brief scalar = (scalar + other) mod L
      Scalar448 operator+(const Scalar448& other) const;

      /// @brief scalar = (scalar * other) mod L
      Scalar448 operator*(const Scalar448& other) const;

      /// @return true iff x >= L.
      static bool bytes_are_reduced(std::span<const uint8_t> x);

   private:
      Scalar448(std::span<const word, WORDS_446> scalar_words) { copy_mem(m_scalar_words, scalar_words); }

      std::array<word, WORDS_446> m_scalar_words;
};

}  // namespace Botan

#endif  // BOTAN_CURVE448_SCALAR_H_
