/*
* Classic McEliece Matrix Logic
*
* People who took the red pill:
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_MATRIX_H_
#define BOTAN_CMCE_MATRIX_H_

#include <botan/cmce_parameters.h>
#include <botan/internal/bitvector.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_poly.h>

namespace Botan {

/**
 * @brief Representation of the Classic McEliece matrix H, with H = (I_mt | T).
 *
 * Only the bytes of the submatrix T are stored.
 */
class BOTAN_TEST_API Classic_McEliece_Matrix {
   public:
      //TODO: Strong type for pivots
      /**
       * @brief Create the matrix H for a Classic McEliece instance given its
       * parameters, field ordering and minimal polynomial.
       *
       * Output is a pair of the matrix and the pivot vector c that was used to
       * create it in the semi-systematic form as described in Classic McEliece ISO
       * Section 9.2.11.
       *
       * @param params Classic McEliece parameters
       * @param field_ordering Field ordering
       * @param g Minimal polynomial
       * @return Pair(the matrix H, pivot vector c)
       */
      static std::optional<std::pair<Classic_McEliece_Matrix, secure_bitvector>> create_matrix(
         const Classic_McEliece_Parameters& params,
         Classic_McEliece_Field_Ordering& field_ordering,
         const Classic_McEliece_Minimal_Polynomial& g);

      /**
       * @brief The bytes of the submatrix T, with H=(I_mt, T) as defined in Classic
       * McEliece ISO Section 9.2.7.
       *
       * @return The matrix bytes
       */
      std::vector<uint8_t> bytes() const { return m_mat_bytes; }

      /**
       * @brief Create a Classic_McEliece_Matrix from bytes.
       *
       * @param mat_bytes The bytes of the submatrix T as defined in Classic McEliece ISO Section 9.2.7.
       */
      Classic_McEliece_Matrix(std::vector<uint8_t> mat_bytes) : m_mat_bytes(std::move(mat_bytes)) {}

      /**
       * @brief Multiply the Classic McEliece matrix H with a bitvector e.
       *
       * @param params Classic McEliece parameters
       * @param e The bitvector e
       * @return H*e
       */
      bitvector mul(const Classic_McEliece_Parameters& params, const secure_bitvector& e) const;

   private:
      /// The bytes of the submatrix T
      const std::vector<uint8_t> m_mat_bytes;
};

}  // namespace Botan

#endif  // BOTAN_CMCE_MATRIX_H_
