/*
* Classic McEliece Matrix Logic
*
* People who took the red pill:
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
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

class BOTAN_TEST_API Classic_McEliece_Matrix {
   public:
      //TODO: Strong type for pivots
      static std::optional<std::pair<Classic_McEliece_Matrix, secure_bitvector<uint64_t>>> create_matrix(
         const Classic_McEliece_Parameters& params,
         Classic_McEliece_Field_Ordering& field_ordering,
         const Classic_McEliece_Minimal_Polynomial& g);

      std::vector<uint8_t> bytes() const { return m_mat_bytes; }

      Classic_McEliece_Matrix(std::vector<uint8_t> mat_bytes) : m_mat_bytes(std::move(mat_bytes)) {}

      bitvector<uint64_t> mul(const Classic_McEliece_Parameters& params, const secure_bitvector<uint64_t>& e) const;

   private:
      const std::vector<uint8_t> m_mat_bytes;
};

}  // namespace Botan

#endif  // BOTAN_CMCE_MATRIX_H_
