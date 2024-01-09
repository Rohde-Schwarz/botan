/*
* Classic McEliece Field Ordering Generation
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_FIELD_ORDERING_H_
#define BOTAN_CMCE_FIELD_ORDERING_H_

#include <botan/cmce_parameters.h>
#include <numeric>

namespace Botan {

/**
 * @brief Represents a field ordering for the Classic McEliece cryptosystem.
 *
 * Field ordering corresponds to the permutation pi defining the alpha sequence in
 * the Classic McEliece specification (see Classic McEliece ISO Sec. 8.2.).
 */
class BOTAN_TEST_API Classic_McEliece_Field_Ordering {
   public:
      /**
       * @brief Creates a field ordering from a random bit sequence. Corresponds to
       *        the algorithm described in Classic McEliece ISO Sec. 8.2.
       *
       * @param params The McEliece parameters.
       * @param random_bits The random bit sequence.
       * @return The field ordering.
       */
      static std::optional<Classic_McEliece_Field_Ordering> create_field_ordering(
         const Classic_McEliece_Parameters& params, std::span<const uint8_t> random_bits);

      /**
       * @brief Create the field ordering from the control bits of a benes network.
       *
       * @param params The McEliece parameters.
       * @param control_bits The control bits of the benes network.
       * @return The field ordering.
       */
      static Classic_McEliece_Field_Ordering create_from_control_bits(const Classic_McEliece_Parameters& params,
                                                                      const secure_bitvector& control_bits);

      /**
       * @brief Returns the field ordering as a vector of all alphas from alpha_0 to alpha_{n-1}.
       *
       * @param n The number of alphas to return.
       * @return the vector of n alphas.
       */
      std::vector<Classic_McEliece_GF> alphas(size_t n) const;

      /**
       * @brief Generates the control bits of the benes network corresponding to the field ordering.
       *
       * @return the control bits.
       */
      secure_bitvector alphas_control_bits() const;

      /**
       * @brief The pi values representing the field ordering.
       *
       * @return pi values.
       */
      secure_vector<uint16_t>& pi_ref() { return m_pi; }

      /**
       * @brief Permute the field ordering with the given pivots.
       *
       * For example: If the pivot vector is 10101, the first, third and fifth element of the field ordering
       * are permuted to positions 0, 1 and 2, respectively. The remaining elements are put at the end.
       *
       * The permutation is done for the elements from position m*t - mu,..., m*t + mu (excl.).
       * This function implements Classic McEliece ISO Sec. 7.2.3 Step 4.
       *
       * @param params The McEliece parameters.
       * @param pivots The pivot vector.
       */
      void permute_with_pivots(const Classic_McEliece_Parameters& params, const secure_bitvector& pivots);

   private:
      Classic_McEliece_Field_Ordering(secure_vector<uint16_t> pi, uint16_t poly_f) :
            m_pi(std::move(pi)), m_poly_f(poly_f) {}

      // Helpers for control bit creation
      static secure_vector<uint16_t> composeinv(const secure_vector<uint16_t>& c, const secure_vector<uint16_t>& pi);
      static void simultaneous_composeinv(secure_vector<uint16_t>& p, secure_vector<uint16_t>& q);
      static secure_vector<uint16_t> generate_control_bits_internal(const secure_vector<uint16_t>& pi);

   private:
      secure_vector<uint16_t> m_pi;
      uint16_t m_poly_f;
};

}  // namespace Botan

#endif
