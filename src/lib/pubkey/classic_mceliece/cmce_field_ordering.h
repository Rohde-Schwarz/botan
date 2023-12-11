/*
* Classic McEliece Field Ordering Generation
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_FIELD_ORDERING_H_
#define BOTAN_CMCE_FIELD_ORDERING_H_

#include <botan/cmce_parameters.h>
#include <numeric>

namespace Botan {
class BOTAN_TEST_API Classic_McEliece_Field_Ordering {
   public:
      // TODO: Question regarding spec: Why not create the field ordering by choosing
      //       random control bits and then call create_from_control_bits? Doesn't this
      //       work? Or is (create_field_ordering + to_control_bits) more expensive than from_control_bits?
      static std::optional<Classic_McEliece_Field_Ordering> create_field_ordering(
         const Classic_McEliece_Parameters& params, std::span<const uint8_t> random_bits);

      static Classic_McEliece_Field_Ordering create_from_control_bits(const Classic_McEliece_Parameters& params,
                                                                      const secure_bitvector& control_bits);

      std::vector<Classic_McEliece_GF> alphas() const;
      secure_bitvector alphas_control_bits() const;

      secure_vector<uint16_t>& pi_ref() { return m_pi; }

   private:
      Classic_McEliece_Field_Ordering(secure_vector<uint16_t> pi, uint16_t poly_f) :
            m_pi(std::move(pi)), m_poly_f(poly_f) {}

      static secure_vector<uint16_t> composeinv(const secure_vector<uint16_t>& c, const secure_vector<uint16_t>& pi);
      static void simultaneous_composeinv(secure_vector<uint16_t>& p, secure_vector<uint16_t>& q);

      static secure_vector<uint16_t> generate_control_bits_internal(const secure_vector<uint16_t>& pi);

   private:
      secure_vector<uint16_t> m_pi;
      uint16_t m_poly_f;
};

}  // namespace Botan

#endif
