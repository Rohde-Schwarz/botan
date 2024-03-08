/*
 * Classic McEliece Parameters
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_PARAMETER_SET_H_
#define BOTAN_CMCE_PARAMETER_SET_H_

#include <botan/asn1_obj.h>

namespace Botan {

/**
 * All Classic McEliece parameter sets defined in the NIST Round 4
 * submission and the Classic McEliece ISO Draft.
 *
 * Instances are defined in the following format:
 * mceliece{n}{t}{[pc]}{[f]}
 *
 * Instance with 'pc' use plaintext confirmation as defined in the ISO Draft.
 * Instance with 'f' use matrix reduction with the semi-systematic form.
 */
enum class Classic_McEliece_Parameter_Set {
   mceliece348864,   // NIST
   mceliece348864f,  // NIST

   mceliece460896,   // NIST
   mceliece460896f,  // NIST

   mceliece6688128,     // ISO + NIST
   mceliece6688128f,    // ISO + NIST
   mceliece6688128pc,   // ISO
   mceliece6688128pcf,  // ISO

   mceliece6960119,     // ISO + NIST
   mceliece6960119f,    // ISO + NIST
   mceliece6960119pc,   // ISO
   mceliece6960119pcf,  // ISO

   mceliece8192128,     // ISO + NIST
   mceliece8192128f,    // ISO + NIST
   mceliece8192128pc,   // ISO
   mceliece8192128pcf,  // ISO

   /// Reduced instances for side channel analysis (Self-created test instance with
   /// m=8, n=128, t=8, f(z)=z^8+z^7+z^2+z+1, F(y)=y^8+y^4+y^3+y^2+1)
   /// Minimal instance without semi-systematic matrix creation and no plaintext confirmation
   test,
   /// Minimal instance with semi-systematic matrix creation and no plaintext confirmation
   testf,
   /// Minimal instance without semi-systematic matrix creation and with plaintext confirmation
   testpc,
   /// Minimal instance with semi-systematic matrix creation and with plaintext confirmation
   testpcf
};

/**
 * @brief Get the parameter set for a given parameter set name.
 */
BOTAN_TEST_API Classic_McEliece_Parameter_Set cmce_param_set_from_str(std::string_view param_name);

/**
 * @brief Get the parameter set name for a given parameter set.
 */
BOTAN_TEST_API std::string cmce_str_from_param_set(Classic_McEliece_Parameter_Set param);

/**
 * @brief Get the parameter set for a given OID.
 */
BOTAN_TEST_API Classic_McEliece_Parameter_Set cmce_param_set_from_oid(const OID& oid);

}  // namespace Botan

#endif  //  BOTAN_CMCE_PARAMETER_SET_H_
