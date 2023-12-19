/*
 * Classic McEliece Parameters
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/cmce_parameters.h>
#include <botan/internal/cmce_poly.h>

namespace Botan {

namespace {

// TODO: unused?
[[maybe_unused]] std::string str_from_param_set(Classic_McEliece_Parameter_Set param) {
   switch(param) {
      case Classic_McEliece_Parameter_Set::mceliece348864:
         return "mceliece348864";
      case Classic_McEliece_Parameter_Set::mceliece348864f:
         return "mceliece348864f";
      case Classic_McEliece_Parameter_Set::mceliece460896:
         return "mceliece460896";
      case Classic_McEliece_Parameter_Set::mceliece460896f:
         return "mceliece460896f";
      case Classic_McEliece_Parameter_Set::mceliece6688128:
         return "mceliece6688128";
      case Classic_McEliece_Parameter_Set::mceliece6688128f:
         return "mceliece6688128f";
      case Classic_McEliece_Parameter_Set::mceliece6688128pc:
         return "mceliece6688128pc";
      case Classic_McEliece_Parameter_Set::mceliece6688128pcf:
         return "mceliece6688128pcf";
      case Classic_McEliece_Parameter_Set::mceliece6960119:
         return "mceliece6960119";
      case Classic_McEliece_Parameter_Set::mceliece6960119f:
         return "mceliece6960119f";
      case Classic_McEliece_Parameter_Set::mceliece6960119pc:
         return "mceliece6960119pc";
      case Classic_McEliece_Parameter_Set::mceliece6960119pcf:
         return "mceliece6960119pcf";
      case Classic_McEliece_Parameter_Set::mceliece8192128:
         return "mceliece8192128";
      case Classic_McEliece_Parameter_Set::mceliece8192128f:
         return "mceliece8192128f";
      case Classic_McEliece_Parameter_Set::mceliece8192128pc:
         return "mceliece8192128pc";
      case Classic_McEliece_Parameter_Set::mceliece8192128pcf:
         return "mceliece8192128pcf";
      // TODO: Remove on final PR
      case Classic_McEliece_Parameter_Set::test:
         return "test";
      case Classic_McEliece_Parameter_Set::testf:
         return "testf";
      case Classic_McEliece_Parameter_Set::testpc:
         return "testpc";
      default:
         throw Decoding_Error("Parameter set not supported");
   }
   BOTAN_ASSERT_UNREACHABLE();
}

std::vector<Classic_McEliece_Polynomial_Ring::Big_F_Coefficient> determine_big_f_coef(size_t t, uint16_t modulus) {
   std::vector<Classic_McEliece_Polynomial_Ring::Big_F_Coefficient> big_f_coef;
   switch(t) {
      case 4:  //y^4 + y + 1 (test instances)
         big_f_coef.push_back({1, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({0, Classic_McEliece_GF(2, modulus)});
         break;
      case 64:  //y^64 + y^3 + y + z
         big_f_coef.push_back({3, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({1, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({0, Classic_McEliece_GF(2, modulus)});
         break;
      case 96:  //y^96 + y^10 + y^9 + y^6 + 1
         big_f_coef.push_back({10, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({9, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({6, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({0, Classic_McEliece_GF(1, modulus)});
         break;
      case 119:  //y^119 + y^8 + 1
         big_f_coef.push_back({8, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({0, Classic_McEliece_GF(1, modulus)});
         break;
      case 128:  // y^128 + y^7 + y^2 + y + 1
         big_f_coef.push_back({7, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({2, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({1, Classic_McEliece_GF(1, modulus)});
         big_f_coef.push_back({0, Classic_McEliece_GF(1, modulus)});
         break;
      default:
         throw Decoding_Error("");
   }

   return big_f_coef;
}
}  //namespace

Classic_McEliece_Parameter_Set Classic_McEliece_Parameters::param_set_from_str(std::string_view param_name) {
   if(param_name == "mceliece348864") {
      return Classic_McEliece_Parameter_Set::mceliece348864;
   }
   if(param_name == "mceliece348864f") {
      return Classic_McEliece_Parameter_Set::mceliece348864f;
   }
   if(param_name == "mceliece460896") {
      return Classic_McEliece_Parameter_Set::mceliece460896;
   }
   if(param_name == "mceliece460896f") {
      return Classic_McEliece_Parameter_Set::mceliece460896f;
   }
   if(param_name == "mceliece6688128") {
      return Classic_McEliece_Parameter_Set::mceliece6688128;
   }
   if(param_name == "mceliece6688128f") {
      return Classic_McEliece_Parameter_Set::mceliece6688128f;
   }
   if(param_name == "mceliece6688128pc") {
      return Classic_McEliece_Parameter_Set::mceliece6688128pc;
   }
   if(param_name == "mceliece6688128pcf") {
      return Classic_McEliece_Parameter_Set::mceliece6688128pcf;
   }
   if(param_name == "mceliece6960119") {
      return Classic_McEliece_Parameter_Set::mceliece6960119;
   }
   if(param_name == "mceliece6960119f") {
      return Classic_McEliece_Parameter_Set::mceliece6960119f;
   }
   if(param_name == "mceliece6960119pc") {
      return Classic_McEliece_Parameter_Set::mceliece6960119pc;
   }
   if(param_name == "mceliece6960119pcf") {
      return Classic_McEliece_Parameter_Set::mceliece6960119pcf;
   }
   if(param_name == "mceliece8192128") {
      return Classic_McEliece_Parameter_Set::mceliece8192128;
   }
   if(param_name == "mceliece8192128f") {
      return Classic_McEliece_Parameter_Set::mceliece8192128f;
   }
   if(param_name == "mceliece8192128pc") {
      return Classic_McEliece_Parameter_Set::mceliece8192128pc;
   }
   if(param_name == "mceliece8192128pcf") {
      return Classic_McEliece_Parameter_Set::mceliece8192128pcf;
   }
   // TODO: Remove on final PR
   if(param_name == "test") {
      return Classic_McEliece_Parameter_Set::test;
   }
   if(param_name == "testf") {
      return Classic_McEliece_Parameter_Set::testf;
   }
   if(param_name == "testpc") {
      return Classic_McEliece_Parameter_Set::testpc;
   }

   throw Decoding_Error("Cannot convert string to CMCE parameter set");
}

Classic_McEliece_Parameters Classic_McEliece_Parameters::create(Classic_McEliece_Parameter_Set set) {
   switch(set) {
      case Classic_McEliece_Parameter_Set::mceliece348864:
      case Classic_McEliece_Parameter_Set::mceliece348864f:
         return Classic_McEliece_Parameters(set, 12, 3488, 64, 0b0001000000001001);

      case Classic_McEliece_Parameter_Set::mceliece460896:
      case Classic_McEliece_Parameter_Set::mceliece460896f:
         return Classic_McEliece_Parameters(set, 13, 4608, 96, 0b0010000000011011);

      case Classic_McEliece_Parameter_Set::mceliece6688128:
      case Classic_McEliece_Parameter_Set::mceliece6688128f:
      case Classic_McEliece_Parameter_Set::mceliece6688128pc:
      case Classic_McEliece_Parameter_Set::mceliece6688128pcf:
         return Classic_McEliece_Parameters(set, 13, 6688, 128, 0b0010000000011011);

      case Classic_McEliece_Parameter_Set::mceliece6960119:
      case Classic_McEliece_Parameter_Set::mceliece6960119f:
      case Classic_McEliece_Parameter_Set::mceliece6960119pc:
      case Classic_McEliece_Parameter_Set::mceliece6960119pcf:
         return Classic_McEliece_Parameters(set, 13, 6960, 119, 0b0010000000011011);

      case Classic_McEliece_Parameter_Set::mceliece8192128:
      case Classic_McEliece_Parameter_Set::mceliece8192128f:
      case Classic_McEliece_Parameter_Set::mceliece8192128pc:
      case Classic_McEliece_Parameter_Set::mceliece8192128pcf:
         return Classic_McEliece_Parameters(set, 13, 8192, 128, 0b0010000000011011);

      case Classic_McEliece_Parameter_Set::toy:
         return Classic_McEliece_Parameters(set, 4, 6688, 128, 0b0010000000011011);

      case Botan::Classic_McEliece_Parameter_Set::test:
      case Botan::Classic_McEliece_Parameter_Set::testf:
      case Botan::Classic_McEliece_Parameter_Set::testpc:
         return Classic_McEliece_Parameters(set, 8, 40, 4, 0b0000000110000111);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

Classic_McEliece_Parameters Classic_McEliece_Parameters::create(std::string_view name) {
   return Classic_McEliece_Parameters::create(param_set_from_str(name));
}

Classic_McEliece_Parameters Classic_McEliece_Parameters::create(const OID& oid) {
   auto param_set = param_set_from_oid(oid);
   return create(param_set);
}

Classic_McEliece_Parameter_Set Classic_McEliece_Parameters::param_set_from_oid(const OID& oid) {
   return Classic_McEliece_Parameters::param_set_from_str(oid.to_formatted_string());
}

OID Classic_McEliece_Parameters::object_identifier() const {
   return OID::from_string(str_from_param_set(m_set));
}

Classic_McEliece_Parameters::Classic_McEliece_Parameters(
   Classic_McEliece_Parameter_Set param_set, size_t m, size_t n, size_t t, uint16_t poly_f) :
      m_set(param_set), m_m(m), m_n(n), m_t(t), m_poly_f(poly_f) {
   BOTAN_ASSERT(n % 8 == 0, "We require that n is a multiple of 8");
   auto poly_big_f_coef = determine_big_f_coef(m_t, poly_f);
   // TODO: Remove from constructor
   m_poly_ring = std::make_unique<Classic_McEliece_Polynomial_Ring>(poly_big_f_coef, poly_f, t);
}

size_t Classic_McEliece_Parameters::estimated_strength() const {
   // Classic McEliece NIST Round 4 submission, Guide for security reviewers, Table 1:
   // For each instance, the minimal strength against the best attack (with free memory access)
   // is used as the overall security strength estimate. The strength is capped at 256, since the
   // seed is only 256 bits long.
   switch(n()) {
      case 3488:
         return 140;
      case 4608:
         return 179;
      case 6688:
         return 246;
      case 6960:
         return 245;
      case 8192:
         return 256;  // 275 in the document. Capped at 256 because of the seed length.
      default:
         throw Decoding_Error("Strength for parameter set ist not registed.");
   }
   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan
