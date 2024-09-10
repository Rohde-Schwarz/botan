/*
 * SLH-DSA Parameters
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/sp_parameters.h>

#include <botan/concepts.h>
#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>

#include <cmath>

namespace Botan {

namespace {
template <typename... Args>
   requires(std::convertible_to<Args, std::string_view> && ...)
bool str_is_any_of(std::string_view str, Args... args) {
   return ((str == std::string_view(args)) || ...);
}

auto str_any_of_func(std::string_view str) {
   return [=]<typename... Args>(Args... args) { return str_is_any_of(str, args...); };
}

Sphincs_Parameter_Set set_from_name(std::string_view name) {
   auto name_any_of = str_any_of_func(name);

   if(name_any_of("SphincsPlus-sha2-128s-r3.1", "SphincsPlus-shake-128s-r3.1", "SphincsPlus-haraka-128s-r3.1")) {
      return Sphincs_Parameter_Set::Sphincs128Small;
   }
   if(name_any_of("SphincsPlus-sha2-128f-r3.1", "SphincsPlus-shake-128f-r3.1", "SphincsPlus-haraka-128f-r3.1")) {
      return Sphincs_Parameter_Set::Sphincs128Fast;
   }

   if(name_any_of("SphincsPlus-sha2-192s-r3.1", "SphincsPlus-shake-192s-r3.1", "SphincsPlus-haraka-192s-r3.1")) {
      return Sphincs_Parameter_Set::Sphincs192Small;
   }
   if(name_any_of("SphincsPlus-sha2-192f-r3.1", "SphincsPlus-shake-192f-r3.1", "SphincsPlus-haraka-192f-r3.1")) {
      return Sphincs_Parameter_Set::Sphincs192Fast;
   }

   if(name_any_of("SphincsPlus-sha2-256s-r3.1", "SphincsPlus-shake-256s-r3.1", "SphincsPlus-haraka-256s-r3.1")) {
      return Sphincs_Parameter_Set::Sphincs256Small;
   }
   if(name_any_of("SphincsPlus-sha2-256f-r3.1", "SphincsPlus-shake-256f-r3.1", "SphincsPlus-haraka-256f-r3.1")) {
      return Sphincs_Parameter_Set::Sphincs256Fast;
   }
   if(name_any_of("SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s")) {
      return Sphincs_Parameter_Set::SLHDSA128Small;
   }
   if(name_any_of("SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f")) {
      return Sphincs_Parameter_Set::SLHDSA128Fast;
   }
   if(name_any_of("SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s")) {
      return Sphincs_Parameter_Set::SLHDSA192Small;
   }
   if(name_any_of("SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f")) {
      return Sphincs_Parameter_Set::SLHDSA192Fast;
   }
   if(name_any_of("SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s")) {
      return Sphincs_Parameter_Set::SLHDSA256Small;
   }
   if(name_any_of("SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f")) {
      return Sphincs_Parameter_Set::SLHDSA256Fast;
   }

   throw Lookup_Error(fmt("No SphincsPlus parameter set found for: {}", name));
}

Sphincs_Hash_Type hash_from_name(std::string_view name) {
   auto name_any_of = str_any_of_func(name);

   if(name_any_of("SphincsPlus-sha2-128s-r3.1",
                  "SphincsPlus-sha2-128f-r3.1",
                  "SphincsPlus-sha2-192s-r3.1",
                  "SphincsPlus-sha2-192f-r3.1",
                  "SphincsPlus-sha2-256s-r3.1",
                  "SphincsPlus-sha2-256f-r3.1",
                  "SLH-DSA-SHA2-128s",
                  "SLH-DSA-SHA2-128f",
                  "SLH-DSA-SHA2-192s",
                  "SLH-DSA-SHA2-192f",
                  "SLH-DSA-SHA2-256s",
                  "SLH-DSA-SHA2-256f")) {
      return Sphincs_Hash_Type::Sha256;
   }
   if(name_any_of("SphincsPlus-shake-128s-r3.1",
                  "SphincsPlus-shake-128f-r3.1",
                  "SphincsPlus-shake-192s-r3.1",
                  "SphincsPlus-shake-192f-r3.1",
                  "SphincsPlus-shake-256s-r3.1",
                  "SphincsPlus-shake-256f-r3.1",
                  "SLH-DSA-SHAKE-128s",
                  "SLH-DSA-SHAKE-128f",
                  "SLH-DSA-SHAKE-192s",
                  "SLH-DSA-SHAKE-192f",
                  "SLH-DSA-SHAKE-256s",
                  "SLH-DSA-SHAKE-256f")) {
      return Sphincs_Hash_Type::Shake256;
   }
   if(name_any_of("SphincsPlus-haraka-128s-r3.1",
                  "SphincsPlus-haraka-128f-r3.1",
                  "SphincsPlus-haraka-192s-r3.1",
                  "SphincsPlus-haraka-192f-r3.1",
                  "SphincsPlus-haraka-256s-r3.1",
                  "SphincsPlus-haraka-256f-r3.1")) {
      return Sphincs_Hash_Type::Haraka;
   }

   throw Lookup_Error(fmt("No SLH-DSA hash instantiation found for: {}", name));
}

SlhDsaInputMode input_mode_from_name(std::string_view name) {
   auto name_any_of = str_any_of_func(name);

   if(name_any_of("SphincsPlus-sha2-128s-r3.1",
                  "SphincsPlus-sha2-128f-r3.1",
                  "SphincsPlus-sha2-192s-r3.1",
                  "SphincsPlus-sha2-192f-r3.1",
                  "SphincsPlus-sha2-256s-r3.1",
                  "SphincsPlus-sha2-256f-r3.1",
                  "SphincsPlus-shake-128s-r3.1",
                  "SphincsPlus-shake-128f-r3.1",
                  "SphincsPlus-shake-192s-r3.1",
                  "SphincsPlus-shake-192f-r3.1",
                  "SphincsPlus-shake-256s-r3.1",
                  "SphincsPlus-shake-256f-r3.1",
                  "SphincsPlus-haraka-128s-r3.1",
                  "SphincsPlus-haraka-128f-r3.1",
                  "SphincsPlus-haraka-192s-r3.1",
                  "SphincsPlus-haraka-192f-r3.1",
                  "SphincsPlus-haraka-256s-r3.1",
                  "SphincsPlus-haraka-256f-r3.1",
                  "SLH-DSA-SHA2-128s",
                  "SLH-DSA-SHA2-128f",
                  "SLH-DSA-SHA2-192s",
                  "SLH-DSA-SHA2-192f",
                  "SLH-DSA-SHA2-256s",
                  "SLH-DSA-SHA2-256f",
                  "SLH-DSA-SHAKE-128s",
                  "SLH-DSA-SHAKE-128f",
                  "SLH-DSA-SHAKE-192s",
                  "SLH-DSA-SHAKE-192f",
                  "SLH-DSA-SHAKE-256s",
                  "SLH-DSA-SHAKE-256f")) {
      return SlhDsaInputMode::Pure;
   }

   if(name_any_of("Hash-SLH-DSA-SHA2-128s-with-SHA256",
                  "Hash-SLH-DSA-SHA2-128f-with-SHA256",
                  "Hash-SLH-DSA-SHA2-192s-with-SHA512",
                  "Hash-SLH-DSA-SHA2-192f-with-SHA512",
                  "Hash-SLH-DSA-SHA2-256s-with-SHA512",
                  "Hash-SLH-DSA-SHA2-256f-with-SHA512",
                  "Hash-SLH-DSA-SHAKE-128s-with-SHAKE128",
                  "Hash-SLH-DSA-SHAKE-128f-with-SHAKE128",
                  "Hash-SLH-DSA-SHAKE-192s-with-SHAKE256",
                  "Hash-SLH-DSA-SHAKE-192f-with-SHAKE256",
                  "Hash-SLH-DSA-SHAKE-256s-with-SHAKE256",
                  "Hash-SLH-DSA-SHAKE-256f-with-SHAKE256")) {
      return SlhDsaInputMode::PreHash;
   }

   throw Lookup_Error(fmt("No SLH-DSA input mode found for: {}", name));
}

constexpr bool is_slh_dsa_set(Sphincs_Parameter_Set set) {
   switch(set) {
      case Sphincs_Parameter_Set::SLHDSA128Small:
      case Sphincs_Parameter_Set::SLHDSA128Fast:
      case Sphincs_Parameter_Set::SLHDSA192Small:
      case Sphincs_Parameter_Set::SLHDSA192Fast:
      case Sphincs_Parameter_Set::SLHDSA256Small:
      case Sphincs_Parameter_Set::SLHDSA256Fast:
         return true;
      case Sphincs_Parameter_Set::Sphincs128Small:
      case Sphincs_Parameter_Set::Sphincs128Fast:
      case Sphincs_Parameter_Set::Sphincs192Small:
      case Sphincs_Parameter_Set::Sphincs192Fast:
      case Sphincs_Parameter_Set::Sphincs256Small:
      case Sphincs_Parameter_Set::Sphincs256Fast:
         return false;
   }
   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace

Sphincs_Parameters::Sphincs_Parameters(Sphincs_Parameter_Set set,
                                       Sphincs_Hash_Type hash_type,
                                       SlhDsaInputMode input_mode,
                                       uint32_t n,
                                       uint32_t h,
                                       uint32_t d,
                                       uint32_t a,
                                       uint32_t k,
                                       uint32_t w,
                                       uint32_t bitsec) :
      m_set(set),
      m_hash_type(hash_type),
      m_input_mode(input_mode),
      m_n(n),
      m_h(h),
      m_d(d),
      m_a(a),
      m_k(k),
      m_w(w),
      m_bitsec(bitsec) {
   BOTAN_ARG_CHECK(!(hash_type == Sphincs_Hash_Type::Haraka && is_slh_dsa_set(set)),
                   "Haraka is not available for SLH-DSA");
   BOTAN_ARG_CHECK(!(!is_slh_dsa_set(set) && input_mode == SlhDsaInputMode::PreHash),
                   "Pre-hash mode not available for SPHINCS+ instances");
   BOTAN_ARG_CHECK(w == 4 || w == 16 || w == 256, "Winternitz parameter must be one of 4, 16, 256");
   BOTAN_ARG_CHECK(n == 16 || n == 24 || n == 32, "n must be one of 16, 24, 32");
   BOTAN_ARG_CHECK(m_d > 0, "d must be greater than zero");

   m_xmss_tree_height = m_h / m_d;
   m_lg_w = ceil_log2(m_w);

   // base_2^b algorithm (Fips 205, Algorithm 4) only works
   // when m_log_w is a divisor of 8.
   BOTAN_ASSERT_NOMSG(m_lg_w <= 8 && 8 % m_lg_w == 0);

   // # Winternitz blocks of the message (len_1 of FIPS 205, Algorithm 1)
   m_wots_len1 = (m_n * 8) / m_lg_w;

   // # Winternitz blocks of the checksum (output of FIPS 205 Algorithm 1)
   m_wots_len2 = ceil_log2(m_wots_len1 * (m_w - 1)) / m_lg_w + 1;

   // # Winternitz blocks in the signature (len of FIPS 205, Equation 5.4)
   m_wots_len = m_wots_len1 + m_wots_len2;

   // byte length of WOTS+ signature as well as public key
   m_wots_bytes = m_wots_len * m_n;

   // # of bytes the WOTS+ checksum consists of
   m_wots_checksum_bytes = ceil_tobytes(m_wots_len2 * m_lg_w);

   m_fors_sig_bytes = (m_a + 1) * m_k * m_n;

   // byte length of the FORS input message
   m_fors_message_bytes = ceil_tobytes(m_k * m_a);

   m_xmss_sig_bytes = m_wots_bytes + m_xmss_tree_height * m_n;
   m_ht_sig_bytes = m_d * m_xmss_sig_bytes;
   m_sp_sig_bytes = m_n /* random */ + m_fors_sig_bytes + m_ht_sig_bytes;

   m_tree_digest_bytes = ceil_tobytes(m_h - m_xmss_tree_height);
   m_leaf_digest_bytes = ceil_tobytes(m_xmss_tree_height);
   m_h_msg_digest_bytes = m_fors_message_bytes + m_tree_digest_bytes + m_leaf_digest_bytes;
}

bool Sphincs_Parameters::is_available() const {
   [[maybe_unused]] bool is_slh_dsa = is_slh_dsa_set(m_set);
#ifdef BOTAN_HAS_SLH_DSA_WITH_SHA2
   if(is_slh_dsa && m_hash_type == Sphincs_Hash_Type::Sha256) {
      return m_input_mode == SlhDsaInputMode::Pure;
   }
#endif
#ifdef BOTAN_HAS_SLH_DSA_WITH_SHAKE
   if(is_slh_dsa && m_hash_type == Sphincs_Hash_Type::Shake256) {
      return m_input_mode == SlhDsaInputMode::Pure;
   }
#endif
#ifdef BOTAN_HAS_SPHINCS_PLUS_WITH_SHA2
   if(!is_slh_dsa && m_hash_type == Sphincs_Hash_Type::Sha256) {
      return m_input_mode == SlhDsaInputMode::Pure;
   }
#endif
#ifdef BOTAN_HAS_SPHINCS_PLUS_SHAKE_BASED
   if(!is_slh_dsa && m_hash_type == Sphincs_Hash_Type::Shake256) {
      return m_input_mode == SlhDsaInputMode::Pure;
   }
#endif
   return false;
}

Sphincs_Parameters Sphincs_Parameters::create(Sphincs_Parameter_Set set,
                                              Sphincs_Hash_Type hash,
                                              SlhDsaInputMode input_mode) {
   // See FIPS 205, Table 2
   switch(set) {
      case Sphincs_Parameter_Set::Sphincs128Small:
      case Sphincs_Parameter_Set::SLHDSA128Small:
         return Sphincs_Parameters(set, hash, input_mode, 16, 63, 7, 12, 14, 16, 133);
      case Sphincs_Parameter_Set::Sphincs128Fast:
      case Sphincs_Parameter_Set::SLHDSA128Fast:
         return Sphincs_Parameters(set, hash, input_mode, 16, 66, 22, 6, 33, 16, 128);

      case Sphincs_Parameter_Set::Sphincs192Small:
      case Sphincs_Parameter_Set::SLHDSA192Small:
         return Sphincs_Parameters(set, hash, input_mode, 24, 63, 7, 14, 17, 16, 193);
      case Sphincs_Parameter_Set::Sphincs192Fast:
      case Sphincs_Parameter_Set::SLHDSA192Fast:
         return Sphincs_Parameters(set, hash, input_mode, 24, 66, 22, 8, 33, 16, 194);

      case Sphincs_Parameter_Set::Sphincs256Small:
      case Sphincs_Parameter_Set::SLHDSA256Small:
         return Sphincs_Parameters(set, hash, input_mode, 32, 64, 8, 14, 22, 16, 255);
      case Sphincs_Parameter_Set::Sphincs256Fast:
      case Sphincs_Parameter_Set::SLHDSA256Fast:
         return Sphincs_Parameters(set, hash, input_mode, 32, 68, 17, 9, 35, 16, 255);
   }
   BOTAN_ASSERT_UNREACHABLE();
}

Sphincs_Parameters Sphincs_Parameters::create(std::string_view name) {
   return Sphincs_Parameters::create(set_from_name(name), hash_from_name(name), input_mode_from_name(name));
}

bool Sphincs_Parameters::is_slh_dsa() const {
   return is_slh_dsa_set(m_set);
}

std::string Sphincs_Parameters::hash_name() const {
   switch(m_hash_type) {
      case Sphincs_Hash_Type::Sha256:
         return "SHA-256";
      case Sphincs_Hash_Type::Shake256:
         return fmt("SHAKE-256({})", 8 * n());
      case Sphincs_Hash_Type::Haraka:
         return "Haraka";
   }
   BOTAN_ASSERT_UNREACHABLE();
}

std::string Sphincs_Parameters::to_string() const {
   if(hash_type() == Sphincs_Hash_Type::Sha256 && input_mode() == SlhDsaInputMode::Pure) {
      switch(parameter_set()) {
         case Sphincs_Parameter_Set::Sphincs128Small:
            return "SphincsPlus-sha2-128s-r3.1";
         case Sphincs_Parameter_Set::Sphincs128Fast:
            return "SphincsPlus-sha2-128f-r3.1";
         case Sphincs_Parameter_Set::Sphincs192Small:
            return "SphincsPlus-sha2-192s-r3.1";
         case Sphincs_Parameter_Set::Sphincs192Fast:
            return "SphincsPlus-sha2-192f-r3.1";
         case Sphincs_Parameter_Set::Sphincs256Small:
            return "SphincsPlus-sha2-256s-r3.1";
         case Sphincs_Parameter_Set::Sphincs256Fast:
            return "SphincsPlus-sha2-256f-r3.1";

         case Sphincs_Parameter_Set::SLHDSA128Small:
            return "SLH-DSA-SHA2-128s";
         case Sphincs_Parameter_Set::SLHDSA128Fast:
            return "SLH-DSA-SHA2-128f";
         case Sphincs_Parameter_Set::SLHDSA192Small:
            return "SLH-DSA-SHA2-192s";
         case Sphincs_Parameter_Set::SLHDSA192Fast:
            return "SLH-DSA-SHA2-192f";
         case Sphincs_Parameter_Set::SLHDSA256Small:
            return "SLH-DSA-SHA2-256s";
         case Sphincs_Parameter_Set::SLHDSA256Fast:
            return "SLH-DSA-SHA2-256f";
      }
   }

   if(hash_type() == Sphincs_Hash_Type::Sha256 && input_mode() == SlhDsaInputMode::PreHash) {
      switch(parameter_set()) {
         case Sphincs_Parameter_Set::Sphincs128Small:
         case Sphincs_Parameter_Set::Sphincs128Fast:
         case Sphincs_Parameter_Set::Sphincs192Small:
         case Sphincs_Parameter_Set::Sphincs192Fast:
         case Sphincs_Parameter_Set::Sphincs256Small:
         case Sphincs_Parameter_Set::Sphincs256Fast:
            throw Invalid_Argument("Cannot serialize invalid parameter combination");

         case Sphincs_Parameter_Set::SLHDSA128Small:
            return "Hash-SLH-DSA-SHA2-128s-with-SHA256";
         case Sphincs_Parameter_Set::SLHDSA128Fast:
            return "Hash-SLH-DSA-SHA2-128f-with-SHA256";
         case Sphincs_Parameter_Set::SLHDSA192Small:
            return "Hash-SLH-DSA-SHA2-192s-with-SHA512";
         case Sphincs_Parameter_Set::SLHDSA192Fast:
            return "Hash-SLH-DSA-SHA2-192f-with-SHA512";
         case Sphincs_Parameter_Set::SLHDSA256Small:
            return "Hash-SLH-DSA-SHA2-256s-with-SHA512";
         case Sphincs_Parameter_Set::SLHDSA256Fast:
            return "Hash-SLH-DSA-SHA2-256f-with-SHA512";
      }
   }

   if(hash_type() == Sphincs_Hash_Type::Shake256 && input_mode() == SlhDsaInputMode::Pure) {
      switch(parameter_set()) {
         case Sphincs_Parameter_Set::Sphincs128Small:
            return "SphincsPlus-shake-128s-r3.1";
         case Sphincs_Parameter_Set::Sphincs128Fast:
            return "SphincsPlus-shake-128f-r3.1";
         case Sphincs_Parameter_Set::Sphincs192Small:
            return "SphincsPlus-shake-192s-r3.1";
         case Sphincs_Parameter_Set::Sphincs192Fast:
            return "SphincsPlus-shake-192f-r3.1";
         case Sphincs_Parameter_Set::Sphincs256Small:
            return "SphincsPlus-shake-256s-r3.1";
         case Sphincs_Parameter_Set::Sphincs256Fast:
            return "SphincsPlus-shake-256f-r3.1";

         case Sphincs_Parameter_Set::SLHDSA128Small:
            return "SLH-DSA-SHAKE-128s";
         case Sphincs_Parameter_Set::SLHDSA128Fast:
            return "SLH-DSA-SHAKE-128f";
         case Sphincs_Parameter_Set::SLHDSA192Small:
            return "SLH-DSA-SHAKE-192s";
         case Sphincs_Parameter_Set::SLHDSA192Fast:
            return "SLH-DSA-SHAKE-192f";
         case Sphincs_Parameter_Set::SLHDSA256Small:
            return "SLH-DSA-SHAKE-256s";
         case Sphincs_Parameter_Set::SLHDSA256Fast:
            return "SLH-DSA-SHAKE-256f";
      }
   }

   if(hash_type() == Sphincs_Hash_Type::Shake256 && input_mode() == SlhDsaInputMode::PreHash) {
      switch(parameter_set()) {
         case Sphincs_Parameter_Set::Sphincs128Small:
         case Sphincs_Parameter_Set::Sphincs128Fast:
         case Sphincs_Parameter_Set::Sphincs192Small:
         case Sphincs_Parameter_Set::Sphincs192Fast:
         case Sphincs_Parameter_Set::Sphincs256Small:
         case Sphincs_Parameter_Set::Sphincs256Fast:
            throw Invalid_Argument("Cannot serialize invalid parameter combination");

         case Sphincs_Parameter_Set::SLHDSA128Small:
            return "Hash-SLH-DSA-SHAKE-128s-with-SHAKE128";
         case Sphincs_Parameter_Set::SLHDSA128Fast:
            return "Hash-SLH-DSA-SHAKE-128f-with-SHAKE128";
         case Sphincs_Parameter_Set::SLHDSA192Small:
            return "Hash-SLH-DSA-SHAKE-192s-with-SHAKE256";
         case Sphincs_Parameter_Set::SLHDSA192Fast:
            return "Hash-SLH-DSA-SHAKE-192f-with-SHAKE256";
         case Sphincs_Parameter_Set::SLHDSA256Small:
            return "Hash-SLH-DSA-SHAKE-256s-with-SHAKE256";
         case Sphincs_Parameter_Set::SLHDSA256Fast:
            return "Hash-SLH-DSA-SHAKE-256f-with-SHAKE256";
      }
   }

   if(hash_type() == Sphincs_Hash_Type::Haraka && input_mode() == SlhDsaInputMode::Pure) {
      switch(parameter_set()) {
         case Sphincs_Parameter_Set::Sphincs128Small:
            return "SphincsPlus-haraka-128s-r3.1";
         case Sphincs_Parameter_Set::Sphincs128Fast:
            return "SphincsPlus-haraka-128f-r3.1";
         case Sphincs_Parameter_Set::Sphincs192Small:
            return "SphincsPlus-haraka-192s-r3.1";
         case Sphincs_Parameter_Set::Sphincs192Fast:
            return "SphincsPlus-haraka-192f-r3.1";
         case Sphincs_Parameter_Set::Sphincs256Small:
            return "SphincsPlus-haraka-256s-r3.1";
         case Sphincs_Parameter_Set::Sphincs256Fast:
            return "SphincsPlus-haraka-256f-r3.1";

         case Sphincs_Parameter_Set::SLHDSA128Small:
         case Sphincs_Parameter_Set::SLHDSA128Fast:
         case Sphincs_Parameter_Set::SLHDSA192Small:
         case Sphincs_Parameter_Set::SLHDSA192Fast:
         case Sphincs_Parameter_Set::SLHDSA256Small:
         case Sphincs_Parameter_Set::SLHDSA256Fast:
            throw Invalid_Argument("Cannot serialize invalid parameter combination");
      }
   }
   throw Invalid_Argument("Cannot serialize invalid parameter combination");
}

Sphincs_Parameters Sphincs_Parameters::create(const OID& oid) {
   return Sphincs_Parameters::create(oid.to_formatted_string());
}

OID Sphincs_Parameters::object_identifier() const {
   return OID::from_string(to_string());
}

AlgorithmIdentifier Sphincs_Parameters::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

}  // namespace Botan
