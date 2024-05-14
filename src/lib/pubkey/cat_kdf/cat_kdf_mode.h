/**
* Modes for CatKDF (TS 103 744 - V1.1.1)
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CAT_KDF_MODE_H_
#define BOTAN_CAT_KDF_MODE_H_

#include <botan/ecdh.h>
#include <botan/hybrid_kem.h>
#include <botan/kyber.h>
#include <botan/pk_algs.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

namespace Botan {

class Cat_Kdf_Mode {
   public:
      Cat_Kdf_Mode(std::string_view ecdh_group,
                   std::string_view pqc_algo,
                   std::string_view pqc_algo_params,
                   std::string_view hash_algo) :
            m_ecdh_group_name(ecdh_group),
            m_ecdh_group(EC_Group(ecdh_group)),
            m_pqc_algo(pqc_algo),
            m_pqc_algo_params(pqc_algo_params),
            m_hash_algo(hash_algo) {}

      Cat_Kdf_Mode(const AlgorithmIdentifier& /*alg_id*/) {
         m_ecdh_group_name = "secp256r1";
         m_ecdh_group = EC_Group(m_ecdh_group_name);
         m_pqc_algo = "Kyber";
         m_pqc_algo_params = "Kyber-512-r3";
         m_hash_algo = "SHA-256";
         // TODO: implement for other combinations
      }

      std::string algo_name() const { return "TODO"; };

      // std::unique_ptr<HashFunction> create_hash_instance() const { return HashFunction::create_or_throw(m_hash_algo); }

      AlgorithmIdentifier ecdh_algo_id() const {
         return AlgorithmIdentifier(OID::from_string("ECDH"),
                                    EC_Group(ecdh_group_name()).DER_encode(EC_Group_Encoding::Explicit));
      }

      AlgorithmIdentifier pqc_algo_id() const {
         // For Kyber
         return AlgorithmIdentifier(OID::from_string(m_pqc_algo_params), AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      const std::string& ecdh_group_name() const { return m_ecdh_group_name; }

      const EC_Group& ecdh_group() const { return m_ecdh_group; }

      const std::string& pqc_algo() const { return m_pqc_algo; }

      const std::string& pqc_algo_params() const { return m_pqc_algo_params; }

      const std::string& hash_algo() const { return m_hash_algo; }

      size_t ecdh_pk_length() const {
         EC_Group ec_group(m_ecdh_group_name);
         return ec_group.get_p_bytes();
      }

      size_t ecdh_sk_length() const {
         EC_Group ec_group(m_ecdh_group_name);
         return ec_group.get_order_bytes();
      }

      size_t pqc_pk_length() const {
         if(m_pqc_algo == "Kyber") {
            const auto kyber_const = KyberConstants(KyberMode(m_pqc_algo_params));
            return kyber_const.public_key_byte_length();
         }
         throw Not_Implemented("PQC Algorithm not supported");
      }

      size_t pqc_sk_length() const {
         if(m_pqc_algo == "Kyber") {
            const auto kyber_const = KyberConstants(KyberMode(m_pqc_algo_params));
            return kyber_const.private_key_byte_length();
         }
         throw Not_Implemented("PQC Algorithm not supported");
      }

      size_t pk_length() const { return ecdh_pk_length() + pqc_pk_length(); }

      size_t sk_length() const { return ecdh_sk_length() + pqc_sk_length(); }

   private:
      std::string m_ecdh_group_name;
      EC_Group m_ecdh_group;
      std::string m_pqc_algo;
      std::string m_pqc_algo_params;
      std::string m_hash_algo;
};

}  // namespace Botan

#endif  // BOTAN_CAT_KDF_MODE_H_
