/**
* Implementation of CatKDF (TS 103 744 - V1.1.1)
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CAT_KDF_H_
#define BOTAN_CAT_KDF_H_

#include <botan/cat_kdf_mode.h>
#include <botan/hybrid_kem.h>
#include <botan/pk_algs.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

#include <memory>
#include <vector>

namespace Botan {

/**
 * @brief CatKDF Public Key
 */
class BOTAN_TEST_API Cat_Kdf_PublicKey : public virtual Hybrid_PublicKey {
   public:
      Cat_Kdf_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk_bytes);

      std::string algo_name() const override;
      AlgorithmIdentifier algorithm_identifier() const override;
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      std::vector<uint8_t> public_key_bits() const override;

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(
         std::string_view kdf, std::string_view provider = "base") const override;

      const Cat_Kdf_Mode& mode() const { return m_mode; }

   protected:
      Cat_Kdf_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks, const Cat_Kdf_Mode& mode);
      static std::unique_ptr<Cat_Kdf_PublicKey> from_public_keys(std::vector<std::unique_ptr<Public_Key>> pks,
                                                                 const Cat_Kdf_Mode& mode);
      Cat_Kdf_PublicKey(const Cat_Kdf_Mode& m_mode) : m_mode(m_mode){};

   private:
      Cat_Kdf_Mode m_mode;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * @brief CatKDF Public Key
 */
class BOTAN_TEST_API Cat_Kdf_PrivateKey final : public Cat_Kdf_PublicKey,
                                                public Hybrid_PrivateKey {
   public:
      /// Create a new CatKDF key using the given RNG
      Cat_Kdf_PrivateKey(RandomNumberGenerator& rng, Cat_Kdf_Mode mode);

      /// Load a raw CatKDF private key
      Cat_Kdf_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bytes);

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> private_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(
         RandomNumberGenerator& rng, std::string_view kdf, std::string_view provider = "base") const override;

   private:
      /// Constructor helper. Creates a private key using the underlying public keys and private keys.
      Cat_Kdf_PrivateKey(
         std::pair<std::vector<std::unique_ptr<Public_Key>>, std::vector<std::unique_ptr<Private_Key>>> key_pairs,
         const Cat_Kdf_Mode& mode);
};

}  // namespace Botan

#endif  // BOTAN_CAT_KDF_H_
