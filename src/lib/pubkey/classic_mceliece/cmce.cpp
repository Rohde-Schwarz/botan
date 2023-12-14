/*
 * Classic McEliece Key Generation
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/cmce.h>
#include <botan/rng.h>
#include <botan/internal/bitvector.h>
#include <botan/internal/cmce_debug_utils.h>
#include <botan/internal/cmce_decaps.h>
#include <botan/internal/cmce_encaps.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_keys_internal.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/pk_ops.h>
#include <botan/internal/pk_ops_impl.h>

#include <algorithm>

namespace Botan {

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(Classic_McEliece_Parameter_Set set,
                                                       std::vector<uint8_t> pub_key) {
   // TODO: ASSERT Correct key length + correct zero padding in matrix?
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(Classic_McEliece_Parameters::create(set),
                                                                   Classic_McEliece_Matrix(std::move(pub_key)));
}

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(const AlgorithmIdentifier& alg_id,
                                                       std::vector<uint8_t> key_bits) {
   // TODO: ASSERT Correct key length + correct zero padding in matrix?
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(Classic_McEliece_Parameters::create(alg_id.oid()),
                                                                   Classic_McEliece_Matrix(std::move(key_bits)));
}

Classic_McEliece_PublicKey::Classic_McEliece_PublicKey(const Classic_McEliece_PublicKey& other) {
   m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(*other.m_public);
}

Classic_McEliece_PublicKey& Classic_McEliece_PublicKey::operator=(const Classic_McEliece_PublicKey& other) {
   if(this != &other) {
      m_public = std::make_shared<Classic_McEliece_PublicKeyInternal>(*other.m_public);
   }
   return *this;
}

AlgorithmIdentifier Classic_McEliece_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Classic_McEliece_PublicKey::object_identifier() const {
   return m_public->params().object_identifier();
}

size_t Classic_McEliece_PublicKey::key_length() const {
   return m_public->matrix().bytes().size();
}

size_t Classic_McEliece_PublicKey::estimated_strength() const {
   throw Not_Implemented("TODO");
}

std::vector<uint8_t> Classic_McEliece_PublicKey::public_key_bits() const {
   return m_public->matrix().bytes();
}

bool Classic_McEliece_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   //TODO: How to check CMCE key
   return true;
}

std::unique_ptr<Private_Key> Classic_McEliece_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Classic_McEliece_PrivateKey>(rng, m_public->params().set());
}

std::unique_ptr<PK_Ops::KEM_Encryption> Classic_McEliece_PublicKey::create_kem_encryption_op(
   std::string_view, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      return std::make_unique<Classic_McEliece_Encryptor>(this->m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(RandomNumberGenerator& rng,
                                                         Classic_McEliece_Parameter_Set param_set) {
   auto params = Classic_McEliece_Parameters::create(param_set);
   auto key_pair = Classic_McEliece_KeyPair_Internal::generate(params, rng.random_vec(params.seed_len()));

   m_private = key_pair.private_key;
   m_public = key_pair.public_key;
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(std::span<const uint8_t> sk,
                                                         Classic_McEliece_Parameter_Set param_set) {
   auto params = Classic_McEliece_Parameters::create(param_set);
   auto sk_internal = Classic_McEliece_PrivateKeyInternal::from_bytes(params, sk);
   m_private = std::make_shared<Classic_McEliece_PrivateKeyInternal>(std::move(sk_internal));
   m_public = nullptr;  // TODO: Create public key from sk
}

Classic_McEliece_PrivateKey::Classic_McEliece_PrivateKey(const AlgorithmIdentifier& alg_id,
                                                         std::span<const uint8_t> key_bits) :
      Classic_McEliece_PrivateKey(key_bits, Classic_McEliece_Parameters::param_set_from_oid(alg_id.oid())) {}

std::unique_ptr<Public_Key> Classic_McEliece_PrivateKey::public_key() const {
   return std::make_unique<Classic_McEliece_PublicKey>(*this);
}

secure_vector<uint8_t> Classic_McEliece_PrivateKey::private_key_bits() const {
   return raw_private_key_bits();
}

secure_vector<uint8_t> Classic_McEliece_PrivateKey::raw_private_key_bits() const {
   return m_private->serialize();
}

std::unique_ptr<PK_Ops::KEM_Decryption> Classic_McEliece_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view params, std::string_view provider) const {
   BOTAN_UNUSED(rng, params);
   if(provider.empty() || provider == "base") {
      return std::make_unique<Classic_McEliece_Decryptor>(this->m_private);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
