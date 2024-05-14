/**
* Implementation of CatKDF (TS 103 744 - V1.1.1)
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cat_kdf.h>

#include <botan/kdf.h>
#include <botan/kyber.h>
#include <botan/x25519.h>
#include <botan/internal/cat_kdf_internal.h>
#include <botan/internal/hybrid_kem_ops.h>
#include <botan/internal/kex_to_kem_adapter.h>
#include <botan/internal/sha3.h>

namespace Botan {

namespace {

template <typename Alloc>
std::vector<uint8_t> flatten(const std::vector<std::vector<uint8_t, Alloc>>& vec) {
   std::vector<uint8_t, Alloc> flat;
   // TODO: Reserve
   for(const auto& v : vec) {
      flat.insert(flat.end(), v.begin(), v.end());
   }
   return flat;
}

void combine_cts(std::span<uint8_t> out_ciphertext, const std::vector<std::vector<uint8_t>>& ciphertexts) {
   // TODO optimize
   auto full_pk = flatten(ciphertexts);
   BOTAN_ASSERT(full_pk.at(0) == 0x04, "ECDH point must be stored in compressed format");
   copy_mem(out_ciphertext, std::span{full_pk.data() + 1, full_pk.size() - 1});
}

std::vector<uint8_t> combine_cts(const std::vector<std::vector<uint8_t>>& ciphertexts) {
   auto full_pk = flatten(ciphertexts);
   BOTAN_ASSERT(full_pk.at(0) == 0x04, "ECDH point must be stored in compressed format");
   full_pk.erase(full_pk.begin());

   return full_pk;
}

class Cat_Kdf_Encryptor final : public KEM_Encryption_with_Combiner {
   public:
      Cat_Kdf_Encryptor(const Cat_Kdf_PublicKey& public_key, std::string_view provider) :
            KEM_Encryption_with_Combiner(public_key.public_keys(), provider) {
         m_pk_bytes = public_key.public_key_bits();
         m_hash_func = public_key.mode().hash_algo();
      }

      size_t encapsulated_key_length() const override {
         return KEM_Encryption_with_Combiner::encapsulated_key_length() - 1;
      }

      void combine_ciphertexts(std::span<uint8_t> out_ciphertext,
                               const std::vector<std::vector<uint8_t>>& ciphertexts,
                               std::span<const uint8_t> /*salt*/) override {
         combine_cts(out_ciphertext, ciphertexts);
      }

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& ciphertexts,
                                  size_t /*desired_shared_key_len*/,
                                  std::span<const uint8_t> /*salt*/) override {
         Cat_Kdf::cat_kdf_secret_combiner(out_shared_secret,
                                          m_hash_func,
                                          m_pk_bytes,
                                          combine_cts(ciphertexts),
                                          shared_secrets,
                                          {/* psk */},
                                          {/* context */},
                                          {/* label */});
      }

      size_t shared_key_length(size_t desired_shared_key_len) const override { return desired_shared_key_len; }

   private:
      std::vector<uint8_t> m_pk_bytes;
      std::string m_hash_func;
};

class Cat_Kdf_Decryptor final : public KEM_Decryption_with_Combiner {
   public:
      Cat_Kdf_Decryptor(const Cat_Kdf_PrivateKey& private_key,
                        RandomNumberGenerator& rng,
                        const std::string_view provider) :
            KEM_Decryption_with_Combiner(private_key.private_keys(), rng, provider) {
         m_pk_bytes = private_key.public_key()->public_key_bits();
         m_hash_func = private_key.mode().hash_algo();
      }

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const std::vector<secure_vector<uint8_t>>& shared_secrets,
                                  const std::vector<std::vector<uint8_t>>& ciphertexts,
                                  size_t /*desired_shared_key_len*/,
                                  std::span<const uint8_t> /*salt*/) override {
         Cat_Kdf::cat_kdf_secret_combiner(out_shared_secret,
                                          m_hash_func,
                                          m_pk_bytes,
                                          combine_cts(ciphertexts),
                                          shared_secrets,
                                          {/* psk */},
                                          {/* context */},
                                          {/* label */});
      }

      std::vector<std::vector<uint8_t>> split_ciphertexts(std::span<const uint8_t> concat_ciphertext) override {
         BOTAN_ARG_CHECK(concat_ciphertext.size() == encapsulated_key_length(), "Invalid ciphertext length");
         auto ct_extended = concat(std::vector<uint8_t>{0x04}, concat_ciphertext);
         std::vector<std::vector<uint8_t>> ciphertexts;
         ciphertexts.reserve(decryptors().size());
         BufferSlicer ct_slicer(ct_extended);
         for(const auto& decryptor : decryptors()) {
            ciphertexts.push_back(ct_slicer.copy_as_vector(decryptor.encapsulated_key_length()));
         }
         BOTAN_ASSERT_NOMSG(ct_slicer.empty());
         return ciphertexts;
      }

      size_t encapsulated_key_length() const override {
         return KEM_Decryption_with_Combiner::encapsulated_key_length() - 1;
      }

      size_t shared_key_length(size_t desired_shared_key_len) const override { return desired_shared_key_len; }

   private:
      std::vector<uint8_t> m_pk_bytes;
      std::string m_hash_func;
};

std::unique_ptr<KEX_to_KEM_Adapter_PrivateKey> load_ecdh_sk_from_bytes(const secure_vector<uint8_t>& sk_bytes,
                                                                       const Cat_Kdf_Mode& mode) {
   // Sadly the ECDH private key constructor only accepts a DER encoded key. Therefore we need to encode it first.
   auto encoded_sk = DER_Encoder()
                        .start_sequence()
                        .encode(static_cast<size_t>(1) /* version ecPrivkeyVer1 */)
                        .encode(sk_bytes, ASN1_Type::OctetString)
                        .end_cons()
                        .get_contents();

   AlgorithmIdentifier alg_id(OID::from_string("ECDH"),
                              EC_Group(mode.ecdh_group_name()).DER_encode(EC_Group_Encoding::Explicit));

   return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(std::make_unique<ECDH_PrivateKey>(alg_id, encoded_sk));
}

std::unique_ptr<KEX_to_KEM_Adapter_PrivateKey> load_ecdh_pk_from_bytes(std::span<const uint8_t> pk_bytes,
                                                                       const Cat_Kdf_Mode& mode) {
   // According to the test vectors of TS 103 744 - V1.1.1, the ECDH public key is encoded as an
   // uncompressed point without the 0x04 as first byte. To load the public key we need to add the 0x04.
   auto pk_bytes_uncompressed_encoding = concat(std::vector<uint8_t>{0x04}, pk_bytes);

   return std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(
      std::make_unique<ECDH_PrivateKey>(mode.ecdh_algo_id(), pk_bytes_uncompressed_encoding));
}

}  // namespace

Cat_Kdf_PublicKey::Cat_Kdf_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks, const Cat_Kdf_Mode& mode) :
      Hybrid_PublicKey(std::move(pks)), m_mode(mode) {}

Cat_Kdf_PublicKey::Cat_Kdf_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk_bytes) :
      Cat_Kdf_PublicKey(
         [&]() {
            Cat_Kdf_Mode mode(alg_id);
            BOTAN_ARG_CHECK(pk_bytes.size() == mode.pk_length(), "Invalid CatKDF public key size");
            BufferSlicer slicer(pk_bytes);
            std::vector<std::unique_ptr<Public_Key>> pks;
            // TODO: add 0x04
            pks.push_back(load_ecdh_pk_from_bytes(slicer.take(mode.ecdh_pk_length()), mode));
            pks.push_back(load_public_key(mode.pqc_algo_id(), slicer.take(mode.pqc_pk_length())));
            BOTAN_ASSERT_NOMSG(slicer.empty());
            return pks;
         }(),
         Cat_Kdf_Mode(alg_id)) {}

std::string Cat_Kdf_PublicKey::algo_name() const {
   return "CatKDF";
}

AlgorithmIdentifier Cat_Kdf_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(OID::from_string(algo_name()), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

std::unique_ptr<Private_Key> Cat_Kdf_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Cat_Kdf_PrivateKey>(rng, m_mode);
}

std::vector<uint8_t> Cat_Kdf_PublicKey::public_key_bits() const {
   auto full_pk = Hybrid_PublicKey::public_key_bits();
   // The first part of the public key is the ECDH public key. According to the test vectors
   // of TS 103 744 - V1.1.1, the ECDH public key is encoded as an uncompressed point without
   // the 0x04 as first byte. Therefore we need to remove the first byte.
   BOTAN_ASSERT_NOMSG(full_pk.at(0) == 0x04);
   full_pk.erase(full_pk.begin(), full_pk.begin() + 1);
   return full_pk;
}

std::unique_ptr<PK_Ops::KEM_Encryption> Cat_Kdf_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                    std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("CatKDF encryption does not support KDFs");
   }
   return std::make_unique<Cat_Kdf_Encryptor>(*this, provider);
}

std::unique_ptr<Cat_Kdf_PublicKey> Cat_Kdf_PublicKey::from_public_keys(std::vector<std::unique_ptr<Public_Key>> pks,
                                                                       const Cat_Kdf_Mode& mode) {
   return std::unique_ptr<Cat_Kdf_PublicKey>(new Cat_Kdf_PublicKey(std::move(pks), mode));
}

Cat_Kdf_PrivateKey::Cat_Kdf_PrivateKey(RandomNumberGenerator& rng, Cat_Kdf_Mode mode) :
      Cat_Kdf_PrivateKey(
         [&]() {
            std::vector<std::unique_ptr<Private_Key>> sks;
            sks.push_back(std::make_unique<KEX_to_KEM_Adapter_PrivateKey>(
               std::make_unique<ECDH_PrivateKey>(rng, EC_Group(mode.ecdh_group_name()))));
            sks.push_back(create_private_key(mode.pqc_algo(), rng, mode.pqc_algo_params()));

            std::vector<std::unique_ptr<Public_Key>> pks;
            pks.reserve(sks.size());
            for(const auto& sk : sks) {
               pks.push_back(sk->public_key());
            }
            return std::make_pair(std::move(pks), std::move(sks));
         }(),
         mode) {}

Cat_Kdf_PrivateKey::Cat_Kdf_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bytes) :
      Cat_Kdf_PrivateKey(
         [&] {
            Cat_Kdf_Mode mode(alg_id);
            BOTAN_ARG_CHECK(key_bytes.size() == mode.sk_length(), "Invalid CatKDF private key size");
            std::vector<std::unique_ptr<Private_Key>> sks;
            BufferSlicer slicer(key_bytes);
            sks.push_back(load_ecdh_sk_from_bytes(slicer.copy_as_secure_vector(mode.ecdh_sk_length()), mode));
            sks.push_back(load_private_key(mode.pqc_algo_id(), slicer.take(mode.pqc_sk_length())));
            BOTAN_ASSERT_NOMSG(slicer.empty());

            std::vector<std::unique_ptr<Public_Key>> pks = extract_public_keys(sks);

            return std::make_pair(std::move(pks), std::move(sks));
         }(),
         Cat_Kdf_Mode(alg_id)) {}

std::unique_ptr<Public_Key> Cat_Kdf_PrivateKey::public_key() const {
   return from_public_keys(extract_public_keys(private_keys()), mode());
}

secure_vector<uint8_t> Cat_Kdf_PrivateKey::private_key_bits() const {
   // TODO: raw_private_key_bits?
   secure_vector<uint8_t> sk_bytes;
   // TODO: reserve. Or with reduce.
   for(const auto& sk : private_keys()) {
      auto sk_bytes_part = sk->raw_private_key_bits();
      sk_bytes.insert(sk_bytes.end(), sk_bytes_part.begin(), sk_bytes_part.end());
   }
   return sk_bytes;
}

bool Cat_Kdf_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   return Hybrid_PrivateKey::check_key(rng, strong);
}

std::unique_ptr<PK_Ops::KEM_Decryption> Cat_Kdf_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                                     std::string_view params,
                                                                                     std::string_view provider) const {
   if(params != "Raw" && !params.empty()) {
      throw Botan::Invalid_Argument("CatKDF decryption does not support custom KDFs");
   }
   return std::make_unique<Cat_Kdf_Decryptor>(*this, rng, provider);
}

Cat_Kdf_PrivateKey::Cat_Kdf_PrivateKey(
   std::pair<std::vector<std::unique_ptr<Public_Key>>, std::vector<std::unique_ptr<Private_Key>>> key_pairs,
   const Cat_Kdf_Mode& mode) :
      Hybrid_PublicKey(std::move(key_pairs.first)),
      Cat_Kdf_PublicKey(mode),
      Hybrid_PrivateKey(std::move(key_pairs.second)) {}

}  // namespace Botan
