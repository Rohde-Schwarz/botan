/*
* Classic McEliece Encapsulation
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_ENCAPS_H_
#define BOTAN_CMCE_ENCAPS_H_

#include <botan/pk_keys.h>

#include <botan/cmce.h>
#include <botan/cmce_parameters.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/cmce_poly.h>
#include <botan/internal/pk_ops.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

class Classic_McEliece_Encryptor final : public PK_Ops::KEM_Encryption {
   public:
      Classic_McEliece_Encryptor(std::shared_ptr<Classic_McEliece_PublicKeyInternal> key) : m_key(std::move(key)) {}

      size_t shared_key_length(size_t desired_shared_key_len) const override {
         // TODO: Desired shared key length?
         BOTAN_UNUSED(desired_shared_key_len);
         return m_key->params().hash_out_bytes();
      }

      size_t encapsulated_key_length() const override { return m_key->params().ciphertext_size(); }

      void kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                       std::span<uint8_t> out_shared_key,
                       RandomNumberGenerator& rng,
                       size_t desired_shared_key_len,  // Whats up with these?
                       std::span<const uint8_t> salt) override;

   private:
      std::shared_ptr<Classic_McEliece_PublicKeyInternal> m_key;
};

}  // namespace Botan

#endif  // BOTAN_CMCE_ENCAPS_H_