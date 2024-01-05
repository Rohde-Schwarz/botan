/*
* Classic McEliece Decapsulation
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_DECAPS_H_
#define BOTAN_CMCE_DECAPS_H_

#include <botan/cmce.h>
#include <botan/rng.h>
#include <botan/internal/bitvector.h>
#include <botan/internal/cmce_debug_utils.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/pk_ops.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

/**
 * Classic McEliece Decapsulation Operation
*/
class Classic_McEliece_Decryptor final : public PK_Ops::KEM_Decryption {
   public:
      /**
       * @brief Constructs a Classic_McEliece_Decryptor object with the given private key.
       * @param key The private key used for decryption.
       */
      Classic_McEliece_Decryptor(std::shared_ptr<Classic_McEliece_PrivateKeyInternal> key) : m_key(std::move(key)) {}

      size_t shared_key_length(size_t desired_shared_key_len) const override {
         // TODO: Desired shared key length?
         BOTAN_UNUSED(desired_shared_key_len);
         return m_key->params().hash_out_bytes();
      }

      size_t encapsulated_key_length() const override { return m_key->params().ciphertext_size(); }

      void kem_decrypt(std::span<uint8_t> out_shared_key,
                       std::span<const uint8_t> encapsulated_key,
                       size_t desired_shared_key_len,
                       std::span<const uint8_t> salt) override;

   private:
      /**
       * @brief Computes the syndrome of a code word.
       *
       * @param params The McEliece parameters.
       * @param goppa_poly The Goppa polynomial.
       * @param ordering The field ordering.
       * @param code_word The code word.
       * @return The syndrome of the code word.
       */
      std::vector<Classic_McEliece_GF> compute_goppa_syndrome(const Classic_McEliece_Parameters& params,
                                                              const Classic_McEliece_Minimal_Polynomial& goppa_poly,
                                                              const Classic_McEliece_Field_Ordering& ordering,
                                                              const secure_bitvector& code_word);

      /**
       * @brief Applies the Berlekamp-Massey algorithm to compute the error locator polynomial.
       *
       * @param params The McEliece parameters.
       * @param syndrome The syndrome of the code word.
       * @return The error locator polynomial.
       */
      Classic_McEliece_Polynomial berlekamp_massey(const Classic_McEliece_Parameters& params,
                                                   const std::vector<Classic_McEliece_GF>& syndrome);

      /**
       * @brief Decodes a code word.
       *
       * @param sk The McEliece private key.
       * @param big_c The code word.
       * @return A pair containing the decoded message and the error pattern.
       */
      std::pair<CT::Mask<uint8_t>, secure_bitvector> decode(const Classic_McEliece_PrivateKeyInternal& sk,
                                                            bitvector big_c);

      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> m_key;
};

}  // namespace Botan

#endif  // BOTAN_CMCE_DECAPS_H_