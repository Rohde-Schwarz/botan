/*
* Curve448
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_CURVE_448_H_
#define BOTAN_CURVE_448_H_

#include <botan/pk_keys.h>

#include <array>

namespace Botan {
class BOTAN_PUBLIC_API(3, 4) Curve448_PublicKey : public virtual Public_Key {
   public:
      /**
      * Create a Curve25519 Public Key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      Curve448_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      /**
      * Create a Curve448 Public Key.
      * @param pub 56-byte raw public key
      */
      explicit Curve448_PublicKey(std::span<const uint8_t> pub);

      std::string algo_name() const override { return "Curve448"; }

      size_t estimated_strength() const override { return 224; }

      size_t key_length() const override { return 448; }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<uint8_t> public_value() const { return {m_public.begin(), m_public.end()}; }

      std::vector<uint8_t> public_key_bits() const override;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::KeyAgreement); }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

   protected:
      Curve448_PublicKey() = default;
      std::array<uint8_t, 56> m_public;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 4) Curve448_PrivateKey final : public Curve448_PublicKey,
                                                         public virtual Private_Key,
                                                         public virtual PK_Key_Agreement_Key {
   public:
      /**
      * Construct a private key from the specified parameters.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits PKCS #8 structure
      */
      Curve448_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      /**
      * Generate a private key.
      * @param rng the RNG to use
      */
      explicit Curve448_PrivateKey(RandomNumberGenerator& rng);

      /**
      * Construct a private key from the specified parameters.
      * @param secret_key the private key
      */
      explicit Curve448_PrivateKey(std::span<const uint8_t> secret_key);

      std::vector<uint8_t> public_value() const override { return Curve448_PublicKey::public_key_bits(); }

      secure_vector<uint8_t> agree(std::span<const uint8_t> w) const;

      secure_vector<uint8_t> raw_private_key_bits() const override { return {m_private.begin(), m_private.end()}; }

      secure_vector<uint8_t> private_key_bits() const override;

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::Key_Agreement> create_key_agreement_op(RandomNumberGenerator& rng,
                                                                     std::string_view params,
                                                                     std::string_view provider) const override;

   private:
      std::array<uint8_t, 56> m_private;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
