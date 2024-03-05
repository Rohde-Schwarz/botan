/*
* Curve448
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/curve448.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/rng.h>
#include <botan/internal/curve448_internal.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

namespace {
void curve448_basepoint_from_data(std::span<uint8_t, 56> mypublic, std::span<const uint8_t, 56> secret) {
   auto bp = x448_basepoint(decode_scalar(secret));
   auto bp_bytes = encode_point(bp);
   copy_mem(mypublic, bp_bytes);
}

secure_vector<uint8_t> ber_decode_sk(std::span<const uint8_t> key_bits) {
   secure_vector<uint8_t> decoded_bits;
   BER_Decoder(key_bits).decode(decoded_bits, ASN1_Type::OctetString).discard_remaining();
   return decoded_bits;
}

}  // namespace

AlgorithmIdentifier Curve448_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

bool Curve448_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   return true;  // no tests possible?
}

std::vector<uint8_t> Curve448_PublicKey::public_key_bits() const {
   return {m_public.begin(), m_public.end()};
}

std::unique_ptr<Private_Key> Curve448_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Curve448_PrivateKey>(rng);
}

Curve448_PublicKey::Curve448_PublicKey(const AlgorithmIdentifier& /*alg_id*/, std::span<const uint8_t> key_bits) :
      Curve448_PublicKey(key_bits) {}

Curve448_PublicKey::Curve448_PublicKey(std::span<const uint8_t> pub) {
   BOTAN_ARG_CHECK(pub.size() == 56, "Invalid size for Curve448 public key");
   copy_mem(m_public, pub);
}

Curve448_PrivateKey::Curve448_PrivateKey(const AlgorithmIdentifier& /*alg_id*/, std::span<const uint8_t> key_bits) :
      Curve448_PrivateKey(ber_decode_sk(key_bits)) {}

Curve448_PrivateKey::Curve448_PrivateKey(std::span<const uint8_t> secret_key) {
   BOTAN_ARG_CHECK(secret_key.size() == 56, "Invalid size for Curve448 private key");
   copy_mem(m_private, secret_key);
   curve448_basepoint_from_data(m_public, m_private);
}

Curve448_PrivateKey::Curve448_PrivateKey(RandomNumberGenerator& rng) {
   rng.randomize(m_private);
   curve448_basepoint_from_data(m_public, m_private);
}

std::unique_ptr<Public_Key> Curve448_PrivateKey::public_key() const {
   return std::make_unique<Curve448_PublicKey>(public_value());
}

secure_vector<uint8_t> Curve448_PrivateKey::private_key_bits() const {
   return DER_Encoder()
      .encode(secure_vector<uint8_t>(m_private.begin(), m_private.end()), ASN1_Type::OctetString)
      .get_contents();
}

bool Curve448_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   std::array<uint8_t, 56> public_point;
   curve448_basepoint_from_data(public_point, m_private);
   return public_point == m_public;
}

secure_vector<uint8_t> Curve448_PrivateKey::agree(std::span<const uint8_t> w) const {
   BOTAN_ARG_CHECK(w.size() == 56, "Invalid size for Curve448 private key");
   auto k = decode_scalar(m_private);
   auto u = decode_point(w);

   return encode_point(x448(k, u));
}

namespace {

/**
* Curve448 operation
*/
class Curve448_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF {
   public:
      Curve448_KA_Operation(const Curve448_PrivateKey& key, std::string_view kdf) :
            PK_Ops::Key_Agreement_with_KDF(kdf), m_key(key) {}

      size_t agreed_value_size() const override { return 56; }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override { return m_key.agree({w, w_len}); }

   private:
      const Curve448_PrivateKey& m_key;
};

}  // namespace

std::unique_ptr<PK_Ops::Key_Agreement> Curve448_PrivateKey::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                                                                    std::string_view params,
                                                                                    std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<Curve448_KA_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
