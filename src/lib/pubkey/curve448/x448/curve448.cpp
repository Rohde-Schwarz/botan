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
#include <botan/internal/ct_utils.h>
#include <botan/internal/curve448_internal.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

namespace {
void curve448_basepoint_from_data(std::span<uint8_t, X448_LEN> mypublic, std::span<const uint8_t, X448_LEN> secret) {
   auto bp = x448_basepoint(decode_scalar(secret));
   auto bp_bytes = encode_point(bp);
   copy_mem(mypublic, bp_bytes);
}

secure_vector<uint8_t> ber_decode_sk(std::span<const uint8_t> key_bits) {
   secure_vector<uint8_t> decoded_bits;
   BER_Decoder(key_bits).decode(decoded_bits, ASN1_Type::OctetString).verify_end();
   BOTAN_ASSERT_NOMSG(decoded_bits.size() == X448_LEN);
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
   return public_value();
}

std::unique_ptr<Private_Key> Curve448_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Curve448_PrivateKey>(rng);
}

Curve448_PublicKey::Curve448_PublicKey(const AlgorithmIdentifier& /*alg_id*/, std::span<const uint8_t> key_bits) :
      Curve448_PublicKey(key_bits) {}

Curve448_PublicKey::Curve448_PublicKey(std::span<const uint8_t> pub) {
   BOTAN_ARG_CHECK(pub.size() == X448_LEN, "Invalid size for Curve448 public key");
   copy_mem(m_public, pub);
}

Curve448_PrivateKey::Curve448_PrivateKey(const AlgorithmIdentifier& /*alg_id*/, std::span<const uint8_t> key_bits) :
      Curve448_PrivateKey(ber_decode_sk(key_bits)) {}

Curve448_PrivateKey::Curve448_PrivateKey(std::span<const uint8_t> secret_key) {
   BOTAN_ARG_CHECK(secret_key.size() == X448_LEN, "Invalid size for Curve448 private key");
   m_private = {secret_key.begin(), secret_key.end()};
   curve448_basepoint_from_data(m_public, std::span(m_private).first<X448_LEN>());
}

Curve448_PrivateKey::Curve448_PrivateKey(RandomNumberGenerator& rng) {
   m_private.resize(X448_LEN);
   rng.randomize(m_private);
   curve448_basepoint_from_data(m_public, std::span(m_private).first<X448_LEN>());
}

std::unique_ptr<Public_Key> Curve448_PrivateKey::public_key() const {
   return std::make_unique<Curve448_PublicKey>(public_value());
}

secure_vector<uint8_t> Curve448_PrivateKey::private_key_bits() const {
   return DER_Encoder().encode(m_private, ASN1_Type::OctetString).get_contents();
}

bool Curve448_PrivateKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   std::array<uint8_t, X448_LEN> public_point;
   BOTAN_ASSERT_NOMSG(m_private.size() == X448_LEN);
   curve448_basepoint_from_data(public_point, std::span(m_private).first<X448_LEN>());
   return CT::is_equal(public_point.data(), m_public.data(), m_public.size()).as_bool();
}

namespace {

/**
* Curve448 operation
*/
class Curve448_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF {
   public:
      Curve448_KA_Operation(std::span<const uint8_t> sk, std::string_view kdf) :
            PK_Ops::Key_Agreement_with_KDF(kdf), m_sk(sk.begin(), sk.end()) {
         BOTAN_ARG_CHECK(sk.size() == X448_LEN, "Invalid size for Curve448 private key");
      }

      size_t agreed_value_size() const override { return X448_LEN; }

      secure_vector<uint8_t> raw_agree(const uint8_t w_data[], size_t w_len) override {
         std::span<const uint8_t> w(w_data, w_len);
         BOTAN_ARG_CHECK(w.size() == X448_LEN, "Invalid size for Curve448 private key");
         BOTAN_ASSERT_NOMSG(m_sk.size() == X448_LEN);
         const auto k = decode_scalar(m_sk);
         const auto u = decode_point(w);

         return encode_point(x448(k, u));
      }

   private:
      secure_vector<uint8_t> m_sk;
};

}  // namespace

std::unique_ptr<PK_Ops::Key_Agreement> Curve448_PrivateKey::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                                                                    std::string_view params,
                                                                                    std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<Curve448_KA_Operation>(m_private, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
