/*
* Crystals Dilithium Digital Signature Algorithms
* Based on the public domain reference implementation by the
* designers (https://github.com/pq-crystals/dilithium)
*
* Further changes
* (C) 2021-2023 Jack Lloyd
* (C) 2021-2022 Manuel Glaser - Rohde & Schwarz Cybersecurity
* (C) 2021-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2024      René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dilithium.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/strong_type.h>

#include <botan/internal/dilithium_polynomials.h>
#include <botan/internal/dilithium_types.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/shake.h>
#include <botan/internal/stl_util.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <span>
#include <vector>

namespace Botan {
namespace {

std::pair<Dilithium::PolynomialVector, Dilithium::PolynomialVector> calculate_t0_and_t1(
   const DilithiumModeConstants& mode,
   const std::vector<uint8_t>& rho,
   Dilithium::PolynomialVector s1,
   const Dilithium::PolynomialVector& s2) {
   /* Generate matrix */
   auto matrix = Dilithium::PolynomialMatrix::generate_matrix(rho, mode);

   /* Matrix-vector multiplication */
   s1.ntt();
   auto t = Dilithium::PolynomialVector::generate_polyvec_matrix_pointwise_montgomery(matrix.get_matrix(), s1, mode);
   t.reduce();
   t.invntt_tomont();

   /* Add error vector s2 */
   t.add_polyvec(s2);

   /* Extract t and write public key */
   t.cadd_q();

   Dilithium::PolynomialVector t0(mode.k());
   Dilithium::PolynomialVector t1(mode.k());
   Dilithium::PolynomialVector::fill_polyvecs_power2round(t1, t0, t);

   return {std::move(t0), std::move(t1)};
}

// TODO: this function could be a member of Dilithium::PolynomialVector
//       returning a copy in NTT domain
Dilithium::PolynomialVector ntt(const Dilithium::PolynomialVector& p) {
   auto result = p;
   result.ntt();
   return result;
}

Dilithium::PolynomialMatrix expand_A(const DilithiumModeConstants& mode, StrongSpan<const DilithiumSeedRho> rho) {
   return Dilithium::PolynomialMatrix::generate_matrix(rho, mode);
}

std::pair<Dilithium::PolynomialVector, Dilithium::PolynomialVector> expand_s(
   const DilithiumModeConstants& mode, StrongSpan<const DilithiumSeedRhoPrime> rhoprime) {
   auto result = std::make_pair(Dilithium::PolynomialVector(mode.l()), Dilithium::PolynomialVector(mode.k()));

   Dilithium::PolynomialVector::fill_polyvec_uniform_eta(std::get<0>(result), rhoprime, 0, mode);
   Dilithium::PolynomialVector::fill_polyvec_uniform_eta(std::get<1>(result), rhoprime, mode.l(), mode);

   return result;
}

Dilithium::PolynomialVector expand_mask(const DilithiumModeConstants& mode,
                                        StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                                        uint16_t kappa) {
   // TODO: implement polyvecl_uniform_gamma1 here, using the mode's XOF
   //       to avoid holding the entire sample data in memory
   // auto xof = mode.symmetric_primitives().XOF(Dilithium_Symmetric_Primitives::XofType::k256, rhoprime, kappa);
   Dilithium::PolynomialVector y(mode.l());
   y.polyvecl_uniform_gamma1(rhoprime, kappa, mode);
   return y;
}

std::pair<Dilithium::PolynomialVector, Dilithium::PolynomialVector> power2round(const DilithiumModeConstants& mode,
                                                                                const Dilithium::PolynomialVector& t) {
   auto result = std::make_pair(Dilithium::PolynomialVector(mode.k()), Dilithium::PolynomialVector(mode.k()));
   Dilithium::PolynomialVector::fill_polyvecs_power2round(std::get<0>(result), std::get<1>(result), t);
   return result;
}

DilithiumMode::Mode dilithium_mode_from_string(std::string_view str) {
   if(str == "Dilithium-4x4-r3") {
      return DilithiumMode::Dilithium4x4;
   }
   if(str == "Dilithium-4x4-AES-r3") {
      return DilithiumMode::Dilithium4x4_AES;
   }
   if(str == "Dilithium-6x5-r3") {
      return DilithiumMode::Dilithium6x5;
   }
   if(str == "Dilithium-6x5-AES-r3") {
      return DilithiumMode::Dilithium6x5_AES;
   }
   if(str == "Dilithium-8x7-r3") {
      return DilithiumMode::Dilithium8x7;
   }
   if(str == "Dilithium-8x7-AES-r3") {
      return DilithiumMode::Dilithium8x7_AES;
   }

   throw Invalid_Argument(fmt("'{}' is not a valid Dilithium mode name", str));
}

}  // namespace

DilithiumMode::DilithiumMode(const OID& oid) : m_mode(dilithium_mode_from_string(oid.to_formatted_string())) {}

DilithiumMode::DilithiumMode(std::string_view str) : m_mode(dilithium_mode_from_string(str)) {}

OID DilithiumMode::object_identifier() const {
   return OID::from_string(to_string());
}

std::string DilithiumMode::to_string() const {
   switch(m_mode) {
      case DilithiumMode::Dilithium4x4:
         return "Dilithium-4x4-r3";
      case DilithiumMode::Dilithium4x4_AES:
         return "Dilithium-4x4-AES-r3";
      case DilithiumMode::Dilithium6x5:
         return "Dilithium-6x5-r3";
      case DilithiumMode::Dilithium6x5_AES:
         return "Dilithium-6x5-AES-r3";
      case DilithiumMode::Dilithium8x7:
         return "Dilithium-8x7-r3";
      case DilithiumMode::Dilithium8x7_AES:
         return "Dilithium-8x7-AES-r3";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

class Dilithium_PublicKeyInternal {
   public:
      Dilithium_PublicKeyInternal(DilithiumModeConstants mode) : m_mode(std::move(mode)) {}

      Dilithium_PublicKeyInternal(DilithiumModeConstants mode, StrongSpan<const DilithiumSerializedPublicKey> raw_pk) :
            m_mode(std::move(mode)) {
         BOTAN_ASSERT_NOMSG(raw_pk.size() == m_mode.public_key_bytes());

         BufferSlicer s(raw_pk);
         m_rho = s.copy<DilithiumSeedRho>(DilithiumModeConstants::SEEDBYTES);
         m_t1 = Dilithium::PolynomialVector::unpack_t1(s.take(DilithiumModeConstants::POLYT1_PACKEDBYTES * m_mode.k()),
                                                       m_mode);

         BOTAN_ASSERT_NOMSG(s.remaining() == 0);
         BOTAN_STATE_CHECK(m_t1.m_vec.size() == m_mode.k());

         m_tr = m_mode.symmetric_primitives().H(this->raw_pk());
      }

      Dilithium_PublicKeyInternal(DilithiumModeConstants mode,
                                  std::vector<uint8_t> rho,
                                  const Dilithium::PolynomialVector& s1,
                                  const Dilithium::PolynomialVector& s2) :
            m_mode(std::move(mode)),
            m_rho(std::move(rho)),
            m_t1([&] { return calculate_t0_and_t1(m_mode, m_rho.get() /* TODO: fixme */, s1, s2).second; }()) {
         BOTAN_ASSERT_NOMSG(!m_rho.empty());
         BOTAN_ASSERT_NOMSG(!m_t1.m_vec.empty());
         m_tr = m_mode.symmetric_primitives().H(raw_pk());
      }

      Dilithium_PublicKeyInternal(DilithiumModeConstants mode, DilithiumSeedRho rho, Dilithium::PolynomialVector t1) :
            m_mode(std::move(mode)), m_rho(std::move(rho)), m_t1(std::move(t1)) {
         BOTAN_ASSERT_NOMSG(!m_rho.empty());
         BOTAN_ASSERT_NOMSG(!m_t1.m_vec.empty());
         m_tr = m_mode.symmetric_primitives().H(raw_pk());
      }

      ~Dilithium_PublicKeyInternal() = default;

      Dilithium_PublicKeyInternal(const Dilithium_PublicKeyInternal&) = delete;
      Dilithium_PublicKeyInternal(Dilithium_PublicKeyInternal&&) = delete;
      Dilithium_PublicKeyInternal& operator=(const Dilithium_PublicKeyInternal& other) = delete;
      Dilithium_PublicKeyInternal& operator=(Dilithium_PublicKeyInternal&& other) = delete;

      DilithiumSerializedPublicKey raw_pk() const {
         return DilithiumSerializedPublicKey(
            concat_as<DilithiumSerializedPublicKey::wrapped_type>(m_rho, m_t1.polyvec_pack_t1()));
      }

      const DilithiumHashedPublicKey& tr() const {
         BOTAN_ASSERT_NOMSG(!m_tr.empty());
         return m_tr;
      }

      const Dilithium::PolynomialVector& t1() const { return m_t1; }

      const std::vector<uint8_t>& rho() const { return m_rho.get(); /* TODO: fixme */ }

      const DilithiumModeConstants& mode() const { return m_mode; }

   private:
      const DilithiumModeConstants m_mode;
      DilithiumHashedPublicKey m_tr;
      DilithiumSeedRho m_rho;
      Dilithium::PolynomialVector m_t1;
};

class Dilithium_PrivateKeyInternal {
   public:
      Dilithium_PrivateKeyInternal(DilithiumModeConstants mode) : m_mode(std::move(mode)) {}

      Dilithium_PrivateKeyInternal(DilithiumModeConstants mode,
                                   DilithiumSeedRho rho,
                                   DilithiumHashedPublicKey tr,
                                   DilithiumSeedK key,
                                   Dilithium::PolynomialVector s1,
                                   Dilithium::PolynomialVector s2,
                                   Dilithium::PolynomialVector t0) :
            m_mode(std::move(mode)),
            m_rho(std::move(rho)),
            m_tr(std::move(tr)),
            m_key(std::move(key)),
            m_t0(std::move(t0)),
            m_s1(std::move(s1)),
            m_s2(std::move(s2)) {}

      Dilithium_PrivateKeyInternal(DilithiumModeConstants mode, std::span<const uint8_t> sk) :
            Dilithium_PrivateKeyInternal(std::move(mode)) {
         BOTAN_ASSERT_NOMSG(sk.size() == m_mode.private_key_bytes());

         BufferSlicer s(sk);
         m_rho = s.copy<DilithiumSeedRho>(DilithiumModeConstants::SEEDBYTES);
         m_key = s.copy<DilithiumSeedK>(DilithiumModeConstants::SEEDBYTES);
         m_tr = s.copy<DilithiumHashedPublicKey>(DilithiumModeConstants::SEEDBYTES);
         m_s1 = Dilithium::PolynomialVector::unpack_eta(
            s.take(m_mode.l() * m_mode.polyeta_packedbytes()), m_mode.l(), m_mode);
         m_s2 = Dilithium::PolynomialVector::unpack_eta(
            s.take(m_mode.k() * m_mode.polyeta_packedbytes()), m_mode.k(), m_mode);
         m_t0 = Dilithium::PolynomialVector::unpack_t0(s.take(m_mode.k() * DilithiumModeConstants::POLYT0_PACKEDBYTES),
                                                       m_mode);
      }

      secure_vector<uint8_t> raw_sk() const {
         return concat_as<secure_vector<uint8_t>>(
            m_rho, m_key, m_tr, m_s1.polyvec_pack_eta(m_mode), m_s2.polyvec_pack_eta(m_mode), m_t0.polyvec_pack_t0());
      }

      const DilithiumModeConstants& mode() const { return m_mode; }

      const std::vector<uint8_t>& rho() const { return m_rho.get(); /* TODO: fixme */ }

      const secure_vector<uint8_t>& get_key() const { return m_key.get(); /* TODO: fixme */ }

      const DilithiumHashedPublicKey& tr() const { return m_tr; }

      const Dilithium::PolynomialVector& s1() const { return m_s1; }

      const Dilithium::PolynomialVector& s2() const { return m_s2; }

      const Dilithium::PolynomialVector& t0() const { return m_t0; }

   private:
      const DilithiumModeConstants m_mode;
      DilithiumSeedRho m_rho;
      DilithiumHashedPublicKey m_tr;
      DilithiumSeedK m_key;
      Dilithium::PolynomialVector m_t0, m_s1, m_s2;
};

class Dilithium_Signature_Operation final : public PK_Ops::Signature {
   public:
      Dilithium_Signature_Operation(std::shared_ptr<Dilithium_PrivateKeyInternal> sk, bool randomized) :
            m_priv_key(std::move(sk)),
            m_mode(m_priv_key->mode()),
            m_randomized(randomized),
            m_s1_hat(ntt(m_priv_key->s1())),
            m_s2_hat(ntt(m_priv_key->s2())),
            m_t0_hat(ntt(m_priv_key->t0())),
            m_matrix(expand_A(m_mode,
                              StrongSpan<const DilithiumSeedRho>(m_priv_key->rho()) /* TODO: remove disambiguation */)),
            m_h(m_mode.symmetric_primitives().get_message_hash(m_priv_key->tr())) {}

      void update(const uint8_t msg[], size_t msg_len) override { m_h.update({msg, msg_len}); }

      /**
       * NIST FIPS 204 IPD, Algorithm 2 (ML-DSA.Sign)
       */
      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         // Note: preparation of s1, s2, t0 and A are done in the constructor to
         //       avoid unnecessary recomputation when creating more than one
         //       signature using this operation object.

         const auto mu = m_h.final();

         // TODO: ML-DSA generates rhoprime differently, namely
         //       rhoprime = H(K, rnd, mu) with rnd being 32 random bytes or 32 zero bytes
         const auto rhoprime = DilithiumSeedRhoPrime((m_randomized) ? rng.random_vec(DilithiumModeConstants::CRHBYTES)
                                                                    : m_mode.CRH(concat(m_priv_key->get_key(), mu)));

         // Note: nonce (as requested by `polyvecl_uniform_gamma1`) is actually just uint16_t
         //       but to avoid an integer overflow, we use uint32_t as the loop variable.
         for(uint32_t nonce = 0; nonce <= std::numeric_limits<uint16_t>::max(); ++nonce) {
            /* Sample intermediate vector y */
            auto y = expand_mask(m_mode, rhoprime, static_cast<uint16_t>(nonce));
            auto z = ntt(y);

            /* Matrix-vector multiplication */
            auto w1 = Dilithium::PolynomialVector::generate_polyvec_matrix_pointwise_montgomery(
               m_matrix.get_matrix(), z, m_mode);

            w1.reduce();
            w1.invntt_tomont();
            w1.cadd_q();

            auto w1_w0 = w1.polyvec_decompose(m_mode);

            auto packed_w1 = std::get<0>(w1_w0).polyvec_pack_w1(m_mode);

            SHAKE_256 shake256_variable(DilithiumModeConstants::SEEDBYTES * 8);
            shake256_variable.update(mu.data(), DilithiumModeConstants::CRHBYTES);
            shake256_variable.update(packed_w1.data(), packed_w1.size());
            auto sm = shake256_variable.final();

            auto cp = Dilithium::Polynomial::poly_challenge(sm.data(), m_mode);
            cp.ntt();

            /* Compute z, reject if it reveals secret */
            auto s1 = m_s1_hat;  // TODO: perhaps avoid copy?
            s1.polyvec_pointwise_poly_montgomery(z, cp);

            z.invntt_tomont();
            z.add_polyvec(y);

            z.reduce();
            if(z.polyvec_chknorm(m_mode.gamma1() - m_mode.beta())) {
               continue;
            }

            /* Check that subtracting cs2 does not change high bits of w and low bits
            * do not reveal secret information */
            Dilithium::PolynomialVector h(m_mode.k());
            auto s2 = m_s2_hat;  // TODO: perhaps avoid copy?
            s2.polyvec_pointwise_poly_montgomery(h, cp);
            h.invntt_tomont();
            std::get<1>(w1_w0) -= h;
            std::get<1>(w1_w0).reduce();

            if(std::get<1>(w1_w0).polyvec_chknorm(m_mode.gamma2() - m_mode.beta())) {
               continue;
            }

            /* Compute hints for w1 */
            auto t0 = m_t0_hat;  // TODO: perhaps avoid copy?
            t0.polyvec_pointwise_poly_montgomery(h, cp);
            h.invntt_tomont();
            h.reduce();
            if(h.polyvec_chknorm(m_mode.gamma2())) {
               continue;
            }

            std::get<1>(w1_w0).add_polyvec(h);
            std::get<1>(w1_w0).cadd_q();

            auto n =
               Dilithium::PolynomialVector::generate_hint_polyvec(h, std::get<1>(w1_w0), std::get<0>(w1_w0), m_mode);
            if(n > m_mode.omega()) {
               continue;
            }

            /* Write signature */
            return pack_sig(sm, z, h);
         }

         throw Internal_Error("Dilithium signature loop did not terminate");
      }

      size_t signature_length() const override { return m_priv_key->mode().crypto_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override {
         // TODO: move this into the DilithiumMode class to satisfy the DRY principle
         return AlgorithmIdentifier(m_priv_key->mode().oid(), AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      std::string hash_function() const override { return m_h.name(); }

   private:
      // Bit-pack signature sig = (c, z, h).
      secure_vector<uint8_t> pack_sig(const secure_vector<uint8_t>& c,
                                      const Dilithium::PolynomialVector& z,
                                      const Dilithium::PolynomialVector& h) {
         BOTAN_ASSERT_NOMSG(c.size() == DilithiumModeConstants::SEEDBYTES);
         size_t position = 0;
         secure_vector<uint8_t> sig(m_mode.crypto_bytes());

         std::copy(c.begin(), c.end(), sig.begin());
         position += DilithiumModeConstants::SEEDBYTES;

         for(size_t i = 0; i < m_mode.l(); ++i) {
            z.m_vec[i].polyz_pack(&sig[position + i * m_mode.polyz_packedbytes()], m_mode);
         }
         position += m_mode.l() * m_mode.polyz_packedbytes();

         /* Encode h */
         for(size_t i = 0; i < m_mode.omega() + m_mode.k(); ++i) {
            sig[i + position] = 0;
         }

         size_t k = 0;
         for(size_t i = 0; i < m_mode.k(); ++i) {
            for(size_t j = 0; j < DilithiumModeConstants::N; ++j) {
               if(h.m_vec[i].m_coeffs[j] != 0) {
                  sig[position + k] = static_cast<uint8_t>(j);
                  k++;
               }
            }
            sig[position + m_mode.omega() + i] = static_cast<uint8_t>(k);
         }
         return sig;
      }

      std::shared_ptr<Dilithium_PrivateKeyInternal> m_priv_key;
      const DilithiumModeConstants& m_mode;
      bool m_randomized;

      const Dilithium::PolynomialVector m_s1_hat;
      const Dilithium::PolynomialVector m_s2_hat;
      const Dilithium::PolynomialVector m_t0_hat;
      const Dilithium::PolynomialMatrix m_matrix;
      DilithiumMessageHash m_h;
};

class Dilithium_Verification_Operation final : public PK_Ops::Verification {
   public:
      Dilithium_Verification_Operation(std::shared_ptr<Dilithium_PublicKeyInternal> pubkey) :
            m_pub_key(std::move(pubkey)),
            m_mode(m_pub_key->mode()),
            m_matrix(
               expand_A(m_mode, StrongSpan<const DilithiumSeedRho>(m_pub_key->rho() /* TOD: remove disambiguation */))),
            m_h(m_mode.symmetric_primitives().get_message_hash(m_pub_key->tr())) {}

      /*
      * Add more data to the message currently being signed
      * @param msg the message
      * @param msg_len the length of msg in bytes
      */
      void update(const uint8_t msg[], size_t msg_len) override { m_h.update({msg, msg_len}); }

      bool is_valid_signature(const uint8_t* sig, size_t sig_len) override {
         const auto mu = m_h.final();

         if(sig_len != m_mode.crypto_bytes()) {
            return false;
         }

         Dilithium::PolynomialVector z(m_mode.l());
         Dilithium::PolynomialVector h(m_mode.k());
         std::vector<uint8_t> signature(sig, sig + sig_len);
         std::array<uint8_t, DilithiumModeConstants::SEEDBYTES> c;
         if(Dilithium::PolynomialVector::unpack_sig(c, z, h, signature, m_mode)) {
            return false;
         }

         if(z.polyvec_chknorm(m_mode.gamma1() - m_mode.beta())) {
            return false;
         }

         /* Matrix-vector multiplication; compute Az - c2^dt1 */
         auto cp = Dilithium::Polynomial::poly_challenge(c.data(), m_mode);
         cp.ntt();

         Dilithium::PolynomialVector t1 = m_pub_key->t1();
         t1.polyvec_shiftl();
         t1.ntt();
         t1.polyvec_pointwise_poly_montgomery(t1, cp);

         z.ntt();

         auto w1 =
            Dilithium::PolynomialVector::generate_polyvec_matrix_pointwise_montgomery(m_matrix.get_matrix(), z, m_mode);
         w1 -= t1;
         w1.reduce();
         w1.invntt_tomont();
         w1.cadd_q();
         w1.polyvec_use_hint(w1, h, m_mode);
         auto packed_w1 = w1.polyvec_pack_w1(m_mode);

         /* Call random oracle and verify challenge */
         SHAKE_256 shake256_variable(DilithiumModeConstants::SEEDBYTES * 8);
         shake256_variable.update(mu.data(), mu.size());
         shake256_variable.update(packed_w1.data(), packed_w1.size());
         auto c2 = shake256_variable.final();

         BOTAN_ASSERT_NOMSG(c.size() == c2.size());
         return std::equal(c.begin(), c.end(), c2.begin());
      }

      std::string hash_function() const override { return "SHAKE-256(512)"; }

   private:
      std::shared_ptr<Dilithium_PublicKeyInternal> m_pub_key;
      const DilithiumModeConstants& m_mode;
      Dilithium::PolynomialMatrix m_matrix;
      DilithiumMessageHash m_h;
};

Dilithium_PublicKey::Dilithium_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk) :
      Dilithium_PublicKey(pk, DilithiumMode(alg_id.oid())) {}

Dilithium_PublicKey::Dilithium_PublicKey(std::span<const uint8_t> pk, DilithiumMode m) {
   DilithiumModeConstants mode(m);
   BOTAN_ARG_CHECK(pk.empty() || pk.size() == mode.public_key_bytes(),
                   "dilithium public key does not have the correct byte count");

   m_public = std::make_shared<Dilithium_PublicKeyInternal>(std::move(mode),
                                                            StrongSpan<const DilithiumSerializedPublicKey>(pk));
}

std::string Dilithium_PublicKey::algo_name() const {
   return object_identifier().to_formatted_string();
}

AlgorithmIdentifier Dilithium_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Dilithium_PublicKey::object_identifier() const {
   return m_public->mode().oid();
}

size_t Dilithium_PublicKey::key_length() const {
   return m_public->mode().public_key_bytes();
}

size_t Dilithium_PublicKey::estimated_strength() const {
   return m_public->mode().nist_security_strength();
}

std::vector<uint8_t> Dilithium_PublicKey::public_key_bits() const {
   return m_public->raw_pk().get();
}

bool Dilithium_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   return true;  // ???
}

std::unique_ptr<Private_Key> Dilithium_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Dilithium_PrivateKey>(rng, m_public->mode().mode());
}

std::unique_ptr<PK_Ops::Verification> Dilithium_PublicKey::create_verification_op(std::string_view params,
                                                                                  std::string_view provider) const {
   BOTAN_ARG_CHECK(params.empty() || params == "Pure", "Unexpected parameters for verifying with Dilithium");
   if(provider.empty() || provider == "base") {
      return std::make_unique<Dilithium_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> Dilithium_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& alg_id, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for Dilithium X.509 signature");
      }
      return std::make_unique<Dilithium_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

/**
 * NIST FIPS 204 IPD, Algorithm 1 (ML-DSA.KeyGen)
 */
Dilithium_PrivateKey::Dilithium_PrivateKey(RandomNumberGenerator& rng, DilithiumMode m) {
   DilithiumModeConstants mode(m);
   const auto& sympriv = mode.symmetric_primitives();

   const auto xi = rng.random_vec<DilithiumSeedRandomness>(DilithiumModeConstants::SEEDBYTES);
   auto [rho, rhoprime, key] = sympriv.H(xi);

   // TODO: do we need those asserts?
   BOTAN_ASSERT_NOMSG(rho.size() == DilithiumModeConstants::SEEDBYTES);
   BOTAN_ASSERT_NOMSG(rhoprime.size() == DilithiumModeConstants::CRHBYTES);
   BOTAN_ASSERT_NOMSG(key.size() == DilithiumModeConstants::SEEDBYTES);

   auto A = expand_A(mode, rho);
   auto [s1, s2] = expand_s(mode, rhoprime);

   // TODO: That could get a bit more readable
   // TODO: find a way to avoid the copy of S1
   auto s1_copy = s1;
   s1.ntt();
   auto t = Dilithium::PolynomialVector::generate_polyvec_matrix_pointwise_montgomery(A.get_matrix(), s1, mode);
   t.reduce();
   t.invntt_tomont();
   t.add_polyvec(s2);
   t.cadd_q();

   auto [t1, t0] = power2round(mode, t);

   m_public = std::make_shared<Dilithium_PublicKeyInternal>(mode, rho, std::move(t1));
   m_private = std::make_shared<Dilithium_PrivateKeyInternal>(std::move(mode),
                                                              std::move(rho),
                                                              m_public->tr(),
                                                              std::move(key),
                                                              std::move(s1_copy),
                                                              std::move(s2),
                                                              std::move(t0));
}

Dilithium_PrivateKey::Dilithium_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk) :
      Dilithium_PrivateKey(sk, DilithiumMode(alg_id.oid())) {}

Dilithium_PrivateKey::Dilithium_PrivateKey(std::span<const uint8_t> sk, DilithiumMode m) {
   DilithiumModeConstants mode(m);
   BOTAN_ARG_CHECK(sk.size() == mode.private_key_bytes(), "dilithium private key does not have the correct byte count");
   m_private = std::make_shared<Dilithium_PrivateKeyInternal>(std::move(mode), sk);
   m_public = std::make_shared<Dilithium_PublicKeyInternal>(
      m_private->mode(), m_private->rho(), m_private->s1(), m_private->s2());
}

secure_vector<uint8_t> Dilithium_PrivateKey::raw_private_key_bits() const {
   return this->private_key_bits();
}

secure_vector<uint8_t> Dilithium_PrivateKey::private_key_bits() const {
   return m_private->raw_sk();
}

std::unique_ptr<PK_Ops::Signature> Dilithium_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                             std::string_view params,
                                                                             std::string_view provider) const {
   BOTAN_UNUSED(rng);

   BOTAN_ARG_CHECK(params.empty() || params == "Deterministic" || params == "Randomized",
                   "Unexpected parameters for signing with Dilithium");

   // TODO: ML-KEM uses the randomized (hedged) variant by default.
   //       We might even drop support for the deterministic variant.
   const bool randomized = (params == "Randomized");
   if(provider.empty() || provider == "base") {
      return std::make_unique<Dilithium_Signature_Operation>(m_private, randomized);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<Public_Key> Dilithium_PrivateKey::public_key() const {
   return std::make_unique<Dilithium_PublicKey>(*this);
}
}  // namespace Botan
