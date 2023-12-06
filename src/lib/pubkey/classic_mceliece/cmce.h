/*
 * Classic McEliece Key Generation
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * TODO: Ref-Code Acknowledgement
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_H_
#define BOTAN_CMCE_H_

#include <botan/pk_keys.h>

#include <botan/cmce_parameters.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/cmce_poly.h>

namespace Botan {

class Classic_McEliece_PublicKeyInternal;
class Classic_McEliece_PrivateKeyInternal;

// TODO: Move in cpp
class Classic_McEliece_PublicKeyInternal {
   public:
      Classic_McEliece_PublicKeyInternal(Classic_McEliece_Parameters params, Classic_McEliece_Matrix matrix) :
            m_params(std::move(params)), m_matrix(std::move(matrix)) {
         BOTAN_ASSERT_NOMSG(m_matrix.bytes().size() == m_params.pk_size_bytes());
      }

      std::vector<uint8_t> serialize() const { return m_matrix.bytes(); }

      const Classic_McEliece_Matrix& matrix() const { return m_matrix; }

      const Classic_McEliece_Parameters& params() const { return m_params; }

   private:
      Classic_McEliece_Parameters m_params;
      Classic_McEliece_Matrix m_matrix;
};

// TODO: Move in Cpp
class Classic_McEliece_PrivateKeyInternal {
   public:
      Classic_McEliece_PrivateKeyInternal(Classic_McEliece_Parameters params,
                                          secure_vector<uint8_t> delta,
                                          secure_bitvector<uint64_t> c,
                                          Classic_McEliece_Minimal_Polynomial g,
                                          Classic_McEliece_Field_Ordering alpha,
                                          secure_vector<uint8_t> s) :
            m_params(std::move(params)),
            m_delta(std::move(delta)),
            m_c(std::move(c)),
            m_g(std::move(g)),
            m_alpha(std::move(alpha)),
            m_s(std::move(s)) {}

      static Classic_McEliece_PrivateKeyInternal from_bytes(const Classic_McEliece_Parameters& params,
                                                            std::span<const uint8_t> sk_bytes) {
         BOTAN_ASSERT(sk_bytes.size() == params.sk_size_bytes(), "Valid private key size");
         BufferSlicer sk_slicer(sk_bytes);
         auto delta = sk_slicer.copy_as_secure_vector(params.seed_len());
         std::array<uint8_t, 8> c;
         sk_slicer.copy_into(c);
         auto g_bytes = sk_slicer.take(params.sk_poly_g_bytes());
         BOTAN_UNUSED(g_bytes);
         // TODO: Minim_Poly::from_bytes
         // auto g = Classic_McEliece_Minimal_Polynomial::from_bytes(g_bytes)
         auto alpha_control_bits = sk_slicer.take(params.sk_alpha_control_bytes());
         // TODO: Reverse Benes network for field ordering recreation
         auto field_ordering = Classic_McEliece_Field_Ordering::create_from_control_bits(params, alpha_control_bits);
         auto s = sk_slicer.copy_as_secure_vector(params.sk_s_bytes());
         throw Not_Implemented("TODO");
         //return Classic_McEliece_PrivateKeyInternal(std::move(params), std::move(delta), c, std::move(g), std::move(alpha), std::move(s));
      }

      secure_vector<uint8_t> serialize() const {
         auto c_bytes = m_c.to_bytes();

         return Botan::concat(m_delta, c_bytes, m_g.to_bytes(), m_alpha.alphas_control_bits().to_bytes(), m_s);
      }

      const secure_vector<uint8_t>& delta() const { return m_delta; }

      const secure_bitvector<uint64_t>& c() const { return m_c; }

      const Classic_McEliece_Minimal_Polynomial& g() const { return m_g; }

      const Classic_McEliece_Field_Ordering& alpha() const { return m_alpha; }

      const secure_vector<uint8_t>& s() const { return m_s; }

      const Classic_McEliece_Parameters& params() const { return m_params; }

   private:
      Classic_McEliece_Parameters m_params;
      secure_vector<uint8_t> m_delta;
      secure_bitvector<uint64_t> m_c;
      Classic_McEliece_Minimal_Polynomial m_g;
      Classic_McEliece_Field_Ordering m_alpha;
      secure_vector<uint8_t> m_s;
};

std::pair<Classic_McEliece_PrivateKeyInternal, Classic_McEliece_PublicKeyInternal> cmce_key_gen(
   const Classic_McEliece_Parameters& params, const secure_vector<uint8_t>& seed);

std::pair<std::vector<uint8_t>, secure_vector<uint8_t>> cmce_encaps(const Classic_McEliece_PublicKeyInternal& pk,
                                                                    RandomNumberGenerator& rng);

std::optional<secure_bitvector<uint64_t>> cmce_fixed_weight_vector_gen(const Classic_McEliece_Parameters& params,
                                                                       const secure_vector<uint8_t>& rand);

std::vector<Classic_McEliece_GF> compute_goppa_syndrome(const Classic_McEliece_Minimal_Polynomial& goppa_poly,
                                                        const Classic_McEliece_Field_Ordering& ordering,
                                                        std::span<const uint8_t> word_to_decaps);

std::vector<Classic_McEliece_GF> berlekamp_massey(const Classic_McEliece_Parameters& params,
                                                  const std::vector<Classic_McEliece_GF>& syndrome);

//------------------------------------------------------

/**
 * Classic McEliece is a Code-Based KEM. It is a round 4 candidate in NIST's PQC competition.
 * It is endorsed by the German Federal Office for Information Security for its conservative security
 * assumptions and a corresponding draft for an ISO standard has been prepared. Both NIST and ISO parameter
 * sets are implemented here.
 */
class BOTAN_PUBLIC_API(3, 4) Classic_McEliece_PublicKey : public virtual Public_Key {
   public:
      Classic_McEliece_PublicKey(Classic_McEliece_Parameter_Set set, std::vector<uint8_t> pub_key);

      Classic_McEliece_PublicKey(const AlgorithmIdentifier& alg_id, std::vector<uint8_t> key_bits);

      Classic_McEliece_PublicKey(const Classic_McEliece_PublicKey& other);
      Classic_McEliece_PublicKey& operator=(const Classic_McEliece_PublicKey& other);
      Classic_McEliece_PublicKey(Classic_McEliece_PublicKey&&) = default;
      Classic_McEliece_PublicKey& operator=(Classic_McEliece_PublicKey&&) = default;

      ~Classic_McEliece_PublicKey() override = default;

      std::string algo_name() const override { return "Classic McEliece"; }  //TODO: Use "CMCE" or "Classic_McEliece"?

      AlgorithmIdentifier algorithm_identifier() const override;

      OID object_identifier() const override;

      size_t key_length() const override;

      size_t estimated_strength() const override;

      std::vector<uint8_t> public_key_bits() const override;

      bool check_key(RandomNumberGenerator&, bool) const override;

      bool supports_operation(PublicKeyOperation op) const override {
         return (op == PublicKeyOperation::KeyEncapsulation);
      }

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(std::string_view params,
                                                                       std::string_view provider) const override;

   protected:
      Classic_McEliece_PublicKey() = default;

   protected:
      std::shared_ptr<Classic_McEliece_PublicKeyInternal>
         m_public;  // NOLINT(misc-non-private-member-variables-in-classes)
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 4) Classic_McEliece_PrivateKey final : public virtual Classic_McEliece_PublicKey,
                                                                 public virtual Private_Key {
   public:
      Classic_McEliece_PrivateKey(RandomNumberGenerator& rng, Classic_McEliece_Parameter_Set param_set);

      Classic_McEliece_PrivateKey(std::span<const uint8_t> sk, Classic_McEliece_Parameter_Set param_set);

      Classic_McEliece_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const override;

   private:
      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> m_private;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif  // BOTAN_CMCE_GF_H_
