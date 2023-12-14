/*
* Classic McEliece key generation with Internal Private and Public Key classes
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#ifndef BOTAN_CMCE_KEYS_INTERNAL_H_
#define BOTAN_CMCE_KEYS_INTERNAL_H_

#include <botan/cmce_parameters.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_matrix.h>
#include <botan/internal/cmce_poly.h>

namespace Botan {

// TODO: Move functions to cpp
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
                                          secure_bitvector c,
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

         return Botan::concat(m_delta, c_bytes, m_g.serialize(), m_alpha.alphas_control_bits().to_bytes(), m_s);
      }

      const secure_vector<uint8_t>& delta() const { return m_delta; }

      const secure_bitvector& c() const { return m_c; }

      const Classic_McEliece_Minimal_Polynomial& g() const { return m_g; }

      const Classic_McEliece_Field_Ordering& alpha() const { return m_alpha; }

      const secure_vector<uint8_t>& s() const { return m_s; }

      const Classic_McEliece_Parameters& params() const { return m_params; }

   private:
      Classic_McEliece_Parameters m_params;
      secure_vector<uint8_t> m_delta;
      secure_bitvector m_c;
      Classic_McEliece_Minimal_Polynomial m_g;
      Classic_McEliece_Field_Ordering m_alpha;
      secure_vector<uint8_t> m_s;
};

std::pair<Classic_McEliece_PrivateKeyInternal, Classic_McEliece_PublicKeyInternal> cmce_key_gen(
   const Classic_McEliece_Parameters& params, const secure_vector<uint8_t>& seed);

}  // namespace Botan

#endif  // BOTAN_CMCE_KEYS_INTERNAL_H_