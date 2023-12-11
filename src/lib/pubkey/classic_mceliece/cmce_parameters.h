/*
 * Classic McEliece Parameters
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_PARAMS_H_
#define BOTAN_CMCE_PARAMS_H_

#include <botan/hash.h>
#include <botan/oids.h>
#include <botan/xof.h>
#include <botan/internal/bitvector.h>
#include <botan/internal/cmce_gf.h>

#include <string_view>

namespace Botan {

struct Classic_McEliece_Big_F_Coefficient;
class Classic_McEliece_Polynomial_Ring;

enum class Classic_McEliece_Parameter_Set {
   mceliece348864,   // NIST
   mceliece348864f,  // NIST

   mceliece460896,   // NIST
   mceliece460896f,  // NIST

   mceliece6688128,     // ISO + NIST
   mceliece6688128f,    // ISO + NIST
   mceliece6688128pc,   // ISO
   mceliece6688128pcf,  // ISO

   mceliece6960119,     // ISO + NIST
   mceliece6960119f,    // ISO + NIST
   mceliece6960119pc,   // ISO
   mceliece6960119pcf,  // ISO

   mceliece8192128,     // ISO + NIST
   mceliece8192128f,    // ISO + NIST
   mceliece8192128pc,   // ISO
   mceliece8192128pcf,  // ISO

   toy,
   /// Minimal instance without semi-systematic matrix creation and no plaintext confirmation
   test,
   /// Minimal instance with semi-systematic matrix creation and no plaintext confirmation
   testf,
   /// Minimal instance without semi-systematic matrix creation and with plaintext confirmation
   testpc
};

/**
 * @returns ceil(n/d)
 * TODO: Remove once LMS is merged
 */
constexpr size_t ceil_div(size_t n, size_t d) {
   return (n + d - 1) / d;
}

/**
 * Container for all Classic McEliece parameters.
 */
class BOTAN_PUBLIC_API(3, 1) Classic_McEliece_Parameters final {
   public:
      static Classic_McEliece_Parameters create(Classic_McEliece_Parameter_Set set);
      static Classic_McEliece_Parameters create(std::string_view name);
      static Classic_McEliece_Parameters create(const OID& oid);

      static Classic_McEliece_Parameter_Set param_set_from_oid(const OID& oid);
      static Classic_McEliece_Parameter_Set param_set_from_str(std::string_view param_name);

      Classic_McEliece_Parameters(const Classic_McEliece_Parameters& other) :
            Classic_McEliece_Parameters(other.m_set, other.m_m, other.m_n, other.m_t, other.m_poly_f) {}

      Classic_McEliece_Parameter_Set set() const { return m_set; }

      OID object_identifier() const { throw Not_Implemented("TODO"); }

      bool is_pc() const {
         return (m_set == Classic_McEliece_Parameter_Set::mceliece6688128pc) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece6688128pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece6960119pc) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece6960119pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece8192128pc) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece8192128pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::testpc);
      }

      bool is_f() const {
         return (m_set == Classic_McEliece_Parameter_Set::mceliece348864f) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece460896f) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece6688128f) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece6688128pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece6960119f) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece6960119pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece8192128f) ||
                (m_set == Classic_McEliece_Parameter_Set::mceliece8192128pcf) ||
                (m_set == Classic_McEliece_Parameter_Set::testf);
      }

      size_t m() const { return m_m; }

      size_t q() const { return (size_t(1) << m_m); }

      size_t n() const { return m_n; }

      size_t t() const { return m_t; }

      static constexpr size_t ell() { return 256; }  // TODO: Better way for const params?

      size_t sigma1() const { return 16; }

      size_t sigma2() const { return 32; }

      static constexpr size_t mu() { return 32; }

      static constexpr size_t nu() { return 64; }

      size_t tau() const {
         // Section 8.4 of ISO:
         // The integer tau is defined as t if n=q; as 2t if q/2<=n<q; as 4t if q/4<=n<q/2; etc
         size_t tau_fact = 1 << (m() - floor_log2(n()));
         return tau_fact * t();
      }

      uint16_t poly_f() const { return m_poly_f; }

      // seed_len and all sk_*_bytes are defined in ISO 9.2.12

      static constexpr size_t seed_len() { return ell() / 8; }

      static constexpr size_t sk_c_bytes() { return 8; }

      size_t sk_poly_g_bytes() const { return t() * sizeof(uint16_t); }

      size_t sk_alpha_control_bytes() const { return (2 * m() - 1) * (1 << (m() - 4)); }

      size_t sk_s_bytes() const { return n() / 8; }

      size_t sk_size_bytes() const {
         // ISO 9.2.12: sk = (delta, c, g, alpha(control bits), s)
         return seed_len() + sk_c_bytes() + sk_poly_g_bytes() + sk_alpha_control_bytes() + sk_s_bytes();
      }

      size_t pk_no_rows() const { return t() * m(); }

      size_t pk_no_cols() const { return n() - pk_no_rows(); }

      size_t pk_row_size_bytes() const { return (pk_no_cols() + 7) / 8; }

      size_t pk_size_bytes() const { return pk_no_rows() * pk_row_size_bytes(); }

      size_t encode_out_size() const { return ceil_div(m() * t(), 8); }

      static constexpr size_t hash_out_bytes() { return ell() / 8; }

      size_t ciphertext_size() const {
         if(is_pc()) {
            // C_0 + C_1
            return encode_out_size() + hash_out_bytes();
         } else {
            return encode_out_size();
         }
      }

      const Classic_McEliece_Polynomial_Ring& poly_ring() const { return *m_poly_ring; }

      secure_vector<uint8_t> prg(std::span<const uint8_t> seed) const {
         BOTAN_ASSERT_EQUAL(seed.size(), 32, "Valid seed length");
         auto xof = XOF::create_or_throw("SHAKE-256");  // TODO: Possibly optimize and avoid re-creating object

         xof->update(std::array<uint8_t, 1>({64}));
         xof->update(seed);

         return xof->output((n() + sigma2() * q() + sigma1() * t() + ell()) / 8);
      }

      std::unique_ptr<HashFunction> hash_func() const { return HashFunction::create_or_throw("SHAKE-256(256)"); }

   private:
      Classic_McEliece_Parameters(
         Classic_McEliece_Parameter_Set param_set, size_t m, size_t n, size_t t, uint16_t poly_f);

   private:
      Classic_McEliece_Parameter_Set m_set;

      size_t m_m;
      size_t m_n;
      size_t m_t;

      uint16_t m_poly_f;
      std::unique_ptr<Classic_McEliece_Polynomial_Ring> m_poly_ring;
};

}  // namespace Botan

#endif
