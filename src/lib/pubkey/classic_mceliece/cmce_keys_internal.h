/*
* Classic McEliece key generation with Internal Private and Public Key classes
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
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

class Classic_McEliece_PrivateKeyInternal;

/**
 * @brief Representation of a Classic McEliece public key.
 *
 * This class represents a Classic McEliece public key. It is used internally by the Classic McEliece
 * public key class and contains the following data:
 * - The Classic McEliece parameters
 * - The public key matrix
 */
class Classic_McEliece_PublicKeyInternal {
   public:
      Classic_McEliece_PublicKeyInternal(const Classic_McEliece_Parameters& params, Classic_McEliece_Matrix matrix) :
            m_params(params), m_matrix(std::move(matrix)) {
         BOTAN_ASSERT_NOMSG(m_matrix.bytes().size() == m_params.pk_size_bytes());
      }

      // TODO: Do we want to return a shared_ptr or an object?
      static std::shared_ptr<Classic_McEliece_PublicKeyInternal> create_from_sk(
         const Classic_McEliece_PrivateKeyInternal& sk);

      std::vector<uint8_t> serialize() const { return m_matrix.bytes(); }

      const Classic_McEliece_Matrix& matrix() const { return m_matrix; }

      const Classic_McEliece_Parameters& params() const { return m_params; }

   private:
      Classic_McEliece_Parameters m_params;
      Classic_McEliece_Matrix m_matrix;
};

/**
 * @brief Representation of a Classic McEliece private key.
 *
 * This class represents a Classic McEliece private key. It is used internally by the Classic McEliece
 * private key class and contains the following data (see Classic McEliece ISO Section 9.2.12):
 * - The Classic McEliece parameters
 * - The seed delta
 * - The column selection pivot vector c
 * - The minimal polynomial g
 * - The field ordering alpha
 * - The seed s for implicit rejection
 */
class Classic_McEliece_PrivateKeyInternal {
   public:
      Classic_McEliece_PrivateKeyInternal(const Classic_McEliece_Parameters& params,
                                          secure_vector<uint8_t> delta,
                                          secure_bitvector c,
                                          Classic_McEliece_Minimal_Polynomial g,
                                          Classic_McEliece_Field_Ordering alpha,
                                          secure_vector<uint8_t> s) :
            m_params(params),
            m_delta(std::move(delta)),
            m_c(std::move(c)),
            m_g(std::move(g)),
            m_field_ordering(std::move(alpha)),
            m_s(std::move(s)) {}

      /**
       * @brief Parses a Classic McEliece private key from a byte sequence.
       *
       * It also creates the field ordering from the control bits in @param sk_bytes.
       *
       * @param params The Classic McEliece parameters
       * @param sk_bytes The secret key byte sequence
       * @return the Classic McEliece private key
       */
      static Classic_McEliece_PrivateKeyInternal from_bytes(const Classic_McEliece_Parameters& params,
                                                            std::span<const uint8_t> sk_bytes);

      /**
       * @brief Serializes the Classic McEliece private key as defined in Classic McEliece ISO Section 9.2.12.
       *
       * @return the serialized Classic McEliece private key
       */
      secure_vector<uint8_t> serialize() const;

      /**
       * @brief The seed delta that was used to create the private key.
       */
      const secure_vector<uint8_t>& delta() const { return m_delta; }

      /**
       * @brief The column selection pivot vector c as defined in Classic McEliece ISO Section 9.2.11.
       */
      const secure_bitvector& c() const { return m_c; }

      /**
       * @brief The minimal polynomial g.
       */
      const Classic_McEliece_Minimal_Polynomial& g() const { return m_g; }

      /**
       * @brief The field ordering alpha.
       */
      const Classic_McEliece_Field_Ordering& field_ordering() const { return m_field_ordering; }

      /**
       * @brief The seed s for implicit rejection on decryption failure.
       */
      const secure_vector<uint8_t>& s() const { return m_s; }

      /**
       * @brief The Classic McEliece parameters.
       */
      const Classic_McEliece_Parameters& params() const { return m_params; }

   private:
      Classic_McEliece_Parameters m_params;
      secure_vector<uint8_t> m_delta;
      secure_bitvector m_c;
      Classic_McEliece_Minimal_Polynomial m_g;
      Classic_McEliece_Field_Ordering m_field_ordering;
      secure_vector<uint8_t> m_s;
};

/**
 * @brief Representation of a Classic McEliece key pair.
 */
struct Classic_McEliece_KeyPair_Internal {
      std::shared_ptr<Classic_McEliece_PrivateKeyInternal> private_key;
      std::shared_ptr<Classic_McEliece_PublicKeyInternal> public_key;

      /**
       * @brief Generate a Classic McEliece key pair using the algorithm described
       * in Classic McEliece ISO Section 8.3
       *
       * @param params
       * @param seed
       * @return Classic_McEliece_KeyPair_Internal
       */
      static Classic_McEliece_KeyPair_Internal generate(const Classic_McEliece_Parameters& params,
                                                        const secure_vector<uint8_t>& seed);
};

}  // namespace Botan

#endif  // BOTAN_CMCE_KEYS_INTERNAL_H_
