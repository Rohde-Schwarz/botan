/**
* NIST.SP.800-56C rev. 2 - One-Step Key Derivation Function Implementation
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sp800_56c_helper.h>

#include <botan/internal/bit_ops.h>

namespace Botan {

namespace {
/**
 * @brief One-Step Key Derivation as defined in SP800-56Cr2 Section 4
 */
void kdm_internal(std::span<uint8_t> output_buffer,
                  std::span<const uint8_t> z,
                  std::span<const uint8_t> fixed_info,
                  Buffered_Computation& h,
                  const std::function<void(Buffered_Computation*)>& reset_h_callback) {
   size_t l = output_buffer.size() * 8;
   // 1. If L > 0, then set reps = ceil(L / H_outputBits); otherwise,
   //    output an error indicator and exit this process without
   //    performing the remaining actions (i.e., omit steps 2 through 8).
   BOTAN_ARG_CHECK(l > 0, "Zero KDM output length");
   size_t reps = ceil_division(l, h.output_length() * 8);

   // 2. If reps > (2^32 − 1), then output an error indicator and exit this
   //    process without performing the remaining actions
   //    (i.e., omit steps 3 through 8).
   BOTAN_ARG_CHECK(reps <= 0xFFFFFFFF, "Too large KDM output length");

   // 3. Initialize a big-endian 4-byte unsigned integer counter as
   //    0x00000000, corresponding to a 32-bit binary representation of
   //    the number zero.
   uint32_t counter = 0;

   // 4. If counter || Z || FixedInfo is more than max_H_inputBits bits
   //    long, then output an error indicator and exit this process
   //    without performing any of the remaining actions (i.e., omit
   //    steps 5 through 8). => SHA3 and KMAC are unlimited

   // 5. Initialize Result(0) as an empty bit string
   //    (i.e., the null string).
   secure_vector<uint8_t> result;

   // 6. For i = 1 to reps, do the following:
   for(size_t i = 1; i <= reps; i++) {
      // 6.1. Increment counter by 1.
      counter++;
      // Reset the hash/MAC object. For MAC, also set the key (salt) and IV.
      reset_h_callback(&h);

      // 6.2 Compute K(i) = H(counter || Z || FixedInfo).
      h.update_be(counter);
      h.update(z);
      h.update(fixed_info);
      auto k_i = h.final();

      // 6.3. Set Result(i) = Result(i−1) || K(i).
      result.insert(result.end(), k_i.begin(), k_i.end());
   }

   // 7. Set DerivedKeyingMaterial equal to the leftmost L bits of Result(reps).
   copy_mem(output_buffer, std::span(result).subspan(0, output_buffer.size()));
}
}  // namespace

// KDF with HashFunctions (Option 1)
void Sp800_56C::kdm(std::span<uint8_t> output_buffer,
                    HashFunction& hash,
                    std::span<const uint8_t> z,
                    std::span<const uint8_t> fixed_info) {
   kdm_internal(output_buffer, z, fixed_info, hash, [&](Buffered_Computation* kdf) {
      HashFunction* hash = dynamic_cast<HashFunction*>(kdf);
      BOTAN_ASSERT_NONNULL(hash);
      hash->clear();
   });
}

// KDF with MAC (Options 2 and 3)
void Sp800_56C::kdm(std::span<uint8_t> output_buffer,
                    MessageAuthenticationCode& mac,
                    std::span<const uint8_t> z,
                    std::span<const uint8_t> fixed_info,
                    std::span<const uint8_t> salt) {
   kdm_internal(output_buffer, z, fixed_info, mac, [&](Buffered_Computation* kdf) {
      BOTAN_ARG_CHECK(salt.size() > 0, "Empty salts not allowed. A default_salt must be provided manually.");
      BOTAN_ARG_CHECK(mac.name().starts_with("KMAC") || mac.name().starts_with("HMAC"),
                      "KDM MAC must be a KMAC or HMAC");
      MessageAuthenticationCode* kdf_mac = dynamic_cast<MessageAuthenticationCode*>(kdf);
      BOTAN_ASSERT_NONNULL(kdf_mac);
      kdf_mac->clear();
      // 4.1 Option 2 and 3 - An implementation dependent byte string, salt,
      //     whose (non-null) value may be optionally provided in
      //     OtherInput, serves as the HMAC#/KMAC# key ...
      kdf_mac->set_key(salt);

      // 4.1 Option 3 - The "customization string" S shall be the byte string
      //     01001011 || 01000100 || 01000110, which represents the sequence
      //     of characters 'K', 'D', and 'F' in 8-bit ASCII.
      if(auto kmac = dynamic_cast<KMAC*>(kdf_mac)) {
         kmac->start(std::array<uint8_t, 3>{'K', 'D', 'F'});
      }
   });
}

}  // namespace Botan
