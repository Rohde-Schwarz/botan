
#include "test_rng.h"
#include "tests.h"

#if defined(BOTAN_HAS_CAT_KDF)
   #include <botan/cat_kdf.h>
   #include <botan/pk_algs.h>
   #include <botan/internal/cat_kdf_internal.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/kex_to_kem_adapter.h>
   #include <botan/internal/parsing.h>

namespace Botan_Tests {

class Cat_Kdf_Roundtrip_Test final : public Text_Based_Test {
   private:
      /// @returns (key gen bytes, kem encapsulation bytes)
      std::pair<size_t, size_t> probe_ecdh_rng_calls(const Botan::EC_Group& group) {
         Request_Counting_RNG keygen_rng;

         Botan::KEX_to_KEM_Adapter_PrivateKey ecdh_key(std::make_unique<Botan::ECDH_PrivateKey>(keygen_rng, group));

         Request_Counting_RNG kem_rng;
         auto kem_encryptor = Botan::PK_KEM_Encryptor(ecdh_key, "Raw");
         kem_encryptor.encrypt(kem_rng, 0 /*No KDF*/);

         return {keygen_rng.bytes_requested_count(), kem_rng.bytes_requested_count()};
      }

      std::unique_ptr<Fixed_Output_RNG> prepare_rng(const Botan::EC_Group& ecdh_group,
                                                    std::span<const uint8_t> ecdh_sk,
                                                    std::span<const uint8_t> encaps_ecdh_sk,
                                                    std::span<const uint8_t> kyber_kat_seed) {
         auto rng = std::make_unique<Fixed_Output_RNG>();
         auto [ecdh_keygen_rng_bytes, ecdh_kem_rng_bytes] = probe_ecdh_rng_calls(ecdh_group);
         auto ecdh_keygen_blinding_bytes = ecdh_keygen_rng_bytes - ecdh_sk.size();
         auto ecdh_kex_blinding_bytes = ecdh_kem_rng_bytes - encaps_ecdh_sk.size();

         // ECDH keygen
         rng->add_entropy(ecdh_sk);
         rng->add_entropy(std::vector<uint8_t>(ecdh_keygen_blinding_bytes, 0));

         // Kyber keygen
         CTR_DRBG_AES256 kyber_rng(kyber_kat_seed);
         rng->add_entropy(kyber_rng.random_vec(32));  // seed
         rng->add_entropy(kyber_rng.random_vec(32));  // z

         // ECDH encaps
         rng->add_entropy(encaps_ecdh_sk);
         rng->add_entropy(std::vector<uint8_t>(ecdh_kex_blinding_bytes, 0));  // blinded KEX

         // Kyber encaps (TODO: with fallback rng)
         for(size_t i = 0; i < 256; ++i) {
            rng->add_entropy(kyber_rng.random_vec(32));  // encaps
         }

         return rng;
      }

      // @return (mode with SHA-2, mode with SHA-3)
      std::pair<Botan::Cat_Kdf_Mode, Botan::Cat_Kdf_Mode> parse_mode(std::string_view mode_str) {
         std::vector<std::string> parts = Botan::split_on(mode_str, '/');
         if(parts.size() != 4) {
            throw Test_Error(Botan::fmt("Invalid mode string: ", mode_str));
         }
         std::string sha_2_instance = Botan::fmt("SHA-{}", parts[3]);
         std::string sha_3_instance = Botan::fmt("SHA-3({})", parts[3]);

         Botan::Cat_Kdf_Mode sha_2_mode(parts[0], parts[1], parts[2], sha_2_instance);
         Botan::Cat_Kdf_Mode sha_3_mode(parts[0], parts[1], parts[2], sha_3_instance);

         return {std::move(sha_2_mode), std::move(sha_3_mode)};
      }

   public:
      Cat_Kdf_Roundtrip_Test() :
            Text_Based_Test(
               "pubkey/cat_kdf.vec",
               "mode,context,sk,pk,encaps_ecdh_sk,kyber_kat_seed,ct,shared_secret_before_kdf,shared_secret_sha2,shared_secret_sha3") {
      }

      Test::Result run_one_test(const std::string& /*tag_str*/, const VarMap& vars) override {
         Test::Result result("CatKDF Roundtrip");

         auto mode_str = vars.get_req_str("mode");
         auto context = vars.get_req_bin("context");
         auto sk_ref = vars.get_req_bin("sk");
         auto pk_ref = vars.get_req_bin("pk");
         auto encaps_ecdh_sk = vars.get_req_bin("encaps_ecdh_sk");
         auto kyber_kat_seed = vars.get_req_bin("kyber_kat_seed");
         auto ct_ref = vars.get_req_bin("ct");
         auto shared_secret_before_kdf = vars.get_req_bin("shared_secret_before_kdf");
         auto shared_secret_sha2 = vars.get_req_bin("shared_secret_sha2");
         auto shared_secret_sha3 = vars.get_req_bin("shared_secret_sha3");

         auto [sha_2_mode, sha_3_mode] = parse_mode(mode_str);

         std::map<std::string, std::vector<uint8_t>> shared_secret_for_hash_algo = {
            {sha_2_mode.hash_algo(), std::move(shared_secret_sha2)},
            {sha_3_mode.hash_algo(), std::move(shared_secret_sha3)},
         };

         for(const auto& mode : {sha_2_mode, sha_3_mode}) {
            auto exp_shared_secret = shared_secret_for_hash_algo[mode.hash_algo()];

            auto rng = prepare_rng(mode.ecdh_group(),
                                   std::span(sk_ref).subspan(0, 32 /*TODO: generalize*/),
                                   encaps_ecdh_sk,
                                   kyber_kat_seed);

            Botan::Cat_Kdf_PrivateKey sk(*rng, mode);

            result.test_eq("Private key creation", sk.private_key_bits(), sk_ref);
            result.test_eq("Public key creation", sk.public_key_bits(), pk_ref);

            auto encryptor = Botan::PK_KEM_Encryptor(sk);
            size_t desired_ss_len = exp_shared_secret.size();
            auto [ct, ss] = Botan::KEM_Encapsulation::destructure(encryptor.encrypt(*rng, desired_ss_len));

            result.test_eq("Ciphertext creation", ct, ct_ref);
            result.test_eq("Shared secret", ss, exp_shared_secret);

            auto decryptor = Botan::PK_KEM_Decryptor(sk, *rng);
            auto ss_dec = decryptor.decrypt(ct, desired_ss_len);

            result.test_eq(Botan::fmt("Decrypted shared secret ({})", mode.hash_algo()), ss_dec, exp_shared_secret);
         }

         return result;
      }
};

class Cat_Kdf_Combiner_Func_Test final : public Text_Based_Test {
   public:
      Cat_Kdf_Combiner_Func_Test() :
            Text_Based_Test("pubkey/cat_kdf_combiner_func.vec",
                            "hash_output_bits,LA,PA1,PA2,LB,PB1,PB2,k1,k2,key_material_sha2,key_material_sha3") {}

      Test::Result run_one_test(const std::string& context_str, const VarMap& vars) override {
         Test::Result result("CatKDF Combiner Function Test");

         auto hash_output_bits = vars.get_req_sz("hash_output_bits");
         auto label_a = vars.get_req_bin("LA");
         auto public_val_a1 = vars.get_req_bin("PA1");
         auto public_val_a2 = vars.get_req_bin("PA2");
         auto label_b = vars.get_req_bin("LB");
         auto public_val_b1 = vars.get_req_bin("PB1");
         auto public_val_b2 = vars.get_req_bin("PB2");
         auto k1 = Botan::lock(vars.get_req_bin("k1"));
         auto k2 = Botan::lock(vars.get_req_bin("k2"));

         // label = LA || LB
         auto label = Botan::concat(label_a, label_b);
         // MA = LA || PA1 || PA2
         auto ma = Botan::concat(label_a, public_val_a1, public_val_a2);
         // MB = LB || PB1 || PB2
         auto mb = Botan::concat(label_b, public_val_b1, public_val_b2);

         std::vector<uint8_t> context(context_str.begin(), context_str.end());

         {
            // SHA-2
            auto key_material_sha2 = Botan::lock(vars.get_req_bin("key_material_sha2"));
            auto hash_func = Botan::fmt("SHA-{}", hash_output_bits);

            Botan::secure_vector<uint8_t> shared_secret(key_material_sha2.size());
            Botan::Cat_Kdf::cat_kdf_secret_combiner(shared_secret, hash_func, ma, mb, {k1, k2}, {}, context, label);

            result.test_eq("CatKDF output with SHA-2", shared_secret, key_material_sha2);
         }
         {
            // SHA-3
            auto key_material_sha3 = Botan::lock(vars.get_req_bin("key_material_sha3"));
            auto hash_func = Botan::fmt("SHA-3({})", hash_output_bits);

            Botan::secure_vector<uint8_t> shared_secret(key_material_sha3.size());
            Botan::Cat_Kdf::cat_kdf_secret_combiner(shared_secret, hash_func, ma, mb, {k1, k2}, {}, context, label);

            result.test_eq("CatKDF output with SHA-3", shared_secret, key_material_sha3);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "cat_kdf", Cat_Kdf_Roundtrip_Test);

BOTAN_REGISTER_TEST("pubkey", "cat_kdf_comb_func", Cat_Kdf_Combiner_Func_Test);

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_CAT_KDF
