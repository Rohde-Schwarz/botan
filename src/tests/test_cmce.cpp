/*
* Tests for Classic McEliece
*
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pubkey.h"
#include "test_rng.h"
#include "tests.h"

#include <botan/cmce.h>
#include <botan/cmce_parameters.h>
#include <botan/hash.h>
#include <botan/pk_algs.h>
#include <botan/pubkey.h>
#include <botan/internal/cmce_debug_utils.h>
#include <botan/internal/cmce_decaps.h>
#include <botan/internal/cmce_encaps.h>
#include <botan/internal/cmce_field_ordering.h>
#include <botan/internal/cmce_gf.h>
#include <botan/internal/cmce_keys_internal.h>
#include <botan/internal/cmce_poly.h>

#include <iostream>

namespace Botan_Tests {

class CMCE_Utility_Tests final : public Test {
   public:
      Test::Result expand_seed_test() {
         Test::Result result("Seed expansion");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::mceliece348864);

         // Created using the reference implementation
         auto seed = Botan::hex_decode_locked("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

         auto exp_first_and_last_bytes = Botan::hex_decode(
            "543e2791fd98dbc1"    // first 8 bytes
            "d332a7c40776ca01");  // last 8 bytes

         size_t byte_length =
            (params.n() + params.sigma2() * params.q() + params.sigma1() * params.t() + params.ell()) / 8;

         auto rand = params.prg(seed)->output_stdvec(byte_length);
         rand.erase(rand.begin() + 8, rand.end() - 8);

         result.test_is_eq("Seed expansion", rand, exp_first_and_last_bytes);

         return result;
      }

      Test::Result create_field_ordering_test() {
         Test::Result result("CMCE Field Ordering");

         auto params = Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::toy);

         // Created using the reference implementation
         auto random_bits = Botan::hex_decode_locked(
            "3273e9bb840d921b0540238e64f3805fce7fff31a4c027bea478c467e87f996f9cfe12ddcee5263e3e1e9c470c8e023b07508380e1a704931a9e8538749d741f");
         Botan::secure_vector<uint16_t> exp_ordering = {1, 15, 4, 14, 11, 9, 10, 3, 6, 7, 12, 2, 13, 0, 5, 8};

         auto ordering = Botan::Classic_McEliece_Field_Ordering::create_field_ordering(params, random_bits);
         result.test_is_eq("Field order creation", ordering->pi_ref(), exp_ordering);

         return result;
      }

      Test::Result reconstruct_field_ordering_test() {
         Test::Result result("CMCE Field Ordering from Control Bits");

         auto params = Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::toy);

         // Created using the reference implementation
         auto random_bits = Botan::hex_decode_locked(
            "3273e9bb840d921b0540238e64f3805fce7fff31a4c027bea478c467e87f996f9cfe12ddcee5263e3e1e9c470c8e023b07508380e1a704931a9e8538749d741f");

         auto ord = Botan::Classic_McEliece_Field_Ordering::create_field_ordering(params, random_bits);
         result.confirm("Field order creation successful", ord.has_value());
         auto ord_from_cb =
            Botan::Classic_McEliece_Field_Ordering::create_from_control_bits(params, ord->alphas_control_bits());
         result.test_is_eq("Field order creation from control bits", ord_from_cb.pi_ref(), ord->pi_ref());

         return result;
      }

      Test::Result irreducible_poly_gen_test() {
         Test::Result result("Irreducible Polynomial Generation");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::mceliece348864);

         auto& field = params.poly_ring();

         // Created using the reference implementation
         auto random_bits = Botan::hex_decode(
            "d9b8bb962a3f9dac0f832d243def581e7d26f4028de1ff9cd168460e5050ab095a32a372b40d720bd5d75389a6b3f08fa1d13cec60a4b716d4d6c240f2f80cd3cbc76ae0dddca164c1130da185bd04e890f2256fb9f4754864811e14ea5a43b8b3612d59cecde1b2fdb6362659a0193d2b7d4b9d79aa1801dde3ca90dc300773");

         auto exp_g = Botan::Classic_McEliece_Minimal_Polynomial::from_bytes(
            Botan::hex_decode(
               "8d00a50f520a0307b8007c06cb04b9073b0f4a0f800fb706a60f2a05910a670b460375091209fc060a09ab036c09e5085a0df90d3506b404a30fda041d09970f1206d000e00aac01c00dc80f490cd80b4108330c0208cf00d602450ec00a21079806eb093f00de015f052905560917081b09270c820af002000c34094504cd03"),
            params.poly_f());
         auto beta = field.create_element_from_bytes(random_bits);
         result.test_is_eq("Beta creation", beta.coef_at(0), Botan::Classic_McEliece_GF(0x08d9, params.poly_f()));
         result.test_is_eq("Beta length", beta.coef().size(), random_bits.size() / sizeof(uint16_t));

         auto g = params.poly_ring().compute_minimal_polynomial(beta);
         result.confirm("Minimize polynomial successful", g.has_value());
         result.test_is_eq("Minimize polynomial", g.value().coef(), exp_g.coef());

         return result;
      }

      Test::Result gf_test() {
         Test::Result result("GF test");

         uint16_t exp_mul = 0x001e;  //00011110

         auto val1 = Botan::Classic_McEliece_GF(0b00000000010110111, 0b100011011);
         auto val2 = Botan::Classic_McEliece_GF(0b00000000011001001, 0b100011011);
         auto mul = val1 * val2;
         result.test_is_eq("Control bits creation", mul.elem(), exp_mul);

         return result;
      }

      Test::Result gf_inv_test() {
         Test::Result result("GF inv test");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::mceliece348864);

         auto v = params.gf(42);
         auto v_inv = v.inv();
         result.test_is_eq("Control bits creation", (v * v_inv).elem(), static_cast<uint16_t>(1));

         return result;
      }

      Test::Result gf_poly_mul_test() {
         Test::Result result("GF Poly Mul");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::mceliece348864);

         const auto& field = params.poly_ring();

         auto val1 = field.create_element_from_bytes(Botan::hex_decode(
            "bb02d40437094c0ae4034c00b10fed090a04850f660c3b0e110eb409810a86015b0f5804ca0e78089806e20b5b03aa0bc2020b05ea03710da902340c390f630bbc07a70db20b9e0ee4038905a00a09090a0521045e0a0706370b5a00050a4100480c4d0e8f00730692093701fe04650dbe0fd00702011a04910360023f04fb0a"));

         auto val2 = field.create_element_from_bytes(Botan::hex_decode(
            "060c630b170abb00020fef03e501020e89098108bf01f30dd30900000e0d3d0ca404ec01190760021f088c09b90b0a06a702d104500f0f02f00a580287010a094e01490d270c73051800bc0af303b901b202b50321002802b903ce0ab40806083f0a2d06d002df0f260811005c02a10b300e5c0ba20d14045003c50f2f02de02"));

         auto exp_mul = field.create_element_from_bytes(Botan::hex_decode(
            "370d090b19008f0efb01f5011b04f9054b0d1f071d0457011e09cd0dfa093c004f08500e670abb0567090000f603770a3905bf044408b8025805930b250122018d0a560e840d960d9d0a280d1d06fc08d5078c06fe0cb406d0061e02c6090507d20eb10cb90146085c042e030c0e1a07910fcd0c5f0fda066c0cee061d01f40f"));

         auto mul = field.multiply(val1, val2);  // val1 * val2;
         result.test_is_eq("GF multiplication", mul.coef(), exp_mul.coef());

         return result;
      }

      std::vector<Test::Result> run() override {
         return {expand_seed_test(),
                 create_field_ordering_test(),
                 irreducible_poly_gen_test(),
                 gf_test(),
                 gf_inv_test(),
                 gf_poly_mul_test(),
                 reconstruct_field_ordering_test()};
      }
};

class CMCE_KeyGen_Test final : public Text_Based_Test {
   public:
      CMCE_KeyGen_Test() : Text_Based_Test("pubkey/cmce_kat_hashed.vec", "seed,hashed_pk,hashed_sk", "ct,ss") {}

      Test::Result run_one_test(const std::string& params_str, const VarMap& vars) override {
         Test::Result result("CMCE KeyGen");

         auto kat_hash = Botan::HashFunction::create("SHAKE-256(512)");

         const auto kat_seed = Botan::lock(vars.get_req_bin("seed"));
         const auto ref_hashed_sk = Botan::lock(vars.get_req_bin("hashed_sk"));
         const auto ref_hashed_pk = vars.get_req_bin("hashed_pk");

         auto test_rng = std::make_unique<CTR_DRBG_AES256>(kat_seed);

         auto private_key = Botan::create_private_key("ClassicMcEliece", *test_rng, params_str);

         auto sk_bytes = private_key->raw_private_key_bits();
         auto pk_bytes = private_key->public_key_bits();

         result.test_is_eq("SK creation", kat_hash->process(sk_bytes), ref_hashed_sk);
         result.test_is_eq("PK creation", Botan::unlock(kat_hash->process(pk_bytes)), ref_hashed_pk);

         return result;
      }

      // TODO: Reactivate semi-systematic instances
      bool skip_this_test(const std::string& params_str, const VarMap&) override {
         //return false;
         auto params = Botan::Classic_McEliece_Parameters::create(params_str);
         // return (params.m() * params.t()) % 32 != 0 && params.is_f();
         return params.set() != Botan::Classic_McEliece_Parameter_Set::mceliece348864f;
         //return params.is_f();
      }
};

class CMCE_Roundtrip_Test : public Text_Based_Test {
   public:
      CMCE_Roundtrip_Test() : Text_Based_Test("pubkey/cmce_kat_hashed.vec", "seed,ct,ss", "hashed_pk,hashed_sk") {}

      Test::Result run_one_test(const std::string& params_str, const VarMap& vars) override {
         Test::Result result("CMCE Roundtrip Test");

         auto kat_hash = Botan::HashFunction::create("SHAKE-256(512)");

         const auto kat_seed = Botan::lock(vars.get_req_bin("seed"));
         const auto ref_ct = vars.get_req_bin("ct");
         const auto ref_ss = Botan::lock(vars.get_req_bin("ss"));

         const auto test_rng = std::make_unique<CTR_DRBG_AES256>(kat_seed);

         auto params = Botan::Classic_McEliece_Parameters::create(params_str);

         auto private_key = Botan::create_private_key("ClassicMcEliece", *test_rng, params_str);
         auto enc = Botan::PK_KEM_Encryptor(*private_key, "Raw", "base");

         auto encaps = enc.encrypt(*test_rng);

         result.test_is_eq("Ciphertext", encaps.encapsulated_shared_key(), ref_ct);
         result.test_is_eq("Shared Secret", encaps.shared_key(), ref_ss);

         // Decaps
         auto dec = Botan::PK_KEM_Decryptor(*private_key, *test_rng);
         auto decaps = dec.decrypt(encaps.encapsulated_shared_key());

         result.test_is_eq("Shared Secret from Decaps", decaps, ref_ss);

         return result;
      }

      // TODO: Skip slow instances if slow tests are disabled
      bool skip_this_test(const std::string&, const VarMap&) override { return false; }
};

// TODO: For easier development. Remove me before release.
class CMCE_Fast_Test : public CMCE_Roundtrip_Test {
      bool skip_this_test(const std::string& params_str, const VarMap&) override {
         auto params = Botan::Classic_McEliece_Parameters::create(params_str);
         return params.set() != Botan::Classic_McEliece_Parameter_Set::mceliece348864f;
         //return params.set() != Botan::Classic_McEliece_Parameter_Set::mceliece6688128pcf;
      }
};

class CMCE_Invalid_Test : public Text_Based_Test {
   public:
      CMCE_Invalid_Test() :
            Text_Based_Test("pubkey/cmce_negative.vec", "seed,ct_invalid,ss_invalid", "ct_invalid_c1,ss_invalid_c1") {}

      Test::Result run_one_test(const std::string& params_str, const VarMap& vars) override {
         Test::Result result("CMCE Invalid Ciphertext Test");

         auto params = Botan::Classic_McEliece_Parameters::create(params_str);

         const auto kat_seed = Botan::lock(vars.get_req_bin("seed"));
         const auto ct_invalid = vars.get_req_bin("ct_invalid");
         const auto ref_ss_invalid = Botan::lock(vars.get_req_bin("ss_invalid"));

         const auto test_rng = std::make_unique<CTR_DRBG_AES256>(kat_seed);

         auto private_key = Botan::create_private_key("ClassicMcEliece", *test_rng, params_str);

         // Decaps an invalid ciphertext
         auto dec = Botan::PK_KEM_Decryptor(*private_key, *test_rng);
         auto decaps_ct_invalid = dec.decrypt(ct_invalid);

         result.test_is_eq("Decaps an invalid encapsulated key", decaps_ct_invalid, ref_ss_invalid);

         if(params.is_pc()) {
            // For pc variants, additionally check the plaintext confirmation (pc) logic by
            // flipping a bit in the second part of the ciphertext (C_1 in pc). In this case
            // C_0 is decoded correctly, but pc will change the shared secret, since C_1' != C_1.
            const auto ct_invalid_c1 = vars.get_opt_bin("ct_invalid_c1");
            const auto ref_ss_invalid_c1 = Botan::lock(vars.get_opt_bin("ss_invalid_c1"));
            auto decaps_ct_invalid_c1 = dec.decrypt(ct_invalid_c1);

            result.test_is_eq("Decaps with invalid C_1 in pc", decaps_ct_invalid_c1, ref_ss_invalid_c1);
         }

         return result;
      }

      bool skip_this_test(const std::string& params_str, const VarMap&) override {
         auto params = Botan::Classic_McEliece_Parameters::create(params_str);
         return !params.is_pc();
      }
};

#if false
class CMCE_Decaps_Unit_Test final : public Text_Based_Test {
   private:
      std::vector<Botan::Classic_McEliece_GF> gf_vector_from_bytes(const Botan::Classic_McEliece_Parameters& params,
                                                                   const std::vector<uint8_t>& bytes) {
         BOTAN_ASSERT_NOMSG(bytes.size() % 2 == 0);
         size_t n = bytes.size() / 2;
         std::vector<Botan::Classic_McEliece_GF> vec;
         for(size_t i = 0; i < n; ++i) {
            uint16_t elem = (uint32_t(bytes.at(2 * i)) << 8) | bytes.at(2 * i + 1);
            vec.push_back(Botan::Classic_McEliece_GF(elem, params.poly_f()));
         }

         return vec;
      }

   public:
      CMCE_Decaps_Unit_Test() :
            Text_Based_Test("pubkey/cmce_decaps_unit.vec",
                            "seed,field_ord,syndrome,locator,images,hashed_pk,hashed_sk,ciphertext,shared_secret") {}

      Test::Result run_one_test(const std::string& params_str, const VarMap& vars) override {
         Test::Result result("CMCE Decaps Unit Test");

         auto kat_hash = Botan::HashFunction::create("SHAKE-256(512)");

         auto params = Botan::Classic_McEliece_Parameters::create(params_str);

         const auto kat_seed = Botan::lock(vars.get_req_bin("seed"));
         const auto ref_hashed_sk = Botan::lock(vars.get_req_bin("hashed_sk"));
         const auto ref_hashed_pk = vars.get_req_bin("hashed_pk");
         const auto ct = vars.get_req_bin("ciphertext");
         const auto ref_syndrome = gf_vector_from_bytes(params, vars.get_req_bin("syndrome"));
         const auto ref_locator = gf_vector_from_bytes(params, vars.get_req_bin("locator"));
         const auto ref_images = gf_vector_from_bytes(params, vars.get_req_bin("images"));
         const auto ref_field_ord = gf_vector_from_bytes(params, vars.get_req_bin("field_ord"));

         auto test_rng = std::make_unique<CTR_DRBG_AES256>(kat_seed);

         auto [sk, pk] = Botan::cmce_key_gen(params, test_rng->random_vec(32));

         auto control_bits = sk.alpha().alphas_control_bits();

         // Test field ordering from control bits
         auto alphas_from_control_bits =
            Botan::Classic_McEliece_Field_Ordering::create_from_control_bits(params, control_bits).alphas();

         auto n_alphas_from_control_bits = std::vector<Botan::Classic_McEliece_GF>(
            alphas_from_control_bits.begin(), alphas_from_control_bits.begin() + params.n());

         result.test_is_eq("Read Field Ordering from Control Bits", n_alphas_from_control_bits, ref_field_ord);

         // Test Classic_McEliece_Minimal_Polynomial::from_bytes
         auto goppa_poly_from_bytes =
            Botan::Classic_McEliece_Minimal_Polynomial::from_bytes(sk.g().serialize(), params.poly_f());
         result.test_is_eq("Read Goppa Polynomial from Bytes", goppa_poly_from_bytes.serialize(), sk.g().serialize());

         // Test syndrome computation
         auto code_word = Botan::bitvector(ct, params.m() * params.t());
         code_word.resize(params.n());

         auto syndrome = compute_goppa_syndrome(params, sk.g(), sk.alpha(), code_word.as_locked());
         result.test_is_eq("Compute Syndrome", syndrome, ref_syndrome);

         // Test the Berlekamp-Massey Algorithm
         auto locator = berlekamp_massey(params, syndrome);
         result.test_is_eq("Berlekamp-Massey Algorithm", locator.coef(), ref_locator);

         // Test application of the locator polynomial
         std::vector<Botan::Classic_McEliece_GF> images;
         images.reserve(ref_field_ord.size());
         for(auto& alpha : ref_field_ord) {
            images.push_back(locator(alpha));
         }
         result.test_is_eq("Test application of the locator polynomial", images, ref_images);

         return result;
      }
};
#endif

class CMCE_Generic_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         return {"mceliece348864",
                 "mceliece348864f",

                 "mceliece460896",
                 "mceliece460896f",

                 "mceliece6688128",
                 "mceliece6688128f",
                 "mceliece6688128pc",
                 "mceliece6688128pcf",

                 "mceliece6960119",
                 "mceliece6960119f",
                 "mceliece6960119pc",
                 "mceliece6960119pcf",

                 "mceliece8192128",
                 "mceliece8192128f",
                 "mceliece8192128pc",
                 "mceliece8192128pcf"};
      }

      std::string algo_name() const override { return "ClassicMcEliece"; }
};

/**
 * This is a test using a minimal instance. Since this instance is self constructed,
 * we have no known answer to check against. However, this test may be useful for
 * side channel analysis.
 *
 * Hints for SCA:
 * Build only ClassicMcEliece with (for example):
 *    ./configure.py --compiler-cache=ccache --minimized-build --enable-modules=classic_mceliece --build-targets=static,tests --without-documentation --build-tool=ninja && ninja
 * Run only this test without prints:
 *    ./botan-test cmce_minimal --test-threads=1 --no-stdout
 */
class CMCE_Minimal_Test final : public Test {
   public:
      Test::Result run_minimal_keygen_test(std::string_view param_set) {
         Test::Result result("Minimal KeyGen Test");

         const Botan::secure_vector<uint8_t> rng_seed(48, 0);
         const auto test_rng = std::make_unique<CTR_DRBG_AES256>(rng_seed);

         // Test Keygen
         std::unique_ptr<Botan::Private_Key> private_key;
         result.test_no_throw("Key Generation", [&] {
            private_key = Botan::create_private_key("ClassicMcEliece", *test_rng, param_set);
         });
         if(!private_key) {
            // Keygen failed
            return result;
         }

         // Test Encapsulation
         std::optional<Botan::KEM_Encapsulation> encaps = std::nullopt;
         result.test_no_throw("Encapsulation", [&] {
            auto enc = Botan::PK_KEM_Encryptor(*private_key, "Raw", "base");
            encaps = enc.encrypt(*test_rng);
         });

         // Test Decapsulation
         Botan::secure_vector<uint8_t> decaps;
         result.test_no_throw("Decapsulation", [&] {
            auto dec = Botan::PK_KEM_Decryptor(*private_key, *test_rng);
            decaps = dec.decrypt(encaps->encapsulated_shared_key());
         });

         result.test_is_eq("Decapsulated secret is correct", decaps, encaps->shared_key());

         return result;
      }

      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         // The parameter decides which instance is tested, i.e. with our without
         // semi-systematic gauss or plaintext confirmation.
         results.push_back(run_minimal_keygen_test("test"));
         results.push_back(run_minimal_keygen_test("testf"));
         results.push_back(run_minimal_keygen_test("testpc"));
         results.push_back(run_minimal_keygen_test("testpcf"));

         return results;
      }
};

BOTAN_REGISTER_TEST("cmce", "cmce_utility", CMCE_Utility_Tests);
BOTAN_REGISTER_TEST("cmce", "cmce_keygen", CMCE_KeyGen_Test);
BOTAN_REGISTER_TEST("cmce", "cmce_generic_keygen", CMCE_Generic_Keygen_Tests);
BOTAN_REGISTER_TEST("cmce", "cmce_roundtrip", CMCE_Roundtrip_Test);
BOTAN_REGISTER_TEST("cmce", "cmce_fast", CMCE_Fast_Test);
BOTAN_REGISTER_TEST("cmce", "cmce_invalid", CMCE_Invalid_Test);
//BOTAN_REGISTER_TEST("cmce", "cmce_decaps_unit", CMCE_Decaps_Unit_Test);
BOTAN_REGISTER_TEST("cmce", "cmce_minimal", CMCE_Minimal_Test);

}  // namespace Botan_Tests
