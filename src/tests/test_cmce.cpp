/*
* Tests for Classic McEliece
*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

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

         auto exp_first_and_last_bytes = Botan::hex_decode_locked(
            "543e2791fd98dbc1"    // first 8 bytes
            "d332a7c40776ca01");  // last 8 bytes

         size_t exp_bit_length =
            params.n() + params.sigma2() * params.q() + params.sigma1() * params.t() + params.ell();

         Botan::secure_vector<uint8_t> rand = params.prg(seed);
         result.test_eq("Expanded seed length", rand.size(), exp_bit_length / 8);
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
         auto control_bits = ord->alphas_control_bits();
         Botan::secure_bitvector control_bv(control_bits);
         auto ord_from_cb = Botan::Classic_McEliece_Field_Ordering::create_from_control_bits(params, control_bv);
         result.test_is_eq("Field order creation from control bits", ord_from_cb.pi_ref(), ord->pi_ref());

         return result;
      }

      Test::Result irreducible_poly_gen_test() {
         Test::Result result("Irreducible Polynomial Generation");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::mceliece348864);

         auto field = params.poly_ring();

         // Created using the reference implementation
         auto random_bits = Botan::hex_decode(
            "d9b8bb962a3f9dac0f832d243def581e7d26f4028de1ff9cd168460e5050ab095a32a372b40d720bd5d75389a6b3f08fa1d13cec60a4b716d4d6c240f2f80cd3cbc76ae0dddca164c1130da185bd04e890f2256fb9f4754864811e14ea5a43b8b3612d59cecde1b2fdb6362659a0193d2b7d4b9d79aa1801dde3ca90dc300773");
         auto exp_beta = field.create_element_from_coef(
            {0x08d9, 0x06bb, 0x0f2a, 0x0c9d, 0x030f, 0x042d, 0x0f3d, 0x0e58, 0x067d, 0x02f4, 0x018d, 0x0cff, 0x08d1,
             0x0e46, 0x0050, 0x09ab, 0x025a, 0x02a3, 0x0db4, 0x0b72, 0x07d5, 0x0953, 0x03a6, 0x0ff0, 0x01a1, 0x0c3c,
             0x0460, 0x06b7, 0x06d4, 0x00c2, 0x08f2, 0x030c, 0x07cb, 0x006a, 0x0cdd, 0x04a1, 0x03c1, 0x010d, 0x0d85,
             0x0804, 0x0290, 0x0f25, 0x04b9, 0x0875, 0x0164, 0x041e, 0x0aea, 0x0843, 0x01b3, 0x092d, 0x0dce, 0x02e1,
             0x06fd, 0x0636, 0x0059, 0x0d19, 0x0d2b, 0x0d4b, 0x0a79, 0x0118, 0x03dd, 0x00ca, 0x00dc, 0x0307});

         auto exp_g = Botan::Classic_McEliece_Minimal_Polynomial::from_bytes(
            Botan::hex_decode(
               "8d00a50f520a0307b8007c06cb04b9073b0f4a0f800fb706a60f2a05910a670b460375091209fc060a09ab036c09e5085a0df90d3506b404a30fda041d09970f1206d000e00aac01c00dc80f490cd80b4108330c0208cf00d602450ec00a21079806eb093f00de015f052905560917081b09270c820af002000c34094504cd03"),
            params.poly_f());
         auto beta = field.create_element_from_bytes(random_bits);
         result.test_is_eq("Beta creation", beta, exp_beta);

         auto g = beta.compute_minimal_polynomial(params.poly_ring());
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

         auto v = Botan::Classic_McEliece_GF(42, params.poly_f());
         auto v_inv = v.inv();
         result.test_is_eq("Control bits creation", (v * v_inv).elem(), static_cast<uint16_t>(1));

         return result;
      }

      Test::Result gf_poly_mul_test() {
         Test::Result result("GF Poly Mul");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::mceliece348864);

         auto field = params.poly_ring();

         auto val1 = field.create_element_from_coef(
            {0x2bb, 0x4d4, 0x937, 0xa4c, 0x3e4, 0x4c,  0xfb1, 0x9ed, 0x40a, 0xf85, 0xc66, 0xe3b, 0xe11,
             0x9b4, 0xa81, 0x186, 0xf5b, 0x458, 0xeca, 0x878, 0x698, 0xbe2, 0x35b, 0xbaa, 0x2c2, 0x50b,
             0x3ea, 0xd71, 0x2a9, 0xc34, 0xf39, 0xb63, 0x7bc, 0xda7, 0xbb2, 0xe9e, 0x3e4, 0x589, 0xaa0,
             0x909, 0x50a, 0x421, 0xa5e, 0x607, 0xb37, 0x5a,  0xa05, 0x41,  0xc48, 0xe4d, 0x8f,  0x673,
             0x992, 0x137, 0x4fe, 0xd65, 0xfbe, 0x7d0, 0x102, 0x41a, 0x391, 0x260, 0x43f, 0xafb});
         auto val2 = field.create_element_from_coef(
            {0xc06, 0xb63, 0xa17, 0xbb,  0xf02, 0x3ef, 0x1e5, 0xe02, 0x989, 0x881, 0x1bf, 0xdf3, 0x9d3,
             0x0,   0xd0e, 0xc3d, 0x4a4, 0x1ec, 0x719, 0x260, 0x81f, 0x98c, 0xbb9, 0x60a, 0x2a7, 0x4d1,
             0xf50, 0x20f, 0xaf0, 0x258, 0x187, 0x90a, 0x14e, 0xd49, 0xc27, 0x573, 0x18,  0xabc, 0x3f3,
             0x1b9, 0x2b2, 0x3b5, 0x21,  0x228, 0x3b9, 0xace, 0x8b4, 0x806, 0xa3f, 0x62d, 0x2d0, 0xfdf,
             0x826, 0x11,  0x25c, 0xba1, 0xe30, 0xb5c, 0xda2, 0x414, 0x350, 0xfc5, 0x22f, 0x2de});

         auto exp_mul = field.create_element_from_coef(std::vector<uint16_t>{
            0xd37, 0xb09, 0x19,  0xe8f, 0x1fb, 0x1f5, 0x41b, 0x5f9, 0xd4b, 0x71f, 0x41d, 0x157, 0x91e,
            0xdcd, 0x9fa, 0x3c,  0x84f, 0xe50, 0xa67, 0x5bb, 0x967, 0x0,   0x3f6, 0xa77, 0x539, 0x4bf,
            0x844, 0x2b8, 0x558, 0xb93, 0x125, 0x122, 0xa8d, 0xe56, 0xd84, 0xd96, 0xa9d, 0xd28, 0x61d,
            0x8fc, 0x7d5, 0x68c, 0xcfe, 0x6b4, 0x6d0, 0x21e, 0x9c6, 0x705, 0xed2, 0xcb1, 0x1b9, 0x846,
            0x45c, 0x32e, 0xe0c, 0x71a, 0xf91, 0xccd, 0xf5f, 0x6da, 0xc6c, 0x6ee, 0x11d, 0xff4});

         auto mul = field.multiply(val1, val2);  // val1 * val2;
         result.test_is_eq("GF multiplication", mul, exp_mul);

         return result;
      }

      Test::Result compute_syndrome_test() {
         Test::Result result("CMCE Syndrome Computation");

         auto params = Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::toy);

         // Created using the reference implementation
         auto random_bits = Botan::hex_decode_locked(
            "3273e9bb840d921b0540238e64f3805fce7fff31a4c027bea478c467e87f996f9cfe12ddcee5263e3e1e9c470c8e023b07508380e1a704931a9e8538749d741f");

         auto ord = Botan::Classic_McEliece_Field_Ordering::create_field_ordering(params, random_bits);
         result.confirm("Field order creation successful", ord.has_value());
         auto control_bits = ord->alphas_control_bits();
         auto control_bv = Botan::secure_bitvector(control_bits);
         auto ord_from_cb = Botan::Classic_McEliece_Field_Ordering::create_from_control_bits(params, control_bv);
         result.test_is_eq("Field order creation from control bits", ord_from_cb.pi_ref(), ord->pi_ref());

         return result;
      }

      std::vector<Test::Result> run() override {
         const std::vector<std::function<Test::Result(void)>> test_methods = {
            [this]() { return expand_seed_test(); },
            [this]() { return create_field_ordering_test(); },
            [this]() { return irreducible_poly_gen_test(); },
            [this]() { return gf_test(); },
            [this]() { return gf_inv_test(); },
            [this]() { return gf_poly_mul_test(); },
            [this]() { return reconstruct_field_ordering_test(); }};
         std::vector<Test::Result> results;
         results.reserve(test_methods.size());
         for(const auto& test_method : test_methods) {
            results.push_back(test_method());
         }

         return results;
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

      // TODO: Reactivate semi-systematic instances
      bool skip_this_test(const std::string& params_str, const VarMap&) override {
         return false;
         //    auto params = Botan::Classic_McEliece_Parameters::create(params_str);
         //    return params.set() != Botan::Classic_McEliece_Parameter_Set::mceliece6688128f;
         //    return params.is_pc();
      }
};

// TODO: For easier development. Remove me before release.
class CMCE_Fast_Test : public CMCE_Roundtrip_Test {
      bool skip_this_test(const std::string& params_str, const VarMap&) override {
         auto params = Botan::Classic_McEliece_Parameters::create(params_str);
         return params.set() != Botan::Classic_McEliece_Parameter_Set::mceliece6688128pcf;
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

         // (optional)
         // result.test_no_throw("Encapsulation", [&] {
         //    auto enc = Botan::PK_KEM_Encryptor(*private_key, "Raw", "base");
         //    enc.encrypt(*test_rng);
         // });

         return result;
      }

      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         // The parameter decides which instance is tested, i.e. with our without
         // semi-systematic gauss or plaintext confirmation.
         results.push_back(run_minimal_keygen_test("test"));
         //results.push_back(run_minimal_keygen_test("testf"));
         //results.push_back(run_minimal_keygen_test("testpc"));

         return results;
      }
};

BOTAN_REGISTER_TEST("cmce", "cmce_utility", CMCE_Utility_Tests);
BOTAN_REGISTER_TEST("cmce", "cmce_keygen", CMCE_KeyGen_Test);
BOTAN_REGISTER_TEST("cmce", "cmce_roundtrip", CMCE_Roundtrip_Test);
BOTAN_REGISTER_TEST("cmce", "cmce_fast", CMCE_Fast_Test);
//BOTAN_REGISTER_TEST("cmce", "cmce_decaps_unit", CMCE_Decaps_Unit_Test);
BOTAN_REGISTER_TEST("cmce", "cmce_minimal", CMCE_Minimal_Test);

}  // namespace Botan_Tests
