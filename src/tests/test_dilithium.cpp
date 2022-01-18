#define BOTAN_HAS_DILITHIUM
/*
 * Tests for Crystals Dilithium
 * - simple roundtrip test
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Dilithium-Round3.zip
 *
 * (C) 2021-2022 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_rng.h"
#include "tests.h"

#if defined(BOTAN_HAS_DILITHIUM)
    #include <dilithium/dilithium_api.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_DILITHIUM)

namespace {

Test::Result run_dilithium_test(const char* test_name, const VarMap& vars )
   {
        Test::Result result(test_name);
        char                fn_req[32], fn_rsp[32];
        FILE                *fp_req, *fp_rsp;
        unsigned char       seed[48];
        unsigned char       msg[3300];
        unsigned char       entropy_input[48];
        unsigned char       *m, *sm, *m1;
        unsigned long long  mlen, smlen, mlen1;
        int                 count;
        int                 done;
        unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
        int                 ret_val;

        // read input from test file
        const auto ref_count = vars.get_req_bin("count");
        const auto ref_seed = vars.get_req_bin("seed");
        const auto ref_mlen = vars.get_req_bin("mlen");
        const auto ref_msg = vars.get_req_bin("msg");
        const auto ref_pk = vars.get_req_bin("pk");
        const auto ref_sk = vars.get_req_bin("sk");
        const auto ref_smlen = vars.get_req_bin("smlen");
        const auto ref_sm = vars.get_req_bin("sm");
    
    for (int i=0; i<48; i++)
        entropy_input[i] = i;
        
        m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
        sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
        
        // Generate the public/private keypair
        ret_val = crypto_sign_keypair(pk, sk)

        result.test_eq( "Key generation: " ret_val, 0 );
        result.test_eq( "Public key generation: ", pk, ref_pk);
        result.test_eq( "Private key generation: ", sk, ref_sk);
        
        /*if ( (ret_val = crypto_sign(sm, &smlen, m, mlen, sk)) != 0) {
            printf("crypto_sign returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintf(fp_rsp, "smlen = %llu\n", smlen);
        fprintBstr(fp_rsp, "sm = ", sm, smlen);
        fprintf(fp_rsp, "\n");
        
        if ( (ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk)) != 0) {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        
        if ( mlen != mlen1 ) {
            printf("crypto_sign_open returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen1, mlen);
            return KAT_CRYPTO_FAILURE;
        }
        
        if ( memcmp(m, m1, mlen) ) {
            printf("crypto_sign_open returned bad 'm' value\n");
            return KAT_CRYPTO_FAILURE;
        }*/

        return result;
    }

#define REGISTER_KYBER_KAT_TEST(mode)                                                                                  \
    class DILITHIUM_KAT_##mode final : public Text_Based_Test                                                              \
    {                                                                                                                  \
      public:                                                                                                          \
        DILITHIUM_KAT_##mode() : Text_Based_Test("pubkey/dilithium_" #mode ".vec", "count,seed,mslen,msg,pk,sk,smlen,sm" )            \
        {                                                                                                              \
        }                                                                                                              \
                                                                                                                       \
        Test::Result run_one_test(const std::string &name, const VarMap &vars) override                                \
        {                                                                                                              \
            return run_dilithium_test("Dilithium_" #mode, vars);                          \
        }                                                                                                              \
    };                                                                                                                 \
    BOTAN_REGISTER_TEST("dilithium", "dilithium_kat_" #mode, DILITHIUM_KAT_##mode)

} // namespace



} // namespace Botan_Tests
