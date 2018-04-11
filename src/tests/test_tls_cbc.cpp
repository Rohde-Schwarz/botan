/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_CBC)
   #include <botan/internal/tls_cbc.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TLS_CBC)

class TLS_CBC_Padding_Tests final : public Text_Based_Test
   {
   public:
      TLS_CBC_Padding_Tests() : Text_Based_Test("tls_cbc_padding.vec", "Record,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::vector<uint8_t> record    = get_req_bin(vars, "Record");
         const size_t output = get_req_sz(vars, "Output");

         uint16_t res = Botan::TLS::check_tls_cbc_padding(record.data(), record.size());

         Test::Result result("TLS CBC padding check");
         result.test_eq("Expected", res, output);
         return result;
         }
   };

BOTAN_REGISTER_TEST("tls_cbc_padding", TLS_CBC_Padding_Tests);

class TLS_CBC_Tests final : public Text_Based_Test
   {
   public:

      class ZeroMac : public Botan::MessageAuthenticationCode
         {
         public:
            ZeroMac(size_t mac_len) : m_mac_len(mac_len) {}

            void clear() override {}

            std::string name() const override { return "ZeroMac"; }
            size_t output_length() const override { return m_mac_len; }

            void add_data(const uint8_t[], size_t) override {}

            void final_result(uint8_t out[]) override
               {
               std::memset(out, 0, m_mac_len);
               }

            Botan::Key_Length_Specification key_spec() const override
               {
               return Botan::Key_Length_Specification(0, 0, 1);
               }

            virtual MessageAuthenticationCode* clone() const override { return new ZeroMac(m_mac_len); }

         private:
            void key_schedule(const uint8_t[], size_t) override {}

            size_t m_mac_len;
         };

      class Noop_Block_Cipher : public Botan::BlockCipher
         {
         public:
            Noop_Block_Cipher(size_t bs) : m_bs(bs) {}

            void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
               {
               std::memmove(out, in, blocks * m_bs);
               }

            void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
               {
               std::memmove(out, in, blocks * m_bs);
               }

            size_t block_size() const override { return m_bs; }
            void clear() override { }
            std::string name() const override { return "noop"; }

            Botan::Key_Length_Specification key_spec() const override
               {
               return Botan::Key_Length_Specification(0, 0, 1);
               }

            virtual BlockCipher* clone() const override { return new Noop_Block_Cipher(m_bs); }
         private:
            void key_schedule(const uint8_t[], size_t) override {}

            size_t m_bs;
         };

      TLS_CBC_Tests() : Text_Based_Test("tls_cbc.vec", "Blocksize,MACsize,Record,Valid") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("TLS CBC");

         const size_t block_size = get_req_sz(vars, "Blocksize");
         const size_t mac_len = get_req_sz(vars, "MACsize");
         const std::vector<uint8_t> record = get_req_bin(vars, "Record");
         const bool is_valid = get_req_sz(vars, "Valid") == 1;

         // todo test permutations
         bool explicit_iv = true;
         bool encrypt_then_mac = false;

         Botan::TLS::TLS_CBC_HMAC_AEAD_Decryption tls_cbc(
            std::unique_ptr<Botan::BlockCipher>(new Noop_Block_Cipher(block_size)),
            std::unique_ptr<Botan::MessageAuthenticationCode>(new ZeroMac(mac_len)),
            0, 0, explicit_iv, encrypt_then_mac);

         tls_cbc.set_key(std::vector<uint8_t>(0));
         std::vector<uint8_t> ad(13);
         tls_cbc.set_associated_data(ad.data(), ad.size());

         Botan::secure_vector<uint8_t> vec(record.begin(), record.end());

         try
            {
            tls_cbc.finish(vec, 0);
            if(is_valid)
               result.test_success("Accepted valid TLS-CBC ciphertext");
            else
               result.test_failure("Accepted invalid TLS-CBC ciphertext");
            }
         catch(std::exception& e)
            {
            if(is_valid)
               result.test_failure("Rejected valid TLS-CBC ciphertext");
            else
               result.test_success("Accepted invalid TLS-CBC ciphertext");
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("tls_cbc", TLS_CBC_Tests);

#endif

}

