/*
* (C) 2026 Jack Lloyd
* (C) 2026 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DTLS_13)

   #include <botan/hex.h>
   #include <botan/tls.h>

   #include <botan/internal/concat_util.h>
   #include <botan/internal/tls_channel_impl_13.h>
   #include <botan/internal/tls_cipher_state.h>

namespace Botan_Tests {

namespace {

using namespace Botan;
using namespace Botan::TLS;

// Minimal secret logger that records what the cipher state logs.
// (Similar to test_tls_cipher_state.cpp.)
class Journaling_Secret_Logger : public Secret_Logger {
   public:
      void maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const override {
         secrets[std::string(label)] = std::vector<uint8_t>(secret.begin(), secret.end());
      }

   public:
      mutable std::map<std::string, std::vector<uint8_t>> secrets;  // NOLINT(*-non-private-member-variable*)
};

std::vector<Test::Result> update_cipher_state() {
   const auto cipher = Ciphersuite::from_name("AES_128_GCM_SHA256").value();

   Journaling_Secret_Logger sl_client;
   Journaling_Secret_Logger sl_server;

   const std::vector<uint8_t> transcript_hash(32, 0x00);

   auto cs_server =
      Cipher_State::init_with_server_hello(Connection_Side::Server,
                                           secure_vector<uint8_t>(32, 0x00),  // shared_secret = 32 zero bytes
                                           cipher,
                                           transcript_hash,
                                           sl_server,
                                           TLS_Flavor::DTLS);
   auto cs_client = Cipher_State::init_with_server_hello(
      Connection_Side::Client, secure_vector<uint8_t>(32, 0x00), cipher, transcript_hash, sl_client, TLS_Flavor::DTLS);

   const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"
   // Unified header: C=0 S=0(8-bit seq) L=0 EE=2 -> 0b00100010 -> 0x22
   //                 plus 8-bit seq no
   const std::vector<uint8_t> unified_header = {0x22, 0x00};

   // reference vectors created via gen_dtls13_cipherstate_vecs.py
   const auto c_hs_traffic =
      hex_decode("c0 91 0e b2 69 ed 01 50 f6 a8 f3 ea bc 49 0e 58 47 c1 33 9f 43 a1 3f 83 ef b4 ee 71 e4 ef ff ba");

   const auto s_hs_traffic =
      hex_decode("81 9d 08 f9 28 c5 ec 8c ce 7f ed 6f dd b5 d1 ef 48 55 17 50 c1 a3 30 66 c9 fa ea d9 7d 28 c0 99");

   const auto ciphertext = hex_decode("a6 0c 82 3b bb 98 bf f5 91 9e e8 9b e2 13 8d b8 8d ee 15 df fc 65 b6 07 32 4f");

   return {
      CHECK("key schedule uses 'dtls13' label prefix",
            [&](Test::Result& result) {
               result.test_bin_eq("client_handshake_traffic_secret",
                                  sl_client.secrets.at("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
                                  c_hs_traffic);
               result.test_bin_eq("server_handshake_traffic_secret",
                                  sl_server.secrets.at("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
                                  s_hs_traffic);
            }),

      CHECK("AEAD encrypt/decrypt round-trip with explicit seq_no",
            [&](Test::Result& result) {
               constexpr uint64_t seq_no = 0;
               // Encrypt on server side
               auto fragment = secure_vector<uint8_t>(plaintext);
               result.test_no_throw("server encrypts successfully",
                                    [&] { cs_server->encrypt_record_fragment_dtls(seq_no, unified_header, fragment); });
               result.test_bin_eq("encrypted fragment matches", fragment, ciphertext);

               // Decrypt on client side
               result.test_no_throw("client decrypts successfully",
                                    [&] { cs_client->decrypt_record_fragment_dtls(seq_no, unified_header, fragment); });
               result.test_bin_eq("decrypted plaintext matches", fragment, plaintext);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "dtls_cipher_state", update_cipher_state);

}  // namespace Botan_Tests

#endif
