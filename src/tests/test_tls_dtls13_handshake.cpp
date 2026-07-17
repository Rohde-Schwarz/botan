/*
* (C) 2026 Jack Lloyd
* (C) 2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
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

class DTLS13_Handshake_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("DTLS 1.3 loopback handshake");

         class Test_Callbacks : public Botan::TLS::Callbacks {
            public:
               Test_Callbacks(Test::Result& r, std::vector<std::vector<uint8_t>>& out, std::vector<uint8_t>& recv) :
                     m_results(r), m_outbound(out), m_recv(recv) {}

               void tls_emit_data(std::span<const uint8_t> bits) override {
                  m_outbound.emplace_back(bits.begin(), bits.end());
               }

               void tls_record_received(uint64_t /*seq*/, std::span<const uint8_t> bits) override {
                  m_recv.insert(m_recv.end(), bits.begin(), bits.end());
               }

               void tls_alert(Botan::TLS::Alert alert) override {
                  m_results.test_failure("unexpected alert: " + alert.type_string());
               }

               void tls_session_activated() override { m_results.test_success("session activated"); }

            private:
               Test::Result& m_results;
               std::vector<std::vector<uint8_t>>& m_outbound;
               std::vector<uint8_t>& m_recv;
         };

         // Minimal PSK-based credentials to avoid x509 for this test
         class Credentials_PSK : public Botan::Credentials_Manager {
            public:
               std::vector<Botan::TLS::ExternalPSK> find_preshared_keys(
                  std::string_view /* host */,
                  TLS::Connection_Side /* whoami */,
                  const std::vector<std::string>& /*identities*/,
                  const std::optional<std::string>& /*prf*/) override {
                  Botan::secure_vector<uint8_t> secret(48, 0x42);
                  std::vector<Botan::TLS::ExternalPSK> psks;
                  psks.emplace_back("localhost", "SHA-384", std::move(secret));
                  return psks;
               }
         };

         // Minimal policy: only DTLS 1.3, one cipher/group, no session tickets
         class Test_Policy : public Botan::TLS::Text_Policy {
            public:
               Test_Policy() : Text_Policy("") {}

               bool allow_dtls12() const override { return false; }

               bool allow_dtls13() const override { return true; }

               bool allow_tls12() const override { return false; }

               bool allow_tls13() const override { return false; }

               bool acceptable_protocol_version(Botan::TLS::Protocol_Version v) const override {
                  return v == Botan::TLS::Protocol_Version::DTLS_V13;
               }

               std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
                  return {Botan::TLS::Group_Params::X25519};
               }

               Botan::TLS::Protocol_Version latest_supported_version(bool datagram) const override {
                  return datagram ? Botan::TLS::Protocol_Version::DTLS_V13
                                  : Botan::TLS::Policy::latest_supported_version(datagram);
               }

               size_t new_session_tickets_upon_handshake_success() const override { return 0; }

               std::vector<std::string> allowed_key_exchange_methods() const override { return {"PSK"}; }
         };

         auto rng = Test::new_shared_rng(this->test_name());
         auto policy = std::make_shared<Test_Policy>();
         auto creds = std::make_shared<Credentials_PSK>();
         auto server_sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();
         auto client_sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();

         // Minimal loopback structures for basic testing, i.e., no loss/reordering/fragmentation
         std::vector<std::vector<uint8_t>> c2s;
         std::vector<std::vector<uint8_t>> s2c;
         std::vector<uint8_t> client_recv;
         std::vector<uint8_t> server_recv;
         auto server_cb = std::make_shared<Test_Callbacks>(result, s2c, server_recv);
         auto client_cb = std::make_shared<Test_Callbacks>(result, c2s, client_recv);

         auto server = std::make_unique<Botan::TLS::Server>(server_cb, server_sessions, creds, policy, rng, true);
         auto client = std::make_unique<Botan::TLS::Client>(client_cb,
                                                            client_sessions,
                                                            creds,
                                                            policy,
                                                            rng,
                                                            Botan::TLS::Server_Information("localhost"),
                                                            Botan::TLS::Protocol_Version::DTLS_V13);

         for(size_t rounds = 0; rounds < 50; ++rounds) {
            if(!c2s.empty()) {
               const auto in = std::exchange(c2s, {});
               for(const auto& datagram : in) {
                  server->received_data(datagram.data(), datagram.size());
               }
               continue;
            }
            if(!s2c.empty()) {
               const auto in = std::exchange(s2c, {});
               for(const auto& datagram : in) {
                  client->received_data(datagram.data(), datagram.size());
               }
               continue;
            }
            break;  // nothing left in flight
         }

         result.test_is_true("client completed handshake", client->is_active());
         result.test_is_true("server completed handshake", server->is_active());

         return {result};
      }
};

}  // namespace

BOTAN_REGISTER_TEST("tls", "tls_dtls13_handshake", DTLS13_Handshake_Test);

}  // namespace Botan_Tests

#endif
