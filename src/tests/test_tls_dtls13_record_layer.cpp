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
   #include <botan/internal/loadstor.h>
   #include <botan/internal/tls_channel_impl_13.h>
   #include <botan/internal/tls_cipher_state.h>
   #include <botan/internal/tls_record_dtls13.h>
   #include <botan/internal/tls_record_layer_dtls13.h>
   #include <botan/internal/tls_utils_dtls13.h>

namespace TLS = Botan::TLS;

namespace Botan_Tests {

namespace {

auto create_policy(std::optional<uint16_t> minimum_record_size = {}) {
   class Test_Policy : public Botan::TLS::Policy {
      public:
         explicit Test_Policy(std::optional<uint16_t> minimum_record_size) :
               m_minimum_record_size(minimum_record_size) {}

         size_t record_padding_bytes(size_t plaintext_bytes) const override {
            return plaintext_bytes < m_minimum_record_size ? *m_minimum_record_size - plaintext_bytes : 0;
         }

      private:
         std::optional<uint16_t> m_minimum_record_size;
   };

   return std::make_shared<Test_Policy>(minimum_record_size);
}

std::vector<Test::Result> read_clienthello_record() {
   const auto client_hello_record = Botan::hex_decode(  // from wolfssl
      "16 fe fd 00 00 00 00 00 00 00 00 01 fa 01 00 01 ee 00 00 00 00"
      "00 00 01 ee fe fd 9a 71 88 3e 33 0e f5 ac f3 1a 3e 34 b6 28 59"
      "cf b5 4b 25 14 e9 fd 7a 88 56 7b 3c 91 56 76 3a 4e 00 00 00 36"
      "13 02 13 01 13 03 c0 2c c0 2b c0 30 c0 2f 00 9f 00 9e cc a9 cc"
      "a8 cc aa c0 27 c0 23 c0 28 c0 24 c0 0a c0 09 c0 14 c0 13 00 6b"
      "00 67 00 39 00 33 cc 14 cc 13 cc 15 01 00 01 8e 00 2b 00 03 02"
      "fe fc 00 0d 00 1c 00 1a 06 03 05 03 04 03 08 06 08 0b 08 05 08"
      "0a 08 04 08 09 06 01 05 01 04 01 03 01 00 0a 00 10 00 0e 11 ed"
      "11 eb 00 19 00 18 00 17 00 15 01 00 00 16 00 00 00 33 01 4b 01"
      "49 00 17 00 41 04 9d 51 3d c7 9b ad 20 a2 4d 54 f7 24 72 ea 25"
      "df 33 0f 51 7e c6 69 34 db 6b 20 52 94 74 ee 2b 4e 3d ad 4b 5d"
      "d6 83 df 82 13 90 be f2 b6 55 67 87 cd a4 30 37 62 e0 6e 45 31"
      "04 1a 5e d0 56 17 97 01 00 01 00 13 9d f5 5b 77 eb 78 86 b2 87"
      "e4 f7 28 7b 09 62 99 ca 70 30 0a 7a 5d 1f 1a fd 78 fd 6a 7b 49"
      "49 ac 66 49 62 48 a7 bc 05 37 cd f0 c3 95 f4 f1 e5 d1 07 dc 8a"
      "48 4a 2a 73 c2 0f 2d 29 66 8f e2 33 69 79 f9 df c8 91 99 20 e4"
      "dc 6d 56 e4 a9 34 bd f5 bc d8 05 b6 f7 de 6c 0b 29 81 7b 60 c5"
      "58 2d 76 7c 4b d9 59 84 65 bb 19 90 a4 13 e4 69 db 5d 2b 7d 03"
      "c3 ef f1 fe 1d f6 3e 9b af fd 69 48 31 74 1a 54 6b 43 05 1c ae"
      "08 90 6d 4e 8b b4 86 e9 90 58 1e bb 34 06 9b 31 eb 11 18 4c aa"
      "84 14 a0 04 0f 71 1b 09 93 c2 b2 ca 0e c1 53 2b 9e 2c 5e 24 92"
      "73 09 72 54 82 40 14 a8 48 9c 9e ab 80 31 36 2c b1 5d fd b7 c1"
      "65 bb b6 c4 e1 9f 0c 53 5c 8d 08 95 28 9c 7a 69 b4 2c 4e 5a b0"
      "b4 9f a1 b3 cd d9 ff 37 78 2d 1f cf ff 4d 76 32 6c d5 fc eb 1a"
      "2c e2 9e 04 85 d3 af 10 3c 4c fa b6 6e 47 66");

   auto policy = create_policy();

   return {
      CHECK("Parse ClientHello",
            [&](Test::Result& result) {
               auto rl = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               result.test_is_true("ingest client hello", rl->copy_data(client_hello_record));

               auto read = rl->next_record();
               result.require("received something", std::holds_alternative<TLS::Record_Content>(read));
               auto record = std::get<TLS::Record_Content>(read);

               result.test_enum_eq("received handshake", record.type, TLS::Record_Type::Handshake);
               result.test_u64_eq("sequence_number is 0", record.sequence_number.value(), 0);
               result.test_enum_eq("received handshake", record.type, TLS::Record_Type::Handshake);
               result.test_bin_eq("received handshake message",
                                  record.payload,
                                  std::span{client_hello_record}.subspan(Botan::TLS::Size_Limits::DTLS_HEADER_SIZE));

               result.test_is_true("no more records", std::holds_alternative<TLS::BytesNeeded>(rl->next_record()));
            }),

      CHECK("Reading records partially fails",
            [&](Test::Result& result) {
               auto rl = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               // Not enough to read record header (13 bytes)
               const auto r_1 = rl->copy_data(std::span{client_hello_record}.first(10));
               result.test_is_false("ingest returns false", r_1);

               auto nr_1 = rl->next_record();
               const auto* n_1 = std::get_if<Botan::TLS::BytesNeeded>(&nr_1);
               result.test_not_null("bytes needed", n_1);
               result.test_sz_eq("bytes needed", *n_1, 0);

               // Full header provided, still just a partial datagram
               const auto r_2 = rl->copy_data(std::span{client_hello_record}.first(13));
               result.test_is_false("ingest returns false", r_2);

               auto nr_2 = rl->next_record();
               const auto* n_2 = std::get_if<Botan::TLS::BytesNeeded>(&nr_2);
               result.test_not_null("bytes needed", n_2);
               result.test_sz_eq("bytes needed", *n_2, 0);
            }),

      CHECK("legacy_record_version",
            [&](Test::Result& result) {
               auto bad_record = client_hello_record;
               bad_record[1] = 0x03;  // Invalid version
               bad_record[2] = 0x03;
               auto rl = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               result.test_is_false("ingest bad record", rl->copy_data(bad_record));

               result.test_sz_eq("No records", std::get<Botan::TLS::BytesNeeded>(rl->next_record()), 0);

               auto dtls10_record = client_hello_record;
               dtls10_record[1] = 0xFE;  // Only valid for initial ClientHello
               dtls10_record[2] = 0xFF;
               auto rl2 = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               result.test_is_true("ingest dtls10 record", rl2->copy_data(dtls10_record));
               auto record = std::get<TLS::Record_Content>(rl2->next_record());
               result.test_enum_eq("received handshake", record.type, TLS::Record_Type::Handshake);

               rl->disable_receiving_compat_mode();
               result.test_is_false("ingest dtls10 record fails", rl->copy_data(dtls10_record));
               result.test_sz_eq("No records", std::get<Botan::TLS::BytesNeeded>(rl->next_record()), 0);
            }),

      CHECK("unprotected ChangeCipherSpec record is rejected",
            [&](Test::Result& result) {
               const auto ccs_record = Botan::hex_decode("14 FE FD 00 00 00 00 00 00 00 00 00 01 01");
               auto rl = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               result.test_is_false("ingest CCS record", rl->copy_data(ccs_record));
               result.test_sz_eq("No records", std::get<Botan::TLS::BytesNeeded>(rl->next_record()), 0);
            }),

      CHECK("basic round-trip",
            [&](Test::Result& result) {
               // Exists to test record layer writing
               auto rl_out = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);
               auto rl_in = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               const std::array<std::vector<uint8_t>, 2> payloads = {Botan::hex_decode("deadbeef"),
                                                                     Botan::hex_decode("beefdead")};
               for(auto i = 0; i < 2; i++) {
                  // Two round-trips to test sequence_number increment
                  auto records = rl_out->prepare_records(TLS::Record_Type::Handshake, payloads[i]);
                  result.require("produced one record", records.size() == 1);

                  rl_in->copy_data(records.front());
                  auto record = std::get<TLS::Record_Content>(rl_in->next_record());

                  // Test that the created record can be read
                  result.test_enum_eq("type is Handshake", record.type, TLS::Record_Type::Handshake);
                  result.test_u64_eq("sequence_number is right", record.sequence_number.value(), i);
                  result.test_bin_eq("payload matches", record.payload, payloads[i]);
               }
            }),

      CHECK("duplicated and too-old records are rejected",
            [&](Test::Result& result) {
               auto rl_out = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);
               auto rl_in = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               const auto payload = Botan::hex_decode("deadbeef");

               const auto first_record = rl_out->prepare_records(TLS::Record_Type::Handshake, payload);
               result.require("produced one record", first_record.size() == 1);

               result.require("ingest first record", rl_in->copy_data(first_record.front()));
               result.test_is_true("first record is delivered",
                                   std::holds_alternative<TLS::Record_Content>(rl_in->next_record()));

               // Receiving the very same record again must not deliver it twice
               result.test_is_true("ingest duplicate record", rl_in->copy_data(first_record.front()));
               result.test_is_true("duplicate record is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in->next_record()));

               // Advance the replay window beyond the first record's sequence number
               for(uint64_t i = 0; i < TLS::Replay_Window_13::window_size; ++i) {
                  const auto records = rl_out->prepare_records(TLS::Record_Type::Handshake, payload);
                  result.require("produced one record", records.size() == 1);
                  result.require("ingest record", rl_in->copy_data(records.front()));
                  result.require("record is delivered",
                                 std::holds_alternative<TLS::Record_Content>(rl_in->next_record()));
               }

               // The first record's sequence number fell off the left edge of the window
               result.test_is_true("ingest too-old record", rl_in->copy_data(first_record.front()));
               result.test_is_true("too-old record is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in->next_record()));

               // The record layer is still functional afterwards
               const auto fresh_record = rl_out->prepare_records(TLS::Record_Type::Handshake, payload);
               result.require("produced one record", fresh_record.size() == 1);
               result.require("ingest fresh record", rl_in->copy_data(fresh_record.front()));
               auto read = rl_in->next_record();
               result.require("fresh record is delivered", std::holds_alternative<TLS::Record_Content>(read));
               result.test_bin_eq("payload matches", std::get<TLS::Record_Content>(read).payload, payload);
            }),
   };
}

struct DTLSRecordVector {
      std::vector<uint8_t> wire;
      std::vector<uint8_t> payload;
      TLS::Record_Type type;
      uint16_t epoch;
      uint64_t seq_no;
      TLS::Connection_Side writer;
};

class Mocked_Secret_Logger : public Botan::TLS::Secret_Logger {
   public:
      void maybe_log_secret(std::string_view /*label*/, std::span<const uint8_t> /*secret*/) const override {}
};

std::unique_ptr<TLS::Cipher_State> make_cipher_state(TLS::Connection_Side side) {
   const auto cipher = TLS::Ciphersuite::from_name("AES_128_GCM_SHA256").value();
   const Mocked_Secret_Logger logger;
   const std::vector<uint8_t> transcript_hash(32, 0x00);
   return TLS::Cipher_State::init_with_server_hello(
      side, Botan::secure_vector<uint8_t>(32, 0x00), cipher, transcript_hash, logger, TLS::TLS_Flavor::DTLS);
}

std::vector<Test::Result> protected_records() {
   const Mocked_Secret_Logger logger;

   const std::vector<uint8_t> transcript_hash(32, 0x00);

   auto policy = create_policy();

   return {
      CHECK("basic round-trip",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               // Exists to test record layer writing
               auto rl_out = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);
               auto rl_in = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               const std::array handshake_payloads = {
                  TLS::MarshalledHandshakeMessageFragment(Botan::hex_decode("deadbeef")),
                  TLS::MarshalledHandshakeMessageFragment(Botan::hex_decode("beefdead")),
               };

               // Two round trips without record protection to test sequence_number increment
               const auto records = rl_out->prepare_records(std::vector{handshake_payloads[0], handshake_payloads[1]});
               result.require("produced two records", records.size() == 2);

               for(size_t i = 0; i < records.size(); ++i) {
                  result.require("ingestion is successful", rl_in->copy_data(records[i]));
                  auto received = std::get<TLS::Record_Content>(rl_in->next_record());
                  result.test_bin_eq("received record matches payload", received.payload, handshake_payloads[i]);
                  result.test_enum_eq("record type", received.type, TLS::Record_Type::Handshake);
                  result.test_u64_eq(
                     "record sequence_number", received.sequence_number.value(), static_cast<uint64_t>(i));
               }

               const auto to_be_protected_payload = Botan::hex_decode("efbeadde");

               const auto records2 =
                  rl_out->prepare_records(TLS::Record_Type::ApplicationData, to_be_protected_payload, cs_client.get());
               result.require("produced one record", records2.size() == 1);

               const auto& record = records2.front();
               result.test_u8_eq("epoch encoded as 001xxxEE", record[0] & 0xE3, 0x22);

               result.require("ingestion is successful", rl_in->copy_data(record));
               auto deprotected = std::get<TLS::Record_Content>(rl_in->next_record(cs_server.get()));
               result.test_bin_eq("deprotected record matches payload", deprotected.payload, to_be_protected_payload);
               result.test_enum_eq("record type", deprotected.type, TLS::Record_Type::ApplicationData);
               result.test_u64_eq("record sequence_number", deprotected.sequence_number.value(), uint64_t{0});
            }),

      CHECK("write protected record",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto rl_client = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);

               const auto payload = TLS::MarshalledHandshakeMessageFragment(Botan::hex_decode("68656c6c6f2064746c73"));
               auto records = rl_client->prepare_records(std::vector{payload}, cs_client.get());

               result.require("produced one record", records.size() == 1);
               result.test_bin_eq("KAT output matches",
                                  records.front(),
                                  "2e 76 cf 00 1b 9a c7 72 ae 54 cb f8 cc 7b 09 72"
                                  "9d 4a 6f 78 89 c9 3b ff 4e 62 a5 3f 4f 34 c4 fb");
            }),

      CHECK("read protected record",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               auto rl_server = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               const auto wire = Botan::hex_decode(
                  "2e 76 cf 00 1b 9a c7 72 ae 54 cb f8 cc 7b 09 72"
                  "9d 4a 6f 78 89 c9 3b ff 4e 62 a5 3f 4f 34 c4 fb");
               result.require("parsing success", rl_server->copy_data(wire));

               auto records = rl_server->next_record(cs_server.get());
               result.require("produced a record", std::holds_alternative<TLS::Record_Content>(records));

               const auto& record = std::get<TLS::Record_Content>(records);
               result.test_bin_eq("payload matches", record.payload, "68656c6c6f2064746c73");
               result.test_enum_eq("type is Handshake", record.type, TLS::Record_Type::Handshake);
            }),

      CHECK("read multiple protected records from one datagram",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Client);
               auto rl_server = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               const auto wire = Botan::hex_decode(
                  "2e c3 3e 00 1d bd 0c 9c 21 b1 ca fb e9 98 81 5a"
                  "3e b8 2c b9 d1 1f e8 07 b3 b3 34 7d 99 3a 05 f5"
                  "09 e7 2e 98 f7 00 1c 28 c2 e0 1e e6 08 64 58 94"
                  "c6 26 51 8a 7f 9a b6 e1 bb 1f d0 7d 27 dc bc ee"
                  "80 af 3f");
               result.require("parsing success", rl_server->copy_data(wire));

               auto record1 = rl_server->next_record(cs_server.get());
               result.require("produced a record", std::holds_alternative<TLS::Record_Content>(record1));

               const auto& r1 = std::get<TLS::Record_Content>(record1);
               result.test_bin_eq("payload matches", r1.payload, "7365727665722068656c6c6f");
               result.test_enum_eq("type is Handshake", r1.type, TLS::Record_Type::Handshake);

               auto record2 = rl_server->next_record(cs_server.get());
               result.require("produced another record", std::holds_alternative<TLS::Record_Content>(record2));

               const auto& r2 = std::get<TLS::Record_Content>(record2);
               result.test_bin_eq("payload matches", r2.payload, "617070207061796c6f6164");
               result.test_enum_eq("type is Handshake", r2.type, TLS::Record_Type::ApplicationData);

               result.test_is_true("no more records",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_server->next_record(cs_server.get())));
            }),

      CHECK("tampered ciphertext error propagates",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               auto rl_server = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               auto wire = Botan::hex_decode(
                  "2e 76 cf 00 1b 9a c7 72 ae 54 cb f8 cc 7b 09 72"
                  "9d 4a 6f 78 89 c9 3b ff 4e 62 a5 3f 4f 34 c4 fb");
               wire.back() ^= 0x40;  // flip a bit in the last ciphertext byte

               result.test_is_true("datagram is accepted", rl_server->copy_data(wire));
               result.test_sz_eq(
                  "No records", std::get<Botan::TLS::BytesNeeded>(rl_server->next_record(cs_server.get())), 0);
            }),

      CHECK("empty ApplicationData is permitted, other empty types are not",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               auto rl_out = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);

               const std::vector<uint8_t> empty;
               const auto records = rl_out->prepare_records(TLS::Record_Type::ApplicationData, empty, cs_client.get());
               result.require("produced records", !records.empty());
               result.test_sz_gt("produced wire bytes", records.front().size(), 0);

               auto rl_in = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               result.require("ingestion is successful", rl_in->copy_data(records.front()));
               auto read = rl_in->next_record(cs_server.get());
               result.require("expect getting a record", std::holds_alternative<TLS::Record_Content>(read));
               auto record = std::get<TLS::Record_Content>(read);
               result.test_enum_eq("type is ApplicationData", record.type, TLS::Record_Type::ApplicationData);
               result.test_is_true("fragment is empty", record.payload.empty());

               // Empty Handshake message must be rejected
               auto rl_out2 = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);
               result.test_throws("empty Handshake is rejected", [&] {
                  rl_out2->prepare_records(std::vector{TLS::MarshalledHandshakeMessageFragment()}, cs_client.get());
               });

               auto rl_in2 = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
            }),

      CHECK("minimum record size is respected",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               const size_t minimum_record_size = 1024;

               auto policy_with_padding = create_policy(minimum_record_size);
               auto rl_out =
                  TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy_with_padding);

               const std::vector<uint8_t> payload(1, 0x42);
               auto records = rl_out->prepare_records(TLS::Record_Type::ApplicationData, payload, cs_client.get());
               result.require("produced one record", records.size() == 1);

               // The lower bound does not include the unified record header
               // which has a variable length.
               const size_t expected_size_lower_bound = cs_client->encrypt_output_length(minimum_record_size);
               result.test_sz_gte("produced wire bytes", records.front().size(), expected_size_lower_bound);

               // decryption
               auto rl_in =
                  TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy_with_padding);
               result.require("ingestion is successful", rl_in->copy_data(records.front()));
               auto read = rl_in->next_record(cs_server.get());
               result.require("expect getting a record", std::holds_alternative<TLS::Record_Content>(read));
               auto record = std::get<TLS::Record_Content>(read);
               result.test_enum_eq("type is ApplicationData", record.type, TLS::Record_Type::ApplicationData);
               result.test_bin_eq("payload matches", record.payload, payload);
            }),

      CHECK("protected ChangeCipherSpec (inner type) is rejected",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               // Some protected record whose DTLSInnerPlaintext.type == 0x14 (CCS).
               const auto wire = Botan::hex_decode("2E86210012F3B637745B63096B1FE706BAD3EE73FF5D73");

               auto rl = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               result.test_is_true("ingest doesn't reject protected datagram", rl->copy_data(wire));
               result.test_throws<TLS::TLS_Exception>("No records",
                                                      "Deprotected DTLS record had unexpected content type: 20",
                                                      [&] { rl->next_record(cs_server.get()); });
            }),

      CHECK("unprotected and protected records in a single datagram",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               auto rl_in = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               const std::array<std::vector<uint8_t>, 2> payloads = {
                  Botan::hex_decode("deadbeef"),
                  Botan::hex_decode("beefdead"),
               };

               // A single datagram that contains an unprotected Handshake
               // record followed by a protected ApplicationData record.
               const auto wire = Botan::hex_decode(
                  "16FEFD00000000000000000004DEADBEEF2E2EF500154C4DC06F2C933E076CF8167DF3B146D408252BF881");

               // This simulates the situation where a datagram contains both
               // unprotected and protected records. The record layer should be
               // able to read both sequentially.
               //
               // Such a situation can occur in DTLS 1.3 for the first server
               // flight, where the server sends an unprotected ServerHello
               // followed by a protected EncryptedExtensions record...
               result.require("reading hybrid datagram", rl_in->copy_data(wire));
               auto unprotected = rl_in->next_record(nullptr);
               result.test_is_true("expect getting a record", std::holds_alternative<TLS::Record_Content>(unprotected));
               auto record1 = std::get<TLS::Record_Content>(unprotected);
               result.test_enum_eq("type is Handshake", record1.type, TLS::Record_Type::Handshake);
               result.test_bin_eq("payload matches", record1.payload, payloads[0]);

               auto was_protected = rl_in->next_record(cs_server.get());
               result.test_is_true("expect getting a record",
                                   std::holds_alternative<TLS::Record_Content>(was_protected));
               auto record2 = std::get<TLS::Record_Content>(was_protected);
               result.test_enum_eq("type is ApplicationData", record2.type, TLS::Record_Type::ApplicationData);
               result.test_bin_eq("payload matches", record2.payload, payloads[1]);

               result.test_is_true("no more records",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in->next_record(cs_server.get())));
            }),

      CHECK("duplicated and too-old protected records are rejected",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               auto rl_out = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);
               auto rl_in = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

               const auto payload = Botan::hex_decode("deadbeef");

               const auto first_record =
                  rl_out->prepare_records(TLS::Record_Type::ApplicationData, payload, cs_client.get());
               result.require("produced one record", first_record.size() == 1);

               result.require("ingest first record", rl_in->copy_data(first_record.front()));
               result.test_is_true("first record is delivered",
                                   std::holds_alternative<TLS::Record_Content>(rl_in->next_record(cs_server.get())));

               // Receiving the very same record again must not deliver it twice.
               // The duplicate deprotects successfully but is then rejected
               // by the replay window (RFC 9147 Section 4.5.1).
               result.test_is_true("ingest duplicate record", rl_in->copy_data(first_record.front()));
               result.test_is_true("duplicate record is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in->next_record(cs_server.get())));

               // Advance the replay window beyond the first record's sequence number
               for(uint64_t i = 0; i < TLS::Replay_Window_13::window_size; ++i) {
                  const auto records =
                     rl_out->prepare_records(TLS::Record_Type::ApplicationData, payload, cs_client.get());
                  result.require("produced one record", records.size() == 1);
                  result.require("ingest record", rl_in->copy_data(records.front()));
                  result.require("record is delivered",
                                 std::holds_alternative<TLS::Record_Content>(rl_in->next_record(cs_server.get())));
               }

               // The first record's sequence number fell off the left edge of the window
               result.test_is_true("ingest too-old record", rl_in->copy_data(first_record.front()));
               result.test_is_true("too-old record is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in->next_record(cs_server.get())));

               // The record layer is still functional afterwards
               const auto fresh_record =
                  rl_out->prepare_records(TLS::Record_Type::ApplicationData, payload, cs_client.get());
               result.require("produced one record", fresh_record.size() == 1);
               result.require("ingest fresh record", rl_in->copy_data(fresh_record.front()));
               auto read = rl_in->next_record(cs_server.get());
               result.require("fresh record is delivered", std::holds_alternative<TLS::Record_Content>(read));
               result.test_bin_eq("payload matches", std::get<TLS::Record_Content>(read).payload, payload);
            }),

      CHECK("round-trip with all relevant cipher suites",
            [&](Test::Result& result) {
               auto go = [&](std::string_view suite) {
                  const auto ciphersuite = TLS::Ciphersuite::from_name(suite).value();

                  auto suite_cs_client =
                     TLS::Cipher_State::init_with_server_hello(TLS::Connection_Side::Client,
                                                               Botan::secure_vector<uint8_t>(32, 0x00),
                                                               ciphersuite,
                                                               transcript_hash,
                                                               logger,
                                                               TLS::TLS_Flavor::DTLS);
                  auto suite_cs_server = TLS::Cipher_State::init_with_server_hello(
                     TLS::Connection_Side::Server,
                     Botan::secure_vector<uint8_t>(32, 0x00),  // shared_secret = 32 zero bytes
                     ciphersuite,
                     transcript_hash,
                     logger,
                     TLS::TLS_Flavor::DTLS);

                  auto rl_out = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);
                  auto rl_in = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);

                  // Short payload to make sure that certain cipher suites properly
                  // perform their implicit padding (See RFC 9147 4.2.3).
                  const auto payload = std::array<uint8_t, 2>{0x01, 0x02};
                  auto records =
                     rl_out->prepare_records(TLS::Record_Type::ApplicationData, payload, suite_cs_client.get());
                  BOTAN_STATE_CHECK(records.size() == 1);
                  BOTAN_STATE_CHECK(records.front().size() >= 16);  // minimum record size for all suites

                  const bool read_success = rl_in->copy_data(records.front());
                  BOTAN_STATE_CHECK(read_success);

                  const auto out_record = rl_in->next_record(suite_cs_server.get());
                  BOTAN_STATE_CHECK(std::holds_alternative<TLS::Record_Content>(out_record));

                  BOTAN_ASSERT_NOMSG(std::get<TLS::Record_Content>(out_record).payload.size() == payload.size());
                  BOTAN_ASSERT_NOMSG(std::get<TLS::Record_Content>(out_record).payload[0] == payload[0]);
                  BOTAN_ASSERT_NOMSG(std::get<TLS::Record_Content>(out_record).payload[1] == payload[1]);
               };

               const auto suites = std::array{
                  "AES_128_GCM_SHA256",
                  "AES_256_GCM_SHA384",
   #if defined(BOTAN_HAS_AEAD_CCM)
                  "AES_128_CCM_SHA256",
                  "AES_128_CCM_8_SHA256",
   #endif
   #if defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)
                  "CHACHA20_POLY1305_SHA256",
   #endif
               };

               for(const auto& suite : suites) {
                  try {
                     go(suite);
                     result.test_success("round-trip with " + std::string(suite) + " succeeded");
                  } catch(const std::exception& e) {
                     result.test_failure("round-trip with " + std::string(suite) + " failed: " + e.what());
                  }
               }
            }),

   };
}

std::vector<Test::Result> retransmission() {
   auto policy = create_policy();

   // Reads epoch and sequence number off a DTLSPlaintext record header:
   // type(1) || legacy_version(2) || epoch(2) || sequence_number(6) || length(2)
   auto plaintext_record_number = [](const TLS::MarshalledRecord& record) -> std::pair<uint64_t, uint64_t> {
      uint64_t epoch = (static_cast<uint64_t>(record[3]) << 8) | record[4];
      uint64_t seqno = 0;
      for(size_t i = 0; i < 6; ++i) {
         seqno = (seqno << 8) | record[5 + i];
      }
      return {epoch, seqno};
   };

   const auto payload1 = Botan::hex_decode("deadbeef");
   const auto payload2 = Botan::hex_decode("beefdead");
   const auto payload3 = Botan::hex_decode("beaddeef");

   return {
      CHECK(
         "unacknowledged outgoing records are retransmitted until the flight state progresses",
         [&](Test::Result& result) {
            auto rl = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);
            auto* dtls_rl = dynamic_cast<TLS::DTLS_Record_Layer*>(rl.get());
            result.require("record layer is DTLS", dtls_rl != nullptr);

            // a flight of two unprotected handshake records (epoch 0)
            const auto original = rl->prepare_records(std::vector{TLS::MarshalledHandshakeMessageFragment(payload1),
                                                                  TLS::MarshalledHandshakeMessageFragment(payload2)},
                                                      nullptr);
            result.require("two records created", original.size() == 2);

            const auto retransmission = dtls_rl->prepare_unacknowledged_records(nullptr);
            result.require("two records retransmitted", retransmission.size() == original.size());

            for(size_t i = 0; i < retransmission.size(); ++i) {
               const auto retransmitted_rn = plaintext_record_number(retransmission[i]);

               result.test_u64_eq("retransmission stays in epoch 0", retransmitted_rn.first, 0);
               result.test_u64_eq(
                  "retransmission uses a fresh record sequence number", retransmitted_rn.second, original.size() + i);

               // the record payload (and hence the handshake message with
               // its message_seq) is reused unchanged
               result.test_bin_eq("retransmitted payload is identical",
                                  std::span{retransmission[i]}.subspan(TLS::DTLS_HEADER_SIZE),
                                  std::span{original[i]}.subspan(TLS::DTLS_HEADER_SIZE));
            }

            dtls_rl->clear_resend_buffer();
            result.test_is_true("nothing left to retransmit", dtls_rl->prepare_unacknowledged_records(nullptr).empty());
         }),

      CHECK("retransmission of a mixed flight with protected records",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);

               auto rl_server = TLS::Record_Layer::create(TLS::Connection_Side::Server, TLS::TLS_Flavor::DTLS, policy);
               auto rl_client = TLS::Record_Layer::create(TLS::Connection_Side::Client, TLS::TLS_Flavor::DTLS, policy);

               auto* dtls_rl_server = dynamic_cast<TLS::DTLS_Record_Layer*>(rl_server.get());
               result.require("record layer is DTLS", dtls_rl_server != nullptr);

               // Simulate a server's first flight, i.e., use an unprotected
               // record (ServerHello) followed by protected records (e.g.
               // EncryptedExtensions, Finished).
               const auto unprotected =
                  rl_server->prepare_records(std::vector{TLS::MarshalledHandshakeMessageFragment(payload1)}, nullptr);
               const auto protected_records =
                  rl_server->prepare_records(std::vector{TLS::MarshalledHandshakeMessageFragment(payload2),
                                                         TLS::MarshalledHandshakeMessageFragment(payload3)},
                                             cs_server.get());
               result.require("three records prepared", unprotected.size() == 1 && protected_records.size() == 2);

               // The flight is lost and the server retransmits everything that
               // was not acknowledged.
               const auto retransmission = dtls_rl_server->prepare_unacknowledged_records(cs_server.get());
               result.require("three records retransmitted", retransmission.size() == 3);

               // The unprotected record is retransmitted in epoch 0 under a
               // fresh record sequence number (RFC 9147 Section 5.2, see the
               // test case above).
               const auto rn = plaintext_record_number(retransmission[0]);
               result.test_u64_eq("retransmission stays in epoch 0", rn.first, 0);
               result.test_u64_eq("fresh record sequence number", rn.second, 1);

               // The protected records are encrypted afresh, i.e. their
               // ciphertexts differ from the originals'.
               result.test_is_true("fresh encryption of first protected record",
                                   retransmission[1] != protected_records[0]);
               result.test_is_true("fresh encryption of second protected record",
                                   retransmission[2] != protected_records[1]);

               // The peer can read all retransmitted records.
               const auto expected_payloads = std::array{payload1, payload2, payload3};
               const auto expected_epochs = std::array<uint64_t, 3>{0, 2, 2};
               const auto expected_seqnos = std::array<uint64_t, 3>{1, 2, 3};
               for(size_t i = 0; i < retransmission.size(); ++i) {
                  result.require("ingestion is successful", rl_client->copy_data(retransmission[i]));
                  auto read = rl_client->next_record(cs_client.get());
                  result.require("record is delivered", std::holds_alternative<TLS::Record_Content>(read));
                  const auto& content = std::get<TLS::Record_Content>(read);
                  result.test_bin_eq("payload round-trips", content.payload, expected_payloads[i]);
                  result.test_u64_eq("epoch", static_cast<uint64_t>(content.epoch.value()), expected_epochs[i]);
                  result.test_u64_eq(
                     "fresh record sequence number", content.sequence_number.value(), expected_seqnos[i]);
               }

               dtls_rl_server->clear_resend_buffer();
               result.test_is_true("nothing left to retransmit",
                                   dtls_rl_server->prepare_unacknowledged_records(nullptr).empty());
            }),
   };
}

std::vector<Test::Result> unified_header() {
   return {
      CHECK("empty input is rejected",
            [&](Test::Result& result) {
               const auto bytes = std::array<uint8_t, 0>{};
               result.test_throws("empty input is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt); });
            }),

      CHECK("input with malformed header byte is rejected",
            [&](Test::Result& result) {
               // epoch_bits=0, no CID, short seq_no, no length
               // prefix is not 0b001xxxxx, so it is malformed
               constexpr uint8_t malformed_header = 0b11100000;
               const auto bytes = std::array<uint8_t, 2>{malformed_header, 0x00 /* seqno */};
               result.test_throws("malformed header is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt); });
            }),

      CHECK("input without sequence number is rejected",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, no length
               constexpr uint8_t minimal_header = 0b00100010;
               const auto bytes = std::array<uint8_t, 1>{minimal_header};
               result.test_throws("missing seqno is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt); });
            }),

      CHECK("input with too short sequence number is rejected",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, long seq_no, no length
               constexpr uint8_t minimal_header_long_seqno = 0b00101010;
               const auto bytes = std::array<uint8_t, 2>{minimal_header_long_seqno, 0x00};
               result.test_throws("too short seqno is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt); });
            }),

      CHECK("minimal unified header",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, no length
               constexpr uint8_t minimal_header = 0b00100010;
               const auto bytes = std::array<uint8_t, 2>{minimal_header, 0b00101010};

               const auto header = TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt);
               result.test_u8_eq("epoch bits", header.epoch_bits, 2);
               result.test_opt_is_null("no CID", header.connection_id);
               result.test_is_true("short seq no", std::holds_alternative<uint8_t>(header.sequence_number));
               result.test_u8_eq("seq_no", std::get<uint8_t>(header.sequence_number), 42);
               result.test_opt_is_null("no payload length", header.length);
               result.test_sz_eq("header length", header.serialized_byte_length(), 2);
            }),

      CHECK("input with missing payload length is rejected",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, with length
               constexpr uint8_t minimal_header_with_length = 0b00100110;

               const auto bytes = std::array<uint8_t, 2>{minimal_header_with_length, 0x00 /* seqno */};
               result.test_throws("missing payload length is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt); });
            }),

      CHECK("input with truncated payload length is rejected",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, with length
               constexpr uint8_t minimal_header_with_length = 0b00100110;

               const auto bytes = std::array<uint8_t, 3>{
                  minimal_header_with_length,
                  0x00 /* seqno */,
                  0x01 /* partial payload length */,
               };
               result.test_throws("partial payload length is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt); });
            }),

      CHECK("unified header with payload length",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, with length
               constexpr uint8_t minimal_header_with_length = 0b00100110;

               const auto bytes = std::array<uint8_t, 4>{
                  minimal_header_with_length,
                  0x00 /* seqno */,
                  0x00,
                  0x10 /* payload length */,
               };

               const auto header = TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt);
               result.test_u8_eq("epoch bits", header.epoch_bits, 2);
               result.test_opt_is_null("no CID", header.connection_id);
               result.test_is_true("short seq no", std::holds_alternative<uint8_t>(header.sequence_number));
               result.test_u8_eq("seq_no", std::get<uint8_t>(header.sequence_number), 0);
               result.test_opt_not_null("has payload length", header.length);
               result.test_u16_eq("payload length", *header.length, 16);
               result.test_sz_eq("header length", header.serialized_byte_length(), 4);
            }),

      CHECK("input with advertised but missing connection ID is rejected",
            [&](Test::Result& result) {
               const size_t connection_id_length = 7;

               // epoch_bits=2, with CID, short seq_no, no length
               constexpr uint8_t minimal_header_with_cid = 0b00110010;

               const auto bytes = std::array<uint8_t, 2>{minimal_header_with_cid, 0x00 /* seqno */};
               result.test_throws("missing connection ID is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, connection_id_length); });
            }),

      CHECK("input with omitted connection ID is rejected",
            [&](Test::Result& result) {
               const size_t connection_id_length = 7;

               // epoch_bits=2, no CID, short seq_no, no length
               constexpr uint8_t minimal_header_without_cid = 0b00100010;

               const auto bytes = std::array<uint8_t, 2>{
                  minimal_header_without_cid, 0x00 /* seqno */
               };

               result.test_throws("omitted connection ID is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, connection_id_length); });
            }),

      CHECK("input with truncated connection ID is rejected",
            [&](Test::Result& result) {
               const size_t connection_id_length = 7;

               // epoch_bits=2, with CID, short seq_no, no length
               constexpr uint8_t minimal_header_with_cid = 0b00110010;

               // clang-format off
               const auto bytes = std::array<uint8_t, 8>{
                  minimal_header_with_cid,
                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // partial connection ID
                  0x00                                // sequence number
               };
               // clang-format on

               result.test_throws("partial connection ID is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, connection_id_length); });
            }),

      CHECK("full unified header",
            [&](Test::Result& result) {
               const size_t connection_id_length = 7;

               // epoch_bits=2, with CID, long seq_no, with length
               constexpr uint8_t full_header = 0b00111110;

               // clang-format off
               const auto bytes = std::array<uint8_t, 12>{
                  full_header,                              // header
                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // connection ID
                  0x00, 0x2A,                               // sequence number
                  0x00, 0x10                                // payload length
               };
               // clang-format on

               const auto header = TLS::UnifiedHeader_DTLS::parse(bytes, connection_id_length);
               result.test_u8_eq("epoch bits", header.epoch_bits, 2);
               result.test_opt_not_null("has CID", header.connection_id);
               result.test_bin_eq("CID matches", *header.connection_id, "01020304050607");
               result.test_is_true("long seq no", std::holds_alternative<uint16_t>(header.sequence_number));
               result.test_u16_eq("seq_no", std::get<uint16_t>(header.sequence_number), 42);
               result.test_opt_not_null("has payload length", header.length);
               result.test_u16_eq("payload length", *header.length, 16);
               result.test_sz_eq("header length", header.serialized_byte_length(), 12);
            }),

      CHECK("unified header with unsolicited CID is rejected",
            [&](Test::Result& result) {
               // clang-format off
               const auto bytes = std::array<uint8_t, 12>{
                  0b00111101,                               // header
                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // connection ID
                  0x00, 0x2A,                               // sequence number
                  0x00, 0x10                                // payload length
               };
               // clang-format on

               result.test_throws("unsolicited CID is rejected",
                                  [&] { TLS::UnifiedHeader_DTLS::parse(bytes, std::nullopt); });
            }),

      CHECK("rendering a minimal unified header",
            [&](Test::Result& result) {
               const auto header = TLS::UnifiedHeader_DTLS{
                  .epoch_bits = 1,
                  .connection_id = std::nullopt,
                  .sequence_number = uint8_t{42},
                  .length = std::nullopt,
               };

               result.test_sz_eq("header length", header.serialized_byte_length(), 2);

               const auto bytes = header.serialize();
               result.test_bin_eq("serialization", bytes, "21 2A");
            }),

      CHECK("rendering a full unified header",
            [&](Test::Result& result) {
               const auto header = TLS::UnifiedHeader_DTLS{
                  .epoch_bits = 2,
                  .connection_id = Botan::TLS::ConnectionID({0x01, 0x02, 0x03, 0x04}),
                  .sequence_number = uint16_t{42},
                  .length = uint16_t{17},
               };

               result.test_sz_eq("header length", header.serialized_byte_length(), 9);

               const auto bytes = header.serialize();
               result.test_bin_eq("serialization", bytes, "3E 01 02 03 04 00 2A 00 11");
            }),

      CHECK("rendering a unified header without a CID",
            [&](Test::Result& result) {
               const auto header = TLS::UnifiedHeader_DTLS{
                  .epoch_bits = 3,
                  .connection_id = std::nullopt,
                  .sequence_number = uint16_t{42},
                  .length = uint16_t{17},
               };

               result.test_sz_eq("header length", header.serialized_byte_length(), 5);

               const auto bytes = header.serialize();
               result.test_bin_eq("serialization", bytes, "2F 00 2A 00 11");
            }),

      CHECK("rendering a unified header without payload length",
            [&](Test::Result& result) {
               const auto header = TLS::UnifiedHeader_DTLS{
                  .epoch_bits = 0,
                  .connection_id = Botan::TLS::ConnectionID({0x01, 0x02, 0x03, 0x04}),
                  .sequence_number = uint8_t{42},
                  .length = std::nullopt,
               };

               result.test_sz_eq("header length", header.serialized_byte_length(), 6);

               const auto bytes = header.serialize();
               result.test_bin_eq("serialization", bytes, "30 01 02 03 04 2A");
            }),

      CHECK("rendering into a too-short buffer is rejected",
            [&](Test::Result& result) {
               const auto header = TLS::UnifiedHeader_DTLS{
                  .epoch_bits = 0,
                  .connection_id = Botan::TLS::ConnectionID({0x01, 0x02, 0x03, 0x04}),
                  .sequence_number = uint8_t{42},
                  .length = std::nullopt,
               };

               std::array<uint8_t, 5> too_short{};
               result.test_sz_lt("buffer is too short", too_short.size(), header.serialized_byte_length());
               result.test_throws("rendering into too-short buffer is rejected",
                                  [&] { header.serialize_to(too_short); });
            }),

      CHECK("UnifiedHeader pre-determine header length",
            [&](Test::Result& result) {
               auto policy = create_policy();

               const size_t r1 = TLS::UnifiedHeader_DTLS::expected_length(*policy, std::nullopt);
               result.test_sz_eq("UnifiedHeader w/o CID (default seqno and length)", r1, 5);

               const size_t r2 = TLS::UnifiedHeader_DTLS::expected_length(*policy, 0);
               result.test_sz_eq("UnifiedHeader w/ empty CID (default seqno and length)", r2, 5);

               const size_t r3 = TLS::UnifiedHeader_DTLS::expected_length(*policy, 4);
               result.test_sz_eq("UnifiedHeader w/ 4 byte CID (default seqno and length)", r3, 9);
            }),
   };
}

std::vector<Test::Result> replay_window() {
   return {
      CHECK("new window accepts sequence number 0",
            [](Test::Result& result) {
               TLS::Replay_Window_13 window;
               result.test_is_true("accepts seqno 0", window.accept(0));
            }),

      CHECK("new window accepts sequence number > 0",
            [](Test::Result& result) {
               TLS::Replay_Window_13 window;
               result.test_is_true("accepts seqno 1", window.accept(1));
            }),

      CHECK("window rejects duplicate sequence number",
            [](Test::Result& result) {
               TLS::Replay_Window_13 window;
               result.test_is_true("accepts seqno 0", window.accept(0));
               result.test_is_false("rejects duplicate seqno 0", window.accept(0));
            }),

      CHECK("window rejects sequence numbers that are too old",
            [](Test::Result& result) {
               TLS::Replay_Window_13 window;
               window.accept(TLS::Replay_Window_13::window_size);
               result.test_is_false("rejects too-old seqno", window.accept(0));
            }),

      CHECK("window slides along when higher sequence numbers are received",
            [](Test::Result& result) {
               TLS::Replay_Window_13 window;
               result.test_is_true("receive 0", window.accept(0));
               result.test_is_true("receive 5", window.accept(5));

               // Shift the window far enough to let 0, 1, and 2 fall off the
               // left side of the window.
               result.test_is_true("receive higher value", window.accept(TLS::Replay_Window_13::window_size + 2));
               result.test_is_false("rejects duplicate 5", window.accept(5));

               result.test_is_false("rejects too-old duplicate 0", window.accept(0));
               result.test_is_false("rejects too-old 1", window.accept(1));
               result.test_is_false("rejects too-old 2", window.accept(2));
               result.test_is_true("receive still-acceptable 3", window.accept(3));
            }),

      CHECK("window slides along for a large jump in sequence numbers",
            [](Test::Result& result) {
               constexpr auto large_seqno = TLS::Replay_Window_13::window_size * 5;

               TLS::Replay_Window_13 window;
               result.test_is_true("receive 0", window.accept(0));
               result.test_is_true("receive a much-later seqno", window.accept(large_seqno));

               result.test_is_false("rejects duplicate of much-later seqno", window.accept(large_seqno));
               result.test_is_false("rejects too-old seqno",
                                    window.accept(large_seqno - TLS::Replay_Window_13::window_size));
               result.test_is_true("receive still-acceptable seqno", window.accept(large_seqno - 1));
            }),

      CHECK("window works close to the maximum sequence number",
            [](Test::Result& result) {
               TLS::Replay_Window_13 window;
               constexpr auto max_seqno = std::numeric_limits<uint64_t>::max();

               result.test_is_true("receive max_seqno - 1", window.accept(max_seqno - 1));
               result.test_is_true("receive max_seqno", window.accept(max_seqno));

               result.test_is_false("rejects duplicate max_seqno - 1", window.accept(max_seqno - 1));
               result.test_is_false("rejects duplicate max_seqno", window.accept(max_seqno));
               result.test_is_false("rejects too-old max_seqno - window_size",
                                    window.accept(max_seqno - TLS::Replay_Window_13::window_size));
            }),

      CHECK("window tracks a completely filled window",
            [](Test::Result& result) {
               TLS::Replay_Window_13 window;

               for(uint64_t i = 0; i < TLS::Replay_Window_13::window_size; ++i) {
                  result.test_is_true("receive " + std::to_string(i), window.accept(i));
               }

               for(uint64_t i = 0; i < TLS::Replay_Window_13::window_size; ++i) {
                  result.test_is_false("rejects replay of " + std::to_string(i), window.accept(i));
               }

               // Slide by one: 0 falls off the left edge, everything else
               // is still tracked as a duplicate.
               result.test_is_true("receive window_size", window.accept(TLS::Replay_Window_13::window_size));
               result.test_is_false("rejects too-old 0", window.accept(0));

               for(uint64_t i = 1; i <= TLS::Replay_Window_13::window_size; ++i) {
                  result.test_is_false("rejects replay of " + std::to_string(i) + " after slide", window.accept(i));
               }
            }),
   };
}

std::vector<Test::Result> sequence_number_reconstruction() {
   // Shorthands for the 8-bit and 16-bit sequence number hints that may
   // appear in the DTLS 1.3 unified header (RFC 9147 Section 4 Figure 3).
   const auto hint8 = [](uint64_t hint) { return TLS::SequenceNumberHint{static_cast<uint8_t>(hint)}; };
   const auto hint16 = [](uint64_t hint) { return TLS::SequenceNumberHint{static_cast<uint16_t>(hint)}; };

   return {
      CHECK("in-order records reconstruct to the next sequence number",
            [&](Test::Result& result) {
               result.test_u64_eq("8-bit hint", TLS::reconstruct_full_sequence_number(5, hint8(6)), 6);
               result.test_u64_eq("16-bit hint", TLS::reconstruct_full_sequence_number(5, hint16(6)), 6);
            }),

      CHECK("the first record in an epoch may have sequence number 0",
            [&](Test::Result& result) {
               result.test_u64_eq("8-bit hint", TLS::reconstruct_full_sequence_number(0, hint8(0)), 0);
               result.test_u64_eq("16-bit hint", TLS::reconstruct_full_sequence_number(0, hint16(0)), 0);
            }),

      CHECK("reordered records reconstruct to sequence numbers in the past",
            [&](Test::Result& result) {
               // Record 266 arrives after 300 was already deprotected
               result.test_u64_eq(
                  "8-bit hint within window", TLS::reconstruct_full_sequence_number(300, hint8(10)), 266);

               // Record 255 arrives after 256 was already deprotected
               result.test_u64_eq(
                  "8-bit hint across window boundary", TLS::reconstruct_full_sequence_number(256, hint8(255)), 255);
               result.test_u64_eq("8-bit hint across window boundary (later)",
                                  TLS::reconstruct_full_sequence_number(512, hint8(255)),
                                  511);

               // Record 65535 arrives after 65536 was already deprotected
               result.test_u64_eq("16-bit hint across window boundary",
                                  TLS::reconstruct_full_sequence_number(65536, hint16(65535)),
                                  65535);
            }),

      CHECK("records after packet loss reconstruct to sequence numbers in the future",
            [&](Test::Result& result) {
               result.test_u64_eq("8-bit hint", TLS::reconstruct_full_sequence_number(0, hint8(42)), 42);
               result.test_u64_eq("16-bit hint", TLS::reconstruct_full_sequence_number(0, hint16(1000)), 1000);
               result.test_u64_eq(
                  "8-bit hint across window boundary", TLS::reconstruct_full_sequence_number(255, hint8(0)), 256);
               result.test_u64_eq(
                  "16-bit hint across window boundary", TLS::reconstruct_full_sequence_number(65535, hint16(0)), 65536);
            }),

      CHECK("at epoch start any hint reconstructs to itself",
            [&](Test::Result& result) {
               // Nothing was deprotected in the epoch, yet, so the closest
               // valid (i.e. non-negative) full sequence number is the hint.
               for(uint64_t hint : {0, 1, 127, 128, 129, 200, 255}) {
                  result.test_u64_eq(
                     "8-bit hint " + std::to_string(hint), TLS::reconstruct_full_sequence_number(0, hint8(hint)), hint);
               }

               for(uint64_t hint : {0, 1, 32767, 32768, 32769, 40000, 65535}) {
                  result.test_u64_eq("16-bit hint " + std::to_string(hint),
                                     TLS::reconstruct_full_sequence_number(0, hint16(hint)),
                                     hint);
               }
            }),

      CHECK(
         "hints in the upper half-window at epoch start do not underflow",
         [&](Test::Result& result) {
            // Regression test: subtracting the window from a candidate
            // smaller than the window would underflow below zero. The
            // closest valid sequence number is the hint itself.
            result.test_u64_eq("8-bit hint, nothing seen", TLS::reconstruct_full_sequence_number(0, hint8(200)), 200);
            result.test_u64_eq("8-bit hint, little seen", TLS::reconstruct_full_sequence_number(100, hint8(255)), 255);
            result.test_u64_eq(
               "16-bit hint, nothing seen", TLS::reconstruct_full_sequence_number(0, hint16(40000)), 40000);
            result.test_u64_eq(
               "16-bit hint, little seen", TLS::reconstruct_full_sequence_number(1000, hint16(65535)), 65535);
         }),

      CHECK(
         "hints at exactly half-window distance resolve to the higher sequence number",
         [&](Test::Result& result) {
            // 272 and 528 are both 128 away from the expected 301 + 99 = 400
            result.test_u64_eq("8-bit tie below expected", TLS::reconstruct_full_sequence_number(399, hint8(16)), 528);

            // 173 and 429 are both 128 away from the expected 301
            result.test_u64_eq("8-bit tie above expected", TLS::reconstruct_full_sequence_number(300, hint8(173)), 429);

            // 7233 and 72769 are both 32768 away from the expected 40001
            result.test_u64_eq(
               "16-bit tie below expected", TLS::reconstruct_full_sequence_number(40000, hint16(7233)), 72769);

            // 37233 and 102769 are both 32768 away from the expected 70001
            result.test_u64_eq(
               "16-bit tie above expected", TLS::reconstruct_full_sequence_number(70000, hint16(37233)), 102769);
         }),

      CHECK("records up to half a window ahead reconstruct to the future",
            [&](Test::Result& result) {
               result.test_u64_eq("8-bit hint, 127 ahead", TLS::reconstruct_full_sequence_number(0, hint8(128)), 128);
               result.test_u64_eq(
                  "16-bit hint, 32767 ahead", TLS::reconstruct_full_sequence_number(0, hint16(32768)), 32768);
            }),

      CHECK("reconstruction preserves the high bits of large sequence numbers",
            [&](Test::Result& result) {
               constexpr uint64_t base32 = uint64_t{1} << 32;
               result.test_u64_eq("8-bit hint, next across boundary",
                                  TLS::reconstruct_full_sequence_number(base32 + 255, hint8(0)),
                                  base32 + 256);
               result.test_u64_eq("8-bit hint, reordered across boundary",
                                  TLS::reconstruct_full_sequence_number(base32 + 256, hint8(255)),
                                  base32 + 255);

               constexpr uint64_t base48 = uint64_t{1} << 48;
               result.test_u64_eq("16-bit hint, next across boundary",
                                  TLS::reconstruct_full_sequence_number(base48 + 65535, hint16(0)),
                                  base48 + 65536);
               result.test_u64_eq("16-bit hint, reordered across boundary",
                                  TLS::reconstruct_full_sequence_number(base48 + 65536, hint16(65535)),
                                  base48 + 65535);
            }),

      CHECK("the hint's bit width determines the reconstruction window",
            [&](Test::Result& result) {
               // The same hint value reconstructs differently depending on
               // whether 8 or 16 bits were transmitted on the wire.
               result.test_u64_eq("8-bit hint", TLS::reconstruct_full_sequence_number(300, hint8(44)), 300);
               result.test_u64_eq("16-bit hint", TLS::reconstruct_full_sequence_number(300, hint16(44)), 44);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "dtls_record_layer_13_clienthello", read_clienthello_record);
BOTAN_REGISTER_TEST_FN("tls", "dtls_record_layer_13_protected", protected_records);
BOTAN_REGISTER_TEST_FN("tls", "dtls_record_layer_13_retransmission", retransmission);
BOTAN_REGISTER_TEST_FN("tls", "dtls_record_layer_13_unified_header", unified_header);
BOTAN_REGISTER_TEST_FN("tls", "dtls_record_layer_13_replay_window", replay_window);
BOTAN_REGISTER_TEST_FN("tls", "dtls_record_layer_13_sequence_number_reconstruction", sequence_number_reconstruction);

}  // namespace Botan_Tests

#endif
