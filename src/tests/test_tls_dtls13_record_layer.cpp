/*
* (C) 2026 Jack Lloyd
* (C) 2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DTLS_13_LOL)

   #include <botan/hex.h>
   #include <botan/tls.h>

   #include <botan/internal/buffer_slicer.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/stl_util.h>
   #include <botan/internal/tls_cipher_state.h>
   #include <botan/internal/tls_record_dtls13.h>
   #include <botan/internal/tls_record_layer_dtls13.h>
   #include <botan/internal/tls_types_13.h>
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

std::unique_ptr<TLS::Cipher_State> make_cipher_state(TLS::Connection_Side side,
                                                     std::string_view suite = "AES_128_GCM_SHA256") {
   const auto cipher = TLS::Ciphersuite::from_name(suite).value();
   return TLS::Cipher_State::init_with_server_hello(
      side, TLS::TLS_Flavor::DTLS, Botan::secure_vector<uint8_t>(32, 0x00), cipher, std::vector<uint8_t>(32, 0x00), {});
}

void advance_to_application_traffic(TLS::Cipher_State& cs) {
   const std::vector<uint8_t> dummy_transcript_hash(32, 0x42);
   cs.advance_with_server_finished(dummy_transcript_hash);
   cs.advance_with_client_finished(dummy_transcript_hash);
}

TLS::PackedHandshakeMessageFragments packed(std::span<const uint8_t> fragment) {
   return TLS::PackedHandshakeMessageFragments(std::vector<uint8_t>(fragment.begin(), fragment.end()));
}

Botan::secure_vector<uint8_t> prepare_record(TLS::DTLS_Record_Layer& rl,
                                             const TLS::Policy& policy,
                                             TLS::Record_Type type,
                                             std::span<const uint8_t> payload,
                                             TLS::Cipher_State* cipher_state = nullptr) {
   Botan::secure_vector<uint8_t> out;
   rl.prepare_record(type, payload, policy, cipher_state, out);
   return out;
}

Botan::secure_vector<uint8_t> prepare_handshake_record(TLS::DTLS_Record_Layer& rl,
                                                       const TLS::Policy& policy,
                                                       std::span<const uint8_t> fragment,
                                                       TLS::Cipher_State* cipher_state = nullptr) {
   Botan::secure_vector<uint8_t> out;
   rl.prepare_handshake_record(packed(fragment), out, policy, cipher_state);
   return out;
}

auto parse_header(std::span<const uint8_t> bytes, std::optional<size_t> cid_length) {
   Botan::BufferSlicer bs(bytes);
   return TLS::UnifiedHeader_DTLS::parse(bs, cid_length);
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
               TLS::DTLS_Record_Layer rl(TLS::Connection_Side::Server);
               result.test_is_true("ingest client hello", rl.copy_data(client_hello_record, false));

               auto read = rl.next_record();
               result.require("received something", !std::holds_alternative<TLS::BytesNeeded>(read));
               auto record = std::get<TLS::Handshake_Record>(read);

               result.test_enum_eq("received handshake", record.type, TLS::Record_Type::Handshake);
               result.test_u64_eq("sequence_number is 0", record.sequence_number.value(), 0);
               result.test_enum_eq("epoch is 0", record.epoch.value(), TLS::EpochNumber::Unprotected);
               result.test_bin_eq("received handshake message",
                                  record.payload,
                                  std::span{client_hello_record}.subspan(Botan::TLS::Size_Limits::DTLS_HEADER_SIZE));

               result.test_is_true("no more records", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
            }),

      CHECK("Reading records partially fails",
            [&](Test::Result& result) {
               // DTLS records must not span datagrams, but copy_data
               // in DTLS assumes to be called on a full datagram.
               TLS::DTLS_Record_Layer rl(TLS::Connection_Side::Server);

               // Not enough to read record header (13 bytes)
               result.test_is_false("partial header is discarded",
                                    rl.copy_data(std::span{client_hello_record}.first(10), false));
               result.test_is_true("nothing to read", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));

               // Full header provided, still just a partial datagram
               result.test_is_false("partial payload is discarded",
                                    rl.copy_data(std::span{client_hello_record}.first(13), false));
               result.test_is_true("nothing to read", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));

               // Syntactically invalid datagrams are silently discarded even
               // when a cryptographic association exists (RFC 9147 4.5.2).
               result.test_is_false("partial datagram is discarded with association",
                                    rl.copy_data(std::span{client_hello_record}.first(13), true));
               result.test_is_true("nothing to read", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));
            }),

      CHECK("legacy_record_version",
            [&](Test::Result& result) {
               // Semantically invalid datagrams abort the connection attempt
               // (throw) as long as no cryptographic association exists, but
               // are silently discarded once one was established
               auto bad_record = client_hello_record;
               bad_record[1] = 0x03;  // Invalid version
               bad_record[2] = 0x03;

               TLS::DTLS_Record_Layer rl(TLS::Connection_Side::Server);
               result.test_throws<TLS::TLS_Exception>("bad record version throws without association",
                                                      [&] { rl.copy_data(bad_record, false); });
               result.test_is_false("bad record version is discarded with association", rl.copy_data(bad_record, true));
               result.test_is_true("nothing to read", std::holds_alternative<TLS::BytesNeeded>(rl.next_record()));

               auto dtls10_record = client_hello_record;
               dtls10_record[1] = 0xFE;  // Only valid for initial ClientHello
               dtls10_record[2] = 0xFF;
               TLS::DTLS_Record_Layer rl2(TLS::Connection_Side::Server);
               result.test_is_true("ingest dtls10 record", rl2.copy_data(dtls10_record, false));
               auto record = std::get<TLS::Handshake_Record>(rl2.next_record());
               result.test_enum_eq("received handshake", record.type, TLS::Record_Type::Handshake);

               rl2.disable_receiving_compat_mode();
               result.test_throws<TLS::TLS_Exception>("dtls10 record throws in strict mode",
                                                      [&] { rl2.copy_data(dtls10_record, false); });
            }),

      CHECK("epoch 0 round-trip with duplicate rejection",
            [&](Test::Result& result) {
               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);
               const std::array<std::vector<uint8_t>, 2> payloads = {Botan::hex_decode("deadbeef"),
                                                                     Botan::hex_decode("beefdead")};

               for(uint64_t i = 0; i < payloads.size(); i++) {
                  // Two round-trips to test sequence_number increment
                  const auto wire = prepare_handshake_record(rl_out, *policy, payloads[i]);
                  result.test_u64_eq(
                     "write sequence number incremented", rl_out.epoch0_sequence_numbers()->write, i + 1);

                  result.require("ingestion is successful", rl_in.copy_data(wire, false));
                  auto record = std::get<TLS::Handshake_Record>(rl_in.next_record());

                  // Test that the created record can be read
                  result.test_enum_eq("type is Handshake", record.type, TLS::Record_Type::Handshake);
                  result.test_u64_eq("sequence_number is right", record.sequence_number.value(), i);
                  result.test_enum_eq("epoch is 0", record.epoch.value(), TLS::EpochNumber::Unprotected);
                  result.test_bin_eq("payload matches", record.payload, payloads[i]);

                  // Receiving the very same record again must not deliver it twice
                  result.test_is_true("ingest duplicate record", rl_in.copy_data(wire, false));
                  result.test_is_true("duplicate record is discarded",
                                      std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record()));
               }
            }),

      CHECK(
         "records from a partially invalid datagram are dropped entirely",
         [&](Test::Result& result) {
            // Records are committed to the read buffer only once the
            // entire datagram was parsed successfully (RFC 9147 Section
            // 4.3: "Records MUST NOT span datagrams").
            TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
            TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

            const auto valid_record = prepare_handshake_record(rl_out, *policy, Botan::hex_decode("deadbeef"));

            // A truncated record header trails the valid record, rendering
            // the entire datagram syntactically invalid.
            const auto datagram = Botan::concat<std::vector<uint8_t>>(valid_record, std::array<uint8_t, 2>{0x16, 0xFE});
            result.test_is_false("partially invalid datagram is discarded", rl_in.copy_data(datagram, false));
            result.test_is_true("valid record was not committed either",
                                std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record()));
         }),
   };
}

std::vector<Test::Result> protected_records() {
   auto policy = create_policy();

   return {
      CHECK("basic round-trip",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               const std::array<std::vector<uint8_t>, 2> handshake_payloads = {Botan::hex_decode("deadbeef"),
                                                                               Botan::hex_decode("beefdead")};

               // Two round trips without record protection to test sequence_number increment
               for(uint64_t i = 0; i < handshake_payloads.size(); ++i) {
                  const auto wire = prepare_handshake_record(rl_out, *policy, handshake_payloads[i]);
                  result.require("ingestion is successful", rl_in.copy_data(wire, false));
                  auto received = std::get<TLS::Handshake_Record>(rl_in.next_record());
                  result.test_bin_eq("received record matches payload", received.payload, handshake_payloads[i]);
                  result.test_enum_eq("record type", received.type, TLS::Record_Type::Handshake);
                  result.test_u64_eq("record sequence_number", received.sequence_number.value(), i);
               }

               // Application data can only be transferred once the handshake
               // completed, i.e. in the application traffic epoch.
               advance_to_application_traffic(*cs_client);
               advance_to_application_traffic(*cs_server);

               const auto to_be_protected_payload = Botan::hex_decode("efbeadde");

               const auto record = prepare_record(
                  rl_out, *policy, TLS::Record_Type::ApplicationData, to_be_protected_payload, cs_client.get());

               result.test_u8_eq("epoch encoded as 001xxxEE", record[0] & 0xE3, 0x23);

               result.require("ingestion is successful", rl_in.copy_data(record, true));
               auto deprotected = std::get<TLS::ApplicationData_Record>(rl_in.next_record(cs_server.get()));
               result.test_bin_eq("deprotected record matches payload", deprotected.payload, to_be_protected_payload);
               result.test_enum_eq("record type", deprotected.type, TLS::Record_Type::ApplicationData);
               result.test_u64_eq("record sequence_number", deprotected.sequence_number.value(), uint64_t{0});
               result.test_enum_eq("record epoch is application traffic",
                                   deprotected.epoch.value(),
                                   TLS::EpochNumber::ApplicationTraffic_0);
            }),

      CHECK("write protected record",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_client(TLS::Connection_Side::Client);

               const auto wire = prepare_handshake_record(
                  rl_client, *policy, Botan::hex_decode("68656c6c6f2064746c73"), cs_client.get());

               result.test_bin_eq("KAT output matches",
                                  wire,
                                  "2e 76 cf 00 1b 9a c7 72 ae 54 cb f8 cc 7b 09 72"
                                  "9d 4a 6f 78 89 c9 3b ff 4e 62 a5 3f 4f 34 c4 fb");
            }),

      CHECK("read protected record",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               TLS::DTLS_Record_Layer rl_server(TLS::Connection_Side::Server);

               const auto wire = Botan::hex_decode(
                  "2e 76 cf 00 1b 9a c7 72 ae 54 cb f8 cc 7b 09 72"
                  "9d 4a 6f 78 89 c9 3b ff 4e 62 a5 3f 4f 34 c4 fb");
               result.require("parsing success", rl_server.copy_data(wire, true));

               auto records = rl_server.next_record(cs_server.get());
               result.require("produced a record", !std::holds_alternative<TLS::BytesNeeded>(records));

               const auto& record = std::get<TLS::Handshake_Record>(records);
               result.test_bin_eq("payload matches", record.payload, "68656c6c6f2064746c73");
               result.test_enum_eq("type is Handshake", record.type, TLS::Record_Type::Handshake);
            }),

      CHECK("reading protected record without key state should drop the record",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               TLS::DTLS_Record_Layer rl_server(TLS::Connection_Side::Server);

               const auto wire = Botan::hex_decode(
                  "2e 76 cf 00 1b 9a c7 72 ae 54 cb f8 cc 7b 09 72"
                  "9d 4a 6f 78 89 c9 3b ff 4e 62 a5 3f 4f 34 c4 fb");
               result.require("parsing success", rl_server.copy_data(wire, false));

               auto records = rl_server.next_record(nullptr);
               result.require("produced no record", std::holds_alternative<TLS::BytesNeeded>(records));
            }),

      CHECK("read multiple protected records from one datagram",
            [&](Test::Result& result) {
               // The records in this datagram are written by a server, so we
               // read them with a client-side cipher state. Application data
               // requires the handshake to be complete, hence the records are
               // transferred in the application traffic epoch.
               auto cs_writer = make_cipher_state(TLS::Connection_Side::Server);
               auto cs_reader = make_cipher_state(TLS::Connection_Side::Client);
               advance_to_application_traffic(*cs_writer);
               advance_to_application_traffic(*cs_reader);

               TLS::DTLS_Record_Layer rl_writer(TLS::Connection_Side::Server);
               TLS::DTLS_Record_Layer rl_reader(TLS::Connection_Side::Client);

               const auto payload1 = Botan::hex_decode("7365727665722068656c6c6f");  // "server hello"
               const auto payload2 = Botan::hex_decode("617070207061796c6f6164");    // "app payload"

               // A (post-handshake) Handshake record followed by an
               // ApplicationData record, coalesced into a single datagram.
               const auto record1 = prepare_handshake_record(rl_writer, *policy, payload1, cs_writer.get());
               const auto record2 =
                  prepare_record(rl_writer, *policy, TLS::Record_Type::ApplicationData, payload2, cs_writer.get());
               const auto wire = Botan::concat<std::vector<uint8_t>>(record1, record2);

               result.require("parsing success", rl_reader.copy_data(wire, true));

               auto read1 = rl_reader.next_record(cs_reader.get());
               result.require("produced a record", !std::holds_alternative<TLS::BytesNeeded>(read1));

               const auto& r1 = std::get<TLS::Handshake_Record>(read1);
               result.test_bin_eq("payload matches", r1.payload, payload1);
               result.test_enum_eq("type is Handshake", r1.type, TLS::Record_Type::Handshake);

               auto read2 = rl_reader.next_record(cs_reader.get());
               result.require("produced another record", !std::holds_alternative<TLS::BytesNeeded>(read2));

               const auto& r2 = std::get<TLS::ApplicationData_Record>(read2);
               result.test_bin_eq("payload matches", r2.payload, payload2);
               result.test_enum_eq("type is ApplicationData", r2.type, TLS::Record_Type::ApplicationData);

               result.test_is_true("no more records",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_reader.next_record(cs_reader.get())));
            }),

      CHECK("tampered ciphertext is dropped",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               TLS::DTLS_Record_Layer rl_server(TLS::Connection_Side::Server);

               auto wire = Botan::hex_decode(
                  "2e 76 cf 00 1b 9a c7 72 ae 54 cb f8 cc 7b 09 72"
                  "9d 4a 6f 78 89 c9 3b ff 4e 62 a5 3f 4f 34 c4 fb");
               wire.back() ^= 0x40;  // flip a bit in the last ciphertext byte

               result.test_is_true("datagram is accepted", rl_server.copy_data(wire, true));
               result.test_sz_eq(
                  "No records", std::get<Botan::TLS::BytesNeeded>(rl_server.next_record(cs_server.get())), 0);
            }),

      CHECK("protected ChangeCipherSpec (inner type) is rejected",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               // Some protected record whose DTLSInnerPlaintext.type == 0x14 (CCS).
               const auto wire = Botan::hex_decode("2E86210012F3B637745B63096B1FE706BAD3EE73FF5D73");

               TLS::DTLS_Record_Layer rl(TLS::Connection_Side::Server);
               result.test_is_true("ingest doesn't reject protected datagram", rl.copy_data(wire, true));
               result.test_throws<TLS::TLS_Exception>("No records",
                                                      "Deprotected DTLS record had unexpected content type: 20",
                                                      [&] { rl.next_record(cs_server.get()); });
            }),

      CHECK("application data at the handshake epoch is rejected",
            [&](Test::Result& result) {
               // Regression test for CVE-2026-34582 in the DTLS flow:
               // application data must not be transferred before the
               // handshake completed (RFC 9147 Section 6.1).
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               // Note that the record layer currently produces such a record
               // without complaint; the peer's cipher state rejects it.
               const auto record = prepare_record(
                  rl_out, *policy, TLS::Record_Type::ApplicationData, Botan::hex_decode("deadbeef"), cs_client.get());

               result.require("ingestion is successful", rl_in.copy_data(record, true));
               result.test_throws<TLS::TLS_Exception>("application data before handshake completion is rejected",
                                                      "Application data received before handshake completion",
                                                      [&] { rl_in.next_record(cs_server.get()); });
            }),

      CHECK("application data replayed at the handshake epoch is rejected after handshake completion",
            [&](Test::Result& result) {
               // Even with application traffic keys in place, application
               // data must not arrive at the handshake epoch
               // (RFC 9147 Section 6.1).
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               const auto record = prepare_record(
                  rl_out, *policy, TLS::Record_Type::ApplicationData, Botan::hex_decode("deadbeef"), cs_client.get());

               // The recipient has completed the handshake in the meantime
               // and holds application traffic secrets.
               advance_to_application_traffic(*cs_server);

               result.require("ingestion is successful", rl_in.copy_data(record, true));
               result.test_throws<TLS::TLS_Exception>("application data at the handshake epoch is rejected",
                                                      "Can't interleave application and handshake data",
                                                      [&] { rl_in.next_record(cs_server.get()); });
            }),

      CHECK("unprotected and protected records in a single datagram",
            [&](Test::Result& result) {
               // This simulates the situation where a datagram contains both
               // unprotected and protected records. The record layer should be
               // able to read both sequentially.
               //
               // Such a situation can occur in DTLS 1.3 for the first server
               // flight, where the server sends an unprotected ServerHello
               // followed by a protected EncryptedExtensions record...
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);

               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Server);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Client);

               const std::array<std::vector<uint8_t>, 2> payloads = {
                  Botan::hex_decode("deadbeef"),
                  Botan::hex_decode("beefdead"),
               };

               // A single datagram that contains an unprotected Handshake
               // record followed by a protected (handshake traffic epoch)
               // Handshake record.
               const auto unprotected_record = prepare_handshake_record(rl_out, *policy, payloads[0]);
               const auto protected_record = prepare_handshake_record(rl_out, *policy, payloads[1], cs_server.get());
               const auto wire = Botan::concat<std::vector<uint8_t>>(unprotected_record, protected_record);

               result.require("reading hybrid datagram", rl_in.copy_data(wire, true));
               auto unprotected = rl_in.next_record(nullptr);
               result.test_is_true("expect getting a record", !std::holds_alternative<TLS::BytesNeeded>(unprotected));
               auto record1 = std::get<TLS::Handshake_Record>(unprotected);
               result.test_enum_eq("type is Handshake", record1.type, TLS::Record_Type::Handshake);
               result.test_bin_eq("payload matches", record1.payload, payloads[0]);

               auto was_protected = rl_in.next_record(cs_client.get());
               result.test_is_true("expect getting a record", !std::holds_alternative<TLS::BytesNeeded>(was_protected));
               auto record2 = std::get<TLS::Handshake_Record>(was_protected);
               result.test_enum_eq("type is Handshake", record2.type, TLS::Record_Type::Handshake);
               result.test_enum_eq(
                  "epoch is handshake traffic", record2.epoch.value(), TLS::EpochNumber::HandshakeTraffic);
               result.test_bin_eq("payload matches", record2.payload, payloads[1]);

               result.test_is_true("no more records",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_client.get())));
            }),

      CHECK("duplicated and too-old protected records are rejected",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               advance_to_application_traffic(*cs_client);
               advance_to_application_traffic(*cs_server);

               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               const auto payload = Botan::hex_decode("deadbeef");

               const auto first_record =
                  prepare_record(rl_out, *policy, TLS::Record_Type::ApplicationData, payload, cs_client.get());

               result.require("ingest first record", rl_in.copy_data(first_record, true));
               result.test_is_true("first record is delivered",
                                   !std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_server.get())));

               // Receiving the very same record again must not deliver it twice.
               // The duplicate deprotects successfully but is then rejected
               // by the replay window (RFC 9147 Section 4.5.1).
               result.test_is_true("ingest duplicate record", rl_in.copy_data(first_record, true));
               result.test_is_true("duplicate record is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_server.get())));

               // Advance the replay window beyond the first record's sequence number
               for(uint64_t i = 0; i < TLS::Replay_Window_13::window_size; ++i) {
                  const auto record =
                     prepare_record(rl_out, *policy, TLS::Record_Type::ApplicationData, payload, cs_client.get());
                  result.require("ingest record", rl_in.copy_data(record, true));
                  result.require("record is delivered",
                                 !std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_server.get())));
               }

               // The first record's sequence number fell off the left edge of the window
               result.test_is_true("ingest too-old record", rl_in.copy_data(first_record, true));
               result.test_is_true("too-old record is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_server.get())));

               // The record layer is still functional afterwards
               const auto fresh_record =
                  prepare_record(rl_out, *policy, TLS::Record_Type::ApplicationData, payload, cs_client.get());
               result.require("ingest fresh record", rl_in.copy_data(fresh_record, true));
               auto read = rl_in.next_record(cs_server.get());
               result.require("fresh record is delivered", !std::holds_alternative<TLS::BytesNeeded>(read));
               result.test_bin_eq("payload matches", std::get<TLS::ApplicationData_Record>(read).payload, payload);
            }),

      CHECK("replay windows are tracked per epoch",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               const auto payload = Botan::hex_decode("deadbeef");

               // Sequence number 0 in the handshake traffic epoch (application
               // data is not allowed, yet, hence a handshake-typed record)
               const auto handshake_record = prepare_handshake_record(rl_out, *policy, payload, cs_client.get());
               result.require("ingest handshake epoch record", rl_in.copy_data(handshake_record, true));
               auto read1 = rl_in.next_record(cs_server.get());
               result.require("handshake epoch record is delivered", !std::holds_alternative<TLS::BytesNeeded>(read1));
               result.test_enum_eq("epoch is handshake traffic",
                                   std::get<TLS::Handshake_Record>(read1).epoch.value(),
                                   TLS::EpochNumber::HandshakeTraffic);

               // Advance both cipher states to the application traffic epoch
               advance_to_application_traffic(*cs_client);
               advance_to_application_traffic(*cs_server);

               // Sequence number 0 in the application traffic epoch must be
               // accepted, because replay state is tracked per epoch.
               const auto app_record =
                  prepare_record(rl_out, *policy, TLS::Record_Type::ApplicationData, payload, cs_client.get());
               result.require("ingest application epoch record", rl_in.copy_data(app_record, true));
               auto read2 = rl_in.next_record(cs_server.get());
               result.require("application epoch record is delivered",
                              !std::holds_alternative<TLS::BytesNeeded>(read2));
               result.test_enum_eq("epoch is application traffic",
                                   std::get<TLS::ApplicationData_Record>(read2).epoch.value(),
                                   TLS::EpochNumber::ApplicationTraffic_0);
               result.test_u64_eq(
                  "sequence number is 0", std::get<TLS::ApplicationData_Record>(read2).sequence_number.value(), 0);

               // ... while a duplicate in that epoch is still rejected.
               result.require("ingest duplicate application epoch record", rl_in.copy_data(app_record, true));
               result.test_is_true("duplicate is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_server.get())));
            }),

      CHECK("plaintext records are discarded once a cryptographic association exists",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);

               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               const auto plaintext_record = prepare_handshake_record(rl_out, *policy, Botan::hex_decode("deadbeef"));

               // RFC 9147 4.2.1: Implementations SHOULD discard records from
               // earlier epochs. Once the cipher state reads in the handshake
               // traffic epoch, plaintext (epoch 0) records are dropped.
               result.require("ingest plaintext record", rl_in.copy_data(plaintext_record, true));
               result.test_is_true("plaintext record is discarded",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_server.get())));

               // The same record is delivered when read without a cipher state.
               TLS::DTLS_Record_Layer rl_in2(TLS::Connection_Side::Server);
               result.require("ingest plaintext record", rl_in2.copy_data(plaintext_record, false));
               result.test_is_true("plaintext record is delivered",
                                   !std::holds_alternative<TLS::BytesNeeded>(rl_in2.next_record(nullptr)));
            }),

      CHECK("a protected record without a length field consumes the rest of the datagram",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               // RFC 9147 Section 4.3: The final record in a datagram can
               // omit the length field; it then consumes the entire rest of
               // the datagram. (epoch_bits=2, no CID, short seq_no, no length)
               const auto wire = Botan::concat<std::vector<uint8_t>>(
                  std::array<uint8_t, 2>{0b00100010, 0x2A}, std::vector<uint8_t>(16, 0xAA) /* garbage "ciphertext" */);

               // The datagram parses fine; the record then fails deprotection
               // and is discarded. Note that a framing error would have
               // rejected the datagram right away.
               result.test_is_true("length-less record is framed correctly", rl_in.copy_data(wire, true));
               result.test_is_true("record is dropped after failed deprotection",
                                   std::holds_alternative<TLS::BytesNeeded>(rl_in.next_record(cs_server.get())));
            }),

      CHECK("record size limit depends on the protection epoch",
            [&](Test::Result& result) {
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               TLS::DTLS_Record_Layer rl(TLS::Connection_Side::Server);

               // Unprotected records use the 13-byte DTLSPlaintext header,
               // protected records use the shorter unified header but incur
               // AEAD expansion, so the payload limits differ per epoch.
               const auto limit_unprotected = rl.record_payload_size_limit(*policy, nullptr);
               const auto limit_epoch0 =
                  rl.record_payload_size_limit(*policy, cs_server.get(), TLS::EpochNumber::Unprotected);
               const auto limit_protected =
                  rl.record_payload_size_limit(*policy, cs_server.get(), TLS::EpochNumber::HandshakeTraffic);

               result.test_is_true("cipher state alone does not protect", limit_unprotected == limit_epoch0);
               result.test_is_true("epoch 0 allows more payload than protected epochs", limit_epoch0 > limit_protected);
            }),

      CHECK("minimum record size is respected",
            [&](Test::Result& result) {
               auto cs_client = make_cipher_state(TLS::Connection_Side::Client);
               auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
               advance_to_application_traffic(*cs_client);
               advance_to_application_traffic(*cs_server);

               const size_t minimum_record_size = 1024;

               auto policy_with_padding = create_policy(minimum_record_size);
               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);

               const std::vector<uint8_t> payload(1, 0x42);
               const auto record = prepare_record(
                  rl_out, *policy_with_padding, TLS::Record_Type::ApplicationData, payload, cs_client.get());

               // The lower bound does not include the unified record header
               // which has a variable length.
               const size_t expected_size_lower_bound = cs_client->encrypt_output_length(minimum_record_size);
               result.test_sz_gte("produced wire bytes", record.size(), expected_size_lower_bound);

               // decryption
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);
               result.require("ingestion is successful", rl_in.copy_data(record, true));
               auto read = rl_in.next_record(cs_server.get());
               result.require("expect getting a record", !std::holds_alternative<TLS::BytesNeeded>(read));
               auto content = std::get<TLS::ApplicationData_Record>(read);
               result.test_enum_eq("type is ApplicationData", content.type, TLS::Record_Type::ApplicationData);
               result.test_bin_eq("payload matches", content.payload, payload);
            }),

      CHECK("round-trip with all relevant cipher suites",
            [&](Test::Result& result) {
               auto go = [&](std::string_view suite) {
                  auto suite_cs_client = make_cipher_state(TLS::Connection_Side::Client, suite);
                  auto suite_cs_server = make_cipher_state(TLS::Connection_Side::Server, suite);
                  advance_to_application_traffic(*suite_cs_client);
                  advance_to_application_traffic(*suite_cs_server);

                  TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
                  TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

                  // Short payload to make sure that certain cipher suites properly
                  // perform their implicit padding (See RFC 9147 4.2.3).
                  const auto payload = std::array<uint8_t, 2>{0x01, 0x02};
                  const auto record =
                     prepare_record(rl_out, *policy, TLS::Record_Type::ApplicationData, payload, suite_cs_client.get());
                  BOTAN_STATE_CHECK(record.size() >= 16);  // minimum record size for all suites

                  const bool read_success = rl_in.copy_data(record, true);
                  BOTAN_STATE_CHECK(read_success);

                  const auto out_record = rl_in.next_record(suite_cs_server.get());
                  BOTAN_STATE_CHECK(!std::holds_alternative<TLS::BytesNeeded>(out_record));

                  BOTAN_ASSERT_NOMSG(std::get<TLS::ApplicationData_Record>(out_record).payload.size() ==
                                     payload.size());
                  BOTAN_ASSERT_NOMSG(std::get<TLS::ApplicationData_Record>(out_record).payload[0] == payload[0]);
                  BOTAN_ASSERT_NOMSG(std::get<TLS::ApplicationData_Record>(out_record).payload[1] == payload[1]);
               };

               const auto suites = std::array {
                  "AES_128_GCM_SHA256", "AES_256_GCM_SHA384",
   #if defined(BOTAN_HAS_AEAD_CCM)
                     "AES_128_CCM_SHA256", "AES_128_CCM_8_SHA256",
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
      CHECK("unacknowledged outgoing records are retransmitted until the flight state progresses",
            [&](Test::Result& result) {
               TLS::DTLS_Record_Layer rl(TLS::Connection_Side::Client);

               // a flight of two unprotected handshake records (epoch 0)
               Botan::secure_vector<uint8_t> out1;
               Botan::secure_vector<uint8_t> out2;
               const auto rn1 = rl.prepare_handshake_record(packed(payload1), out1, *policy, nullptr);
               const auto rn2 = rl.prepare_handshake_record(packed(payload2), out2, *policy, nullptr);
               result.test_enum_eq("first record in epoch 0", rn1.epoch, TLS::EpochNumber::Unprotected);
               result.test_u64_eq("first record sequence number", rn1.sequence_number, 0);
               result.test_u64_eq("second record sequence number", rn2.sequence_number, 1);

               const std::array<Botan::secure_vector<uint8_t>, 2> original = {out1, out2};

               const auto retransmission = rl.prepare_unacknowledged_records(*policy, nullptr);
               result.require("two records retransmitted", retransmission.size() == original.size());

               for(size_t i = 0; i < retransmission.size(); ++i) {
                  const auto retransmitted_rn = plaintext_record_number(retransmission[i]);

                  result.test_u64_eq("retransmission stays in epoch 0", retransmitted_rn.first, 0);
                  result.test_u64_eq("retransmission uses a fresh record sequence number",
                                     retransmitted_rn.second,
                                     original.size() + i);

                  // the record payload (and hence the handshake message with
                  // its message_seq) is reused unchanged
                  result.test_bin_eq("retransmitted payload is identical",
                                     std::span{retransmission[i].get()}.subspan(TLS::Size_Limits::DTLS_HEADER_SIZE),
                                     std::span{original[i]}.subspan(TLS::Size_Limits::DTLS_HEADER_SIZE));
               }

               rl.clear_resend_buffer();
               result.test_is_true("nothing left to retransmit",
                                   rl.prepare_unacknowledged_records(*policy, nullptr).empty());
            }),

      CHECK(
         "retransmission of a mixed flight with protected records",
         [&](Test::Result& result) {
            auto cs_server = make_cipher_state(TLS::Connection_Side::Server);
            auto cs_client = make_cipher_state(TLS::Connection_Side::Client);

            TLS::DTLS_Record_Layer rl_server(TLS::Connection_Side::Server);
            TLS::DTLS_Record_Layer rl_client(TLS::Connection_Side::Client);

            // Simulate a server's first flight, i.e., use an unprotected
            // record (ServerHello) followed by protected records (e.g.
            // EncryptedExtensions, Finished).
            Botan::secure_vector<uint8_t> unprotected;
            rl_server.prepare_handshake_record(packed(payload1), unprotected, *policy, nullptr);
            Botan::secure_vector<uint8_t> protected1;
            Botan::secure_vector<uint8_t> protected2;
            rl_server.prepare_handshake_record(packed(payload2), protected1, *policy, cs_server.get());
            rl_server.prepare_handshake_record(packed(payload3), protected2, *policy, cs_server.get());

            // The flight is lost and the server retransmits everything that
            // was not acknowledged.
            const auto retransmission = rl_server.prepare_unacknowledged_records(*policy, cs_server.get());
            result.require("three records retransmitted", retransmission.size() == 3);

            // The unprotected record is retransmitted in epoch 0 under a
            // fresh record sequence number (RFC 9147 Section 5.2, see the
            // test case above).
            const auto rn = plaintext_record_number(retransmission[0]);
            result.test_u64_eq("retransmission stays in epoch 0", rn.first, 0);
            result.test_u64_eq("fresh record sequence number", rn.second, 1);

            // The protected records are encrypted afresh, i.e. their
            // ciphertexts differ from the originals'.
            result.test_is_true("fresh encryption of first protected record", retransmission[1].get() != protected1);
            result.test_is_true("fresh encryption of second protected record", retransmission[2].get() != protected2);

            // The peer can read all retransmitted records.
            const auto expected_payloads = std::array{payload1, payload2, payload3};
            const auto expected_epochs = std::array{
               TLS::EpochNumber::Unprotected, TLS::EpochNumber::HandshakeTraffic, TLS::EpochNumber::HandshakeTraffic};
            const auto expected_seqnos = std::array<uint64_t, 3>{1, 2, 3};
            for(size_t i = 0; i < retransmission.size(); ++i) {
               result.require("ingestion is successful", rl_client.copy_data(retransmission[i].get(), true));

               // Plaintext records from an earlier epoch are discarded once a
               // cryptographic association exists (RFC 9147 Section 4.2.1), so
               // the retransmitted ServerHello is read without one.
               auto read = (expected_epochs[i] == TLS::EpochNumber::Unprotected)
                              ? rl_client.next_record()
                              : rl_client.next_record(cs_client.get());
               result.require("record is delivered", !std::holds_alternative<TLS::BytesNeeded>(read));
               const auto& content = std::get<TLS::Handshake_Record>(read);
               result.test_bin_eq("payload round-trips", content.payload, expected_payloads[i]);
               result.test_enum_eq("epoch", content.epoch.value(), expected_epochs[i]);
               result.test_u64_eq("fresh record sequence number", content.sequence_number.value(), expected_seqnos[i]);
            }

            rl_server.clear_resend_buffer();
            result.test_is_true("nothing left to retransmit",
                                rl_server.prepare_unacknowledged_records(*policy, nullptr).empty());
         }),

      CHECK("acknowledged records are not retransmitted",
            [&](Test::Result& result) {
               TLS::DTLS_Record_Layer rl_out(TLS::Connection_Side::Client);
               TLS::DTLS_Record_Layer rl_in(TLS::Connection_Side::Server);

               Botan::secure_vector<uint8_t> out;
               const auto rn = rl_out.prepare_handshake_record(packed(payload1), out, *policy, nullptr);
               result.test_is_true("record is unacknowledged", rl_out.has_unacknowledged_record(rn));

               // The peer receives the record and queues an acknowledgement
               // for it (RFC 9147 Section 7).
               result.require("ingestion is successful", rl_in.copy_data(out, false));
               auto read = rl_in.next_record();
               result.require("record is delivered", !std::holds_alternative<TLS::BytesNeeded>(read));
               const auto& content = std::get<TLS::Handshake_Record>(read);

               result.test_is_true("nothing to acknowledge yet", !rl_in.has_outstanding_acknowledgements());
               rl_in.acknowledge_handshake_record(
                  TLS::RecordNumber{content.epoch.value(), content.sequence_number.value()}, *policy);
               result.test_is_true("acknowledgement is queued", rl_in.has_outstanding_acknowledgements());

               // The sender consumes the ACK record and stops retransmitting.
               result.test_is_true("all records acknowledged",
                                   rl_out.handle_acknowledgements(rl_in.acknowledgements()));
               result.test_is_true("no unacknowledged records", !rl_out.has_unacknowledged_records());
               result.test_is_true("nothing left to retransmit",
                                   rl_out.prepare_unacknowledged_records(*policy, nullptr).empty());

               rl_in.clear_outstanding_acknowledgements();
               result.test_is_true("acknowledgement queue is cleared", !rl_in.has_outstanding_acknowledgements());
            }),
   };
}

std::vector<Test::Result> unified_header() {
   return {
      CHECK("empty input is rejected",
            [&](Test::Result& result) {
               const auto bytes = std::array<uint8_t, 0>{};
               result.test_throws("empty input is rejected", [&] { parse_header(bytes, std::nullopt); });
            }),

      CHECK("input with malformed header byte is rejected",
            [&](Test::Result& result) {
               // epoch_bits=0, no CID, short seq_no, no length
               // prefix is not 0b001xxxxx, so it is malformed
               constexpr uint8_t malformed_header = 0b11100000;
               const auto bytes = std::array<uint8_t, 2>{malformed_header, 0x00 /* seqno */};
               result.test_throws("malformed header is rejected", [&] { parse_header(bytes, std::nullopt); });
            }),

      CHECK("input without sequence number is rejected",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, no length
               constexpr uint8_t minimal_header = 0b00100010;
               const auto bytes = std::array<uint8_t, 1>{minimal_header};
               result.test_throws("missing seqno is rejected", [&] { parse_header(bytes, std::nullopt); });
            }),

      CHECK("input with too short sequence number is rejected",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, long seq_no, no length
               constexpr uint8_t minimal_header_long_seqno = 0b00101010;
               const auto bytes = std::array<uint8_t, 2>{minimal_header_long_seqno, 0x00};
               result.test_throws("too short seqno is rejected", [&] { parse_header(bytes, std::nullopt); });
            }),

      CHECK("minimal unified header",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, no length
               constexpr uint8_t minimal_header = 0b00100010;
               const auto bytes = std::array<uint8_t, 2>{minimal_header, 0b00101010};

               const auto header = parse_header(bytes, std::nullopt);
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
               result.test_throws("missing payload length is rejected", [&] { parse_header(bytes, std::nullopt); });
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
               result.test_throws("partial payload length is rejected", [&] { parse_header(bytes, std::nullopt); });
            }),

      CHECK("unified header with payload length",
            [&](Test::Result& result) {
               // epoch_bits=2, no CID, short seq_no, with length
               constexpr uint8_t minimal_header_with_length = 0b00100110;

               // Parsing validates that the advertised payload is actually
               // present in the input buffer.
               const auto bytes = Botan::concat<std::vector<uint8_t>>(
                  std::array<uint8_t, 4>{
                     minimal_header_with_length,
                     0x00 /* seqno */,
                     0x00,
                     0x10 /* payload length */,
                  },
                  std::vector<uint8_t>(16, 0xAA) /* dummy payload */);

               const auto header = parse_header(bytes, std::nullopt);
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
                                  [&] { parse_header(bytes, connection_id_length); });
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
                                  [&] { parse_header(bytes, connection_id_length); });
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
                                  [&] { parse_header(bytes, connection_id_length); });
            }),

      CHECK("full unified header",
            [&](Test::Result& result) {
               const size_t connection_id_length = 7;

               // epoch_bits=2, with CID, long seq_no, with length
               constexpr uint8_t full_header = 0b00111110;

               // Parsing validates that the advertised payload is actually
               // present in the input buffer.
               // clang-format off
               const auto bytes = Botan::concat<std::vector<uint8_t>>(
                  std::array<uint8_t, 12>{
                     full_header,                              // header
                     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // connection ID
                     0x00, 0x2A,                               // sequence number
                     0x00, 0x10                                // payload length
                  },
                  std::vector<uint8_t>(16, 0xAA) /* dummy payload */);
               // clang-format on

               const auto header = parse_header(bytes, connection_id_length);
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

               result.test_throws("unsolicited CID is rejected", [&] { parse_header(bytes, std::nullopt); });
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
