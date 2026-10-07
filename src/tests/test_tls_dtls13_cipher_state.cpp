/*
* (C) 2026 Jack Lloyd
* (C) 2026 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DTLS_13)

   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/tls.h>

   #include <botan/internal/buffer_slicer.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/tls_channel_impl_13.h>
   #include <botan/internal/tls_cipher_state.h>
   #include <botan/internal/tls_cipher_state_dtls13.h>

namespace Botan_Tests {

namespace {

using namespace Botan;
using namespace Botan::TLS;

class Journaling_Secret_Logger : public std::enable_shared_from_this<Journaling_Secret_Logger> {
   public:
      Botan::TLS::SecretLoggerFn get_secret_logger() {
         return [self = weak_from_this()](std::string_view label, std::span<const uint8_t> secret) {
            if(const auto s = self.lock()) {
               s->maybe_log_secret(label, secret);
            }
         };
      }

      void maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const {
         secrets[std::string(label)] = std::vector<uint8_t>(secret.begin(), secret.end());
      }

   public:
      mutable std::map<std::string, std::vector<uint8_t>> secrets;  // NOLINT(*-non-private-member-variable*)
};

/// Maximum plaintext size accepted when deprotecting records in these tests
constexpr size_t RECORD_SIZE_LIMIT = 16384;

/**
 * Creates a client/server pair of DTLS cipher states that share the same
 * (artificial) handshake secrets, i.e. records protected by one side can be
 * deprotected by the other.
 */
struct DTLS_Peers {
      std::unique_ptr<Cipher_State> client;  // NOLINT(*-non-private-member-variables-in-classes)
      std::unique_ptr<Cipher_State> server;  // NOLINT(*-non-private-member-variables-in-classes)

      static DTLS_Peers make(const Ciphersuite& cipher) {
         const std::vector<uint8_t> transcript_hash(HashFunction::create_or_throw(cipher.prf_algo())->output_length(),
                                                    0x00);
         auto shared_secret = [] { return secure_vector<uint8_t>(32, 0x00); };

         return DTLS_Peers{
            .client = Cipher_State::init_with_server_hello(
               Connection_Side::Client, TLS_Flavor::DTLS, shared_secret(), cipher, transcript_hash, nullptr),
            .server = Cipher_State::init_with_server_hello(
               Connection_Side::Server, TLS_Flavor::DTLS, shared_secret(), cipher, transcript_hash, nullptr),
         };
      }

      /// Advances both peers to the application traffic state (epoch 3)
      void advance_to_application_traffic() const {
         const std::vector<uint8_t> transcript_hash(
            HashFunction::create_or_throw(client->hash_algorithm())->output_length(), 0x01);
         client->advance_with_server_finished(transcript_hash);
         server->advance_with_server_finished(transcript_hash);
         client->advance_with_client_finished(transcript_hash);
         server->advance_with_client_finished(transcript_hash);
      }

      /// Performs a key update in both directions, keeping the peers in sync
      void update_keys() const {
         client->update_write_keys();
         server->update_read_keys();
         server->update_write_keys();
         client->update_read_keys();
      }
};

RecordNumber protect(Cipher_State& cs,
                     Record_Type type,
                     std::span<const uint8_t> payload,
                     secure_vector<uint8_t>& wire,
                     size_t padding = 0,
                     std::optional<EpochNumber> epoch = std::nullopt) {
   return as_dtls_cipher_state(&cs)->protect_record(type, payload, padding, wire, epoch);
}

/// Parses the unified header of a marshalled record as produced by protect()
UnifiedHeader_DTLS parse_header(std::span<const uint8_t> wire) {
   BufferSlicer bs(wire);
   return UnifiedHeader_DTLS::parse(bs, std::nullopt /* no CID */);
}

/// Re-marshall a record with a different header, keeping the payload as-is
secure_vector<uint8_t> remarshall_with_header(const UnifiedHeader_DTLS& header, std::span<const uint8_t> wire) {
   BufferSlicer bs(wire);
   UnifiedHeader_DTLS::parse(bs, std::nullopt /* no CID */);  // skip the original header
   const auto payload = bs.take(bs.remaining());

   auto out = header.serialize<secure_vector<uint8_t>>();
   out.insert(out.end(), payload.begin(), payload.end());
   return out;
}

/// Deprotects a marshalled record as produced by protect()
std::optional<Record> deprotect(Cipher_State& cs, std::span<const uint8_t> wire) {
   BufferSlicer bs(wire);
   auto header = UnifiedHeader_DTLS::parse(bs, std::nullopt /* no CID */);
   const auto payload = bs.take(bs.remaining());
   return as_dtls_cipher_state(&cs)->deprotect_record(
      ProtectedRecord_DTLS{.header = header, .payload = secure_vector<uint8_t>(payload.begin(), payload.end())},
      RECORD_SIZE_LIMIT);
}

const Record_Content& record_content(const Record& record) {
   return std::visit([](const auto& r) -> const Record_Content& { return r; }, record);
}

/// The sequence number hint in the unified header (masked, as on the wire)
uint64_t sequence_number_hint(const UnifiedHeader_DTLS& header) {
   return std::visit([](const auto seqno) -> uint64_t { return seqno; }, header.sequence_number);
}

/// Protects a record with @p sender, deprotects it with @p receiver and checks
/// the record number, epoch bits, content type, payload and sequence number.
void check_roundtrip(Test::Result& result,
                     Cipher_State& sender,
                     Cipher_State& receiver,
                     Record_Type type,
                     std::span<const uint8_t> payload,
                     EpochNumber expected_epoch,
                     uint64_t expected_seqno) {
   secure_vector<uint8_t> wire;
   const auto record_number = protect(sender, type, payload, wire);

   result.test_enum_eq("epoch of protected record", record_number.epoch, expected_epoch);
   result.test_u64_eq("sequence number of protected record", record_number.sequence_number, expected_seqno);
   result.test_u8_eq("epoch bits in unified header",
                     parse_header(wire).epoch_bits,
                     static_cast<uint8_t>(static_cast<uint64_t>(expected_epoch) & 0b11));

   auto record = deprotect(receiver, wire);
   result.test_opt_not_null("record was deprotected", record);
   if(record.has_value()) {
      const auto& content = record_content(*record);
      result.test_enum_eq("deprotected record type", content.type, type);
      result.test_bin_eq("deprotected payload", content.payload, payload);
      result.test_opt_u64_eq("deprotected sequence number", content.sequence_number, expected_seqno);
      result.test_is_true("deprotected epoch", content.epoch == expected_epoch);
   }
}

std::vector<Test::Result> update_cipher_state() {
   const auto cipher = Ciphersuite::from_name("AES_128_GCM_SHA256").value();

   auto sl_client = std::make_shared<Journaling_Secret_Logger>();
   auto sl_server = std::make_shared<Journaling_Secret_Logger>();

   const std::vector<uint8_t> transcript_hash(32, 0x00);
   auto shared_secret = [] { return secure_vector<uint8_t>(32, 0x00); };

   auto cs_server = Cipher_State::init_with_server_hello(Connection_Side::Server,
                                                         TLS_Flavor::DTLS,
                                                         shared_secret(),
                                                         cipher,
                                                         transcript_hash,
                                                         sl_server->get_secret_logger());
   auto cs_client = Cipher_State::init_with_server_hello(Connection_Side::Client,
                                                         TLS_Flavor::DTLS,
                                                         shared_secret(),
                                                         cipher,
                                                         transcript_hash,
                                                         sl_client->get_secret_logger());

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
                                  sl_client->secrets.at("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
                                  c_hs_traffic);
               result.test_bin_eq("server_handshake_traffic_secret",
                                  sl_server->secrets.at("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
                                  s_hs_traffic);
            }),
   };
}

std::vector<Test::Result> record_number_handling() {
   auto suite_roundtrip = [](const char* suite_name) {
      return CHECK(suite_name, [suite_name](Test::Result& result) {
         auto peers = DTLS_Peers::make(Ciphersuite::from_name(suite_name).value());

         const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

         check_roundtrip(
            result, *peers.client, *peers.server, Record_Type::Handshake, plaintext, EpochNumber::HandshakeTraffic, 0);
         check_roundtrip(
            result, *peers.server, *peers.client, Record_Type::Handshake, plaintext, EpochNumber::HandshakeTraffic, 0);
      });
   };

   return {
      CHECK("records are deprotected out of order within an epoch",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               std::array<secure_vector<uint8_t>, 5> wires;
               for(auto& wire : wires) {
                  protect(*peers.client, Record_Type::Handshake, plaintext, wire);
               }

               // datagrams may be reordered in transit; the full sequence
               // number is reconstructed from the 16-bit hint on the wire
               // (RFC 9147 Section 4.2.2)
               for(const size_t i : {2, 0, 4, 1, 3}) {
                  auto record = deprotect(*peers.server, wires[i]);
                  result.test_opt_not_null("record was deprotected", record);
                  if(record.has_value()) {
                     const auto& content = record_content(*record);
                     result.test_opt_u64_eq("reconstructed sequence number", content.sequence_number, i);
                     result.test_bin_eq("deprotected payload", content.payload, plaintext);
                  }
               }
            }),

      CHECK("sequence numbers are masked on the wire",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               std::array<secure_vector<uint8_t>, 3> wires;
               for(size_t i = 0; i < wires.size(); ++i) {
                  const auto record_number = protect(*peers.client, Record_Type::Handshake, plaintext, wires[i]);
                  result.test_u64_eq("sequence number of protected record", record_number.sequence_number, i);

                  // RFC 9147 Section 4.2.3
                  //    The encrypted sequence number is computed by XORing the
                  //    leading bytes of the mask with the on-the-wire
                  //    representation of the sequence number.
                  result.test_sz_ne(
                     "sequence number is masked on the wire", sequence_number_hint(parse_header(wires[i])), i);
               }

               for(size_t i = 0; i < wires.size(); ++i) {
                  auto record = deprotect(*peers.server, wires[i]);
                  result.test_opt_not_null("record was deprotected", record);
                  if(record.has_value()) {
                     result.test_opt_u64_eq("recovered sequence number", record_content(*record).sequence_number, i);
                  }
               }
            }),

      // round trips covering the AES-256 and ChaCha20 record number mask
      // constructions (AES-128 is covered by the test above)
      suite_roundtrip("AES_256_GCM_SHA384"),
      suite_roundtrip("AES_128_CCM_SHA256"),
      suite_roundtrip("CHACHA20_POLY1305_SHA256"),
   };
}

std::vector<Test::Result> epoch_transitions() {
   return {
      CHECK("records round trip across epochs",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               result.test_enum_eq(
                  "client write epoch", peers.client->current_write_epoch_number(), EpochNumber::HandshakeTraffic);
               result.test_enum_eq(
                  "server read epoch", peers.server->current_read_epoch_number(), EpochNumber::HandshakeTraffic);

               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::Handshake,
                               plaintext,
                               EpochNumber::HandshakeTraffic,
                               0);
               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::Handshake,
                               plaintext,
                               EpochNumber::HandshakeTraffic,
                               1);

               peers.advance_to_application_traffic();

               result.test_enum_eq(
                  "client write epoch", peers.client->current_write_epoch_number(), EpochNumber::ApplicationTraffic_0);
               result.test_enum_eq(
                  "server read epoch", peers.server->current_read_epoch_number(), EpochNumber::ApplicationTraffic_0);

               // sequence numbers restart at 0 in the new epoch
               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0,
                               0);
               check_roundtrip(result,
                               *peers.server,
                               *peers.client,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0,
                               0);
               check_roundtrip(result,
                               *peers.server,
                               *peers.client,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0,
                               1);
            }),

      CHECK("records can be protected under the previous epoch",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               // e.g. a handshake flight retransmission after application
               // traffic keys are already available
               secure_vector<uint8_t> wire;
               const auto record_number =
                  protect(*peers.client, Record_Type::Handshake, plaintext, wire, 0, EpochNumber::HandshakeTraffic);
               result.test_enum_eq(
                  "protected under handshake epoch", record_number.epoch, EpochNumber::HandshakeTraffic);
               result.test_u64_eq("sequence number of protected record", record_number.sequence_number, 0);
               result.test_u8_eq("epoch bits in unified header", parse_header(wire).epoch_bits, 0b10);

               auto record = deprotect(*peers.server, wire);
               result.test_opt_not_null("record was deprotected", record);
               if(record.has_value()) {
                  const auto& content = record_content(*record);
                  result.test_enum_eq("deprotected record type", content.type, Record_Type::Handshake);
                  result.test_bin_eq("deprotected payload", content.payload, plaintext);
                  result.test_is_true("deprotected epoch", content.epoch == EpochNumber::HandshakeTraffic);
               }
            }),

      CHECK("records round trip after key update with previous epoch retained",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               // protect a record under the initial application traffic epoch
               secure_vector<uint8_t> old_wire;
               protect(*peers.client, Record_Type::ApplicationData, plaintext, old_wire);

               peers.update_keys();

               result.test_enum_eq("client write epoch after key update",
                                   peers.client->current_write_epoch_number(),
                                   EpochNumber::ApplicationTraffic_0 + 1);

               // sequence numbers restart at 0 in the new epoch
               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0 + 1,
                               0);
               check_roundtrip(result,
                               *peers.server,
                               *peers.client,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0 + 1,
                               0);

               // records from the retained previous epoch can still be deprotected
               auto old_record = deprotect(*peers.server, old_wire);
               result.test_opt_not_null("record from previous epoch was deprotected", old_record);
               if(old_record.has_value()) {
                  const auto& content = record_content(*old_record);
                  result.test_bin_eq("deprotected payload", content.payload, plaintext);
                  result.test_is_true("deprotected epoch", content.epoch == EpochNumber::ApplicationTraffic_0);
               }
            }),

      CHECK("deprotection uses the newest epoch matching the epoch bits",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               // retain a record protected under the initial application
               // traffic epoch 3 (epoch bits 0b11)
               secure_vector<uint8_t> epoch3_wire;
               protect(*peers.client, Record_Type::ApplicationData, plaintext, epoch3_wire);

               // perform several key updates without pruning, so that multiple
               // read epochs share the same epoch bits (epochs 3 and 7 -> 0b11)
               for(size_t i = 0; i < 4; ++i) {
                  peers.update_keys();
               }

               result.test_enum_eq("client write epoch",
                                   peers.client->current_write_epoch_number(),
                                   EpochNumber::ApplicationTraffic_0 + 4);

               // the record's epoch bits (0b11) match both the current epoch 7
               // and the retained epoch 3; deprotection only succeeds if the
               // newest matching epoch is used (RFC 9147 Section 4.2.2)
               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0 + 4,
                               0);
               check_roundtrip(result,
                               *peers.server,
                               *peers.client,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0 + 4,
                               0);

               // the epoch-3 record is now ambiguous with epoch 7; it is
               // (unsuccessfully) attempted under the newest matching epoch
               // and thus silently discarded (RFC 9147 Sections 4.2.2, 4.5.2)
               result.test_opt_is_null("record from ambiguous previous epoch was discarded",
                                       deprotect(*peers.server, epoch3_wire));

               // deprotecting under the newest matching epoch did not poison
               // the cipher state for the current epoch
               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0 + 4,
                               1);
            }),
   };
}

std::vector<Test::Result> epoch_pruning() {
   return {
      CHECK("records of pruned read epochs are silently discarded",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               secure_vector<uint8_t> old_wire;
               protect(*peers.client, Record_Type::ApplicationData, plaintext, old_wire);

               peers.update_keys();

               as_dtls_cipher_state(peers.server.get())
                  ->prune_read_epochs_older_than(EpochNumber::ApplicationTraffic_0 + 1);

               result.test_opt_is_null("record from pruned epoch was discarded", deprotect(*peers.server, old_wire));

               // the current epoch is not affected by the pruning
               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0 + 1,
                               0);
            }),

      CHECK("protecting under a pruned write epoch fails",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               peers.update_keys();

               as_dtls_cipher_state(peers.client.get())
                  ->prune_write_epochs_older_than(EpochNumber::ApplicationTraffic_0 + 1);

               result.test_throws<TLS_Exception>(
                  "no write epoch for pruned epoch number", "No write epoch found for requested epoch number", [&] {
                     secure_vector<uint8_t> wire;
                     protect(*peers.client,
                             Record_Type::ApplicationData,
                             plaintext,
                             wire,
                             0,
                             EpochNumber::ApplicationTraffic_0);
                  });

               // the current epoch is not affected by the pruning
               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0 + 1,
                               0);
            }),
   };
}

std::vector<Test::Result> invalid_records() {
   return {
      CHECK("tampered records are silently discarded",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               secure_vector<uint8_t> wire;
               protect(*peers.client, Record_Type::ApplicationData, plaintext, wire);

               // RFC 9147 Section 4.5.2
               //    Unlike TLS, DTLS is resilient in the face of invalid
               //    records [...]. In general, invalid records SHOULD be
               //    silently discarded [...].
               auto tampered_ciphertext = wire;
               tampered_ciphertext.back() ^= 0x01;
               result.test_opt_is_null("tampered ciphertext was discarded",
                                       deprotect(*peers.server, tampered_ciphertext));

               // the masked sequence number hint is part of the associated data
               auto tampered_hint = parse_header(wire);
               tampered_hint.sequence_number = std::visit(
                  [](const auto seqno) -> SequenceNumberHint { return static_cast<decltype(seqno)>(seqno ^ 0x01); },
                  tampered_hint.sequence_number);
               result.test_opt_is_null("tampered header was discarded",
                                       deprotect(*peers.server, remarshall_with_header(tampered_hint, wire)));

               // epoch bits that match no known epoch (e.g. early traffic)
               auto unknown_epoch = parse_header(wire);
               unknown_epoch.epoch_bits = 0b01;
               result.test_opt_is_null("record with unknown epoch was discarded",
                                       deprotect(*peers.server, remarshall_with_header(unknown_epoch, wire)));

               // the failed attempts must not poison the cipher state
               result.test_opt_not_null("untampered record was deprotected", deprotect(*peers.server, wire));

               check_roundtrip(result,
                               *peers.client,
                               *peers.server,
                               Record_Type::ApplicationData,
                               plaintext,
                               EpochNumber::ApplicationTraffic_0,
                               1);
            }),

      CHECK("authenticated records with disallowed content types are rejected",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

               // RFC 9147 Section 4.1 Figure 5: ChangeCipherSpec (20) is not a
               // valid content type for protected DTLS 1.3 records
               secure_vector<uint8_t> ccs_wire;
               protect(*peers.client, Record_Type::ChangeCipherSpec, plaintext, ccs_wire);
               result.test_throws<TLS_Exception>("unexpected content type",
                                                 "Deprotected DTLS record had unexpected content type: 20",
                                                 [&] { deprotect(*peers.server, ccs_wire); });

               // RFC 9147 Section 6.1: application data must not appear in the
               // handshake epoch
               secure_vector<uint8_t> interleaved_wire;
               protect(*peers.client,
                       Record_Type::ApplicationData,
                       plaintext,
                       interleaved_wire,
                       0,
                       EpochNumber::HandshakeTraffic);
               result.test_throws<TLS_Exception>("application data in handshake epoch",
                                                 "Can't interleave application and handshake data",
                                                 [&] { deprotect(*peers.server, interleaved_wire); });
            }),
   };
}

std::vector<Test::Result> record_padding() {
   return {
      CHECK("short records are padded to the minimum ciphertext size",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_CCM_8_SHA256").value());
               peers.advance_to_application_traffic();

               const std::span<const uint8_t> empty_payload;

               secure_vector<uint8_t> wire;
               protect(*peers.client, Record_Type::ApplicationData, empty_payload, wire);
               result.test_sz_eq(
                  "ciphertext was padded to 16 bytes", wire.size() - parse_header(wire).serialized_byte_length(), 16);

               auto record = deprotect(*peers.server, wire);
               result.test_opt_not_null("record was deprotected", record);
               if(record.has_value()) {
                  const auto& content = record_content(*record);
                  result.test_enum_eq("deprotected record type", content.type, Record_Type::ApplicationData);
                  result.test_is_true("deprotected payload is empty", content.payload.empty());
               }
            }),

      CHECK("explicitly padded records round trip",
            [&](Test::Result& result) {
               auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());
               peers.advance_to_application_traffic();

               const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls" (10 bytes)

               secure_vector<uint8_t> wire;
               protect(*peers.client, Record_Type::ApplicationData, plaintext, wire, 64 /* padding bytes */);

               // 10 content bytes + 1 type byte + 64 padding bytes + 16 tag bytes
               result.test_sz_eq(
                  "ciphertext size", wire.size() - parse_header(wire).serialized_byte_length(), 10 + 1 + 64 + 16);

               auto record = deprotect(*peers.server, wire);
               result.test_opt_not_null("record was deprotected", record);
               if(record.has_value()) {
                  result.test_bin_eq("deprotected payload without padding", record_content(*record).payload, plaintext);
               }
            }),
   };
}

std::vector<Test::Result> clearing_keys() {
   return {
      CHECK(
         "protect and deprotect fail after clearing the respective keys",
         [&](Test::Result& result) {
            auto peers = DTLS_Peers::make(Ciphersuite::from_name("AES_128_GCM_SHA256").value());

            const auto plaintext = hex_decode_locked("68656c6c6f2064746c73");  // "hello dtls"

            result.test_is_true("cryptographic association established", peers.client->has_cryptographic_association());
            result.test_is_true("cryptographic association established", peers.server->has_cryptographic_association());

            secure_vector<uint8_t> wire;
            protect(*peers.client, Record_Type::Handshake, plaintext, wire);

            peers.server->clear_read_keys();
            result.test_is_false("no cryptographic association", peers.server->has_cryptographic_association());
            result.test_throws("deprotect without read keys", [&] { deprotect(*peers.server, wire); });

            peers.client->clear_write_keys();
            result.test_is_false("no cryptographic association", peers.client->has_cryptographic_association());
            result.test_throws("protect without write keys", [&] {
               secure_vector<uint8_t> w;
               protect(*peers.client, Record_Type::Handshake, plaintext, w);
            });
         }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls",
                       "dtls_cipher_state",
                       update_cipher_state,
                       record_number_handling,
                       epoch_transitions,
                       epoch_pruning,
                       invalid_records,
                       record_padding,
                       clearing_keys);

}  // namespace Botan_Tests

#endif
