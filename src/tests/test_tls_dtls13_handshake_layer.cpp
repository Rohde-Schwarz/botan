/*
* (C) 2026 Jack Lloyd
* (C) 2026 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DTLS_13)
   #include <numeric>

   #include <botan/hex.h>
   #include <botan/tls.h>

   #include <botan/internal/buffer_slicer.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/tls_handshake_layer_13.h>
   #include <botan/internal/tls_handshake_layer_dtls13.h>
   #include <botan/internal/tls_transcript_hash_13.h>

namespace TLS = Botan::TLS;

namespace Botan_Tests {

namespace {

using CopyDataResult = TLS::Handshake_Layer::CopyDataResult;

std::unique_ptr<TLS::DTLS_Handshake_Layer> make_handshake_layer(TLS::Connection_Side side) {
   return std::make_unique<TLS::DTLS_Handshake_Layer>(side);
}

TLS::Handshake_Record handshake_record(std::span<const uint8_t> bytes,
                                       TLS::EpochNumber epoch = TLS::EpochNumber::HandshakeTraffic) {
   return TLS::Handshake_Record{{
      .type = TLS::Record_Type::Handshake,
      .sequence_number = std::nullopt,
      .payload = Botan::secure_vector<uint8_t>(bytes.begin(), bytes.end()),
      .epoch = epoch,
   }};
}

std::vector<uint8_t> concat_fragments(Test::Result& result,
                                      std::span<const TLS::MarshalledHandshakeMessageFragment> fragments) {
   std::vector<uint8_t> msg;
   for(const auto& fragment : fragments) {
      result.require("fragment has a header", fragment.size() > 12);
      msg.insert(msg.end(), fragment.begin() + 12 /* skip header */, fragment.end());
   }
   return msg;
}

/**
 * @returns bytes of a full DTLS client hello record without fragmentation
 */
std::vector<uint8_t> client_hello_record_bytes() {
   return Botan::hex_decode(  // from wolfssl
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
}

/**
 * @returns bytes of a full DTLS encrypted extensions message (without headers)
 */
std::vector<uint8_t> client_finished_bare_bytes() {
   return Botan::hex_decode(
      "a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa"
      "c6 e9 85 27 b6 42 f2 ed d5 ce 61");
}

/**
 * @returns bytes of a client Certificate message with an empty certificate
 *          list (i.e. a client without credentials, RFC 8446 4.4.2)
 */
std::vector<uint8_t> client_certificate_bare_bytes() {
   return {0x00 /* empty request context */, 0x00, 0x00, 0x00 /* empty certificate list */};
}

/**
 * @returns bytes of a CertificateVerify message (ecdsa_secp256r1_sha256 with an
 *          empty -- hence invalid -- signature; parsing does not verify it)
 */
std::vector<uint8_t> certificate_verify_bare_bytes() {
   return {0x04, 0x03 /* ecdsa_secp256r1_sha256 */, 0x00, 0x00 /* empty signature */};
}

/**
 * @returns bytes of a minimal NewSessionTicket message (RFC 8446 4.6.1)
 */
std::vector<uint8_t> new_session_ticket_bare_bytes() {
   return Botan::hex_decode(
      "00 00 0e 10"  // ticket_lifetime: 3600 seconds
      "00 00 00 00"  // ticket_age_add
      "00"           // empty ticket_nonce
      "00 01 aa"     // ticket: 1 byte
      "00 00");      // no extensions
}

/**
 * @returns bytes of a full DTLS client hello message with handshake protocol
 *          header without fragmentation
 */
std::vector<uint8_t> client_hello_marshalled_bytes() {
   const auto client_hello_record = client_hello_record_bytes();
   const auto client_hello_bytes = std::span{client_hello_record}.subspan(13 /* record header */);
   return {client_hello_bytes.begin(), client_hello_bytes.end()};
}

/**
 * @returns bytes of a full DTLS client hello message
 */
std::vector<uint8_t> client_hello_bare_bytes() {
   const auto client_hello_record = client_hello_record_bytes();
   const auto bare_client_hello_bytes =
      std::span{client_hello_record}.subspan(13 /* record header */ + 12 /* HS msg header */);
   return {bare_client_hello_bytes.begin(), bare_client_hello_bytes.end()};
}

/**
 * @returns a DTLS ClientHello object
 */
TLS::Client_Hello_13 client_hello() {
   return std::get<TLS::Client_Hello_13>(TLS::Client_Hello_13::parse(client_hello_bare_bytes()));
}

/**
 * @returns the bytes of a SHA-256 transcript hash of client_hello()
*/
std::vector<uint8_t> client_hello_transcript_hash() {
   return Botan::hex_decode("2AABAE13B1D3CC208A6E37F3B91B46C101DD1B96E0731A04DC379A79186C86CF");
}

/**
 * Frames a single DTLS handshake message fragment (RFC 9147 5.2) by prepending
 * the msg_type/length/message_seq/fragment_offset/fragment_length header.
 */
std::vector<uint8_t> dtls_marshall_fragment(TLS::Handshake_Type type,
                                            size_t total_len,
                                            uint16_t msg_seq,
                                            size_t frag_offset,
                                            std::span<const uint8_t> fragment) {
   auto store_be24 = [](uint32_t value) {
      BOTAN_ASSERT_NOMSG(value <= 0xFFFFFF);
      const auto be = Botan::store_be(value);
      std::array<uint8_t, 3> result{};
      Botan::copy_mem(result, std::span{be}.last<3>());
      return result;
   };

   return Botan::concat<std::vector<uint8_t>>(  //
      Botan::store_be(type),
      store_be24(static_cast<uint32_t>(total_len)),
      Botan::store_be(msg_seq),
      store_be24(static_cast<uint32_t>(frag_offset)),
      store_be24(static_cast<uint32_t>(fragment.size())),
      fragment);
}

/**
 * One slice of a handshake message, to be wrapped into an individual DTLS
 * handshake fragment (see dtls_marshall_fragment()).
 */
struct Fragment_Piece {
      size_t offset;
      std::span<const uint8_t> bytes;
};

/**
 * Splits @p message into consecutive, non-overlapping pieces of the given
 * @p sizes (which must sum up to message.size()). The resulting pieces span into the original message,
 * so the caller must ensure that the original message remains valid for the lifetime of the pieces.
 */
std::vector<Fragment_Piece> split_into_pieces(std::span<const uint8_t> message, std::span<const size_t> sizes) {
   BOTAN_ASSERT_NOMSG(std::accumulate(sizes.begin(), sizes.end(), size_t{0}) == message.size());
   std::vector<Fragment_Piece> pieces;
   pieces.reserve(sizes.size());

   Botan::BufferSlicer bs(message);
   while(!bs.empty() && pieces.size() < sizes.size()) {
      const auto offset = message.size() - bs.remaining();
      const auto bytes_in_this_piece = std::min(bs.remaining(), sizes[pieces.size()]);
      pieces.emplace_back(Fragment_Piece{offset, bs.take(bytes_in_this_piece)});
   }

   BOTAN_ASSERT_NOMSG(pieces.size() == sizes.size());
   return pieces;
}

/**
 * @returns @p count roughly equally sized pieces covering @p total bytes
 *          (the remainder is added to the last piece)
 */
std::vector<size_t> equal_sizes(size_t total, size_t count) {
   std::vector<size_t> sizes(count, total / count);
   sizes.back() += total - (total / count) * count;
   return sizes;
}

std::vector<Test::Result> basic() {
   const auto default_policy = TLS::Policy();

   return {
      CHECK("read ClientHello",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto transcript_hash = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);
               result.require("successful ingestion",
                              hl->copy_data(default_policy, handshake_record(client_hello_marshalled_bytes())) ==
                                 CopyDataResult::Consumed);
               auto msg = hl->next_message(default_policy, transcript_hash);
               result.require("received something", msg.has_value());
               result.test_u64_eq("message index is 0", msg->index(), 0);
               result.require("message is ClientHello", std::holds_alternative<TLS::Client_Hello_13>(msg.value()));

               result.test_bin_eq("received handshake message",
                                  std::get<TLS::Client_Hello_13>(msg.value()).serialize(),
                                  client_hello_bare_bytes());

               transcript_hash.set_algorithm("SHA-256");
               result.test_bin_eq("transcript hash", transcript_hash.current(), client_hello_transcript_hash());

               result.test_opt_is_null("no more records", hl->next_message(default_policy, transcript_hash));
            }),

      CHECK("prepare ClientHello",
            [&](Test::Result& result) {
               auto hello = client_hello();
               auto hl = make_handshake_layer(TLS::Connection_Side::Client);

               // Creating a fresh handshake layer message for the TLS ClientHello should result in the
               // same bytes as the handshake msg header in client_hello_record
               result.test_bin_eq(
                  "reproduces wire message",
                  hl->fragment_message(
                     hello.wire_type(), TLS::Handshake_Layer::serialize(hello), TLS::MAX_PLAINTEXT_SIZE)[0],
                  client_hello_marshalled_bytes());
            }),

      CHECK("prepare ClientHello with fragmentation",
            [&](Test::Result& result) {
               auto hello = client_hello();
               auto hl = make_handshake_layer(TLS::Connection_Side::Client);

               // Force fragmentation into two or more fragments
               const size_t fragment_size = client_hello_bare_bytes().size() / 2;

               // Creating a fresh handshake layer message for the TLS ClientHello should result in the
               // same bytes as the handshake msg header in client_hello_record
               const auto fragments = hl->fragment_message(
                  hello.wire_type(), TLS::Handshake_Layer::serialize(hello), static_cast<uint16_t>(fragment_size));
               result.test_is_true("fragmented", fragments.size() > 1);

               result.test_bin_eq(
                  "reproduces full message", concat_fragments(result, fragments), client_hello_bare_bytes());

               // The first fragment can be capped individually, e.g. to fill up a
               // record that already holds fragments of previous messages.
               constexpr uint16_t first_fragment_size = 64;
               const auto capped_fragments = hl->fragment_message(hello.wire_type(),
                                                                  TLS::Handshake_Layer::serialize(hello),
                                                                  static_cast<uint16_t>(fragment_size),
                                                                  first_fragment_size);
               result.test_is_true("fragmented", capped_fragments.size() > 1);
               result.test_sz_eq(
                  "first fragment respects its individual cap", capped_fragments.front().size(), first_fragment_size);
               result.test_sz_eq("second fragment uses the full budget", capped_fragments[1].size(), fragment_size);
               result.test_bin_eq(
                  "reproduces full message", concat_fragments(result, capped_fragments), client_hello_bare_bytes());

               result.test_throws("first fragment cap must not exceed the general cap", [&] {
                  static_cast<void>(hl->fragment_message(hello.wire_type(),
                                                         TLS::Handshake_Layer::serialize(hello),
                                                         first_fragment_size,
                                                         static_cast<uint16_t>(fragment_size)));
               });

               result.test_throws("fragment size must exceed the fragment header length", [&] {
                  static_cast<void>(hl->fragment_message(hello.wire_type(),
                                                         TLS::Handshake_Layer::serialize(hello),
                                                         TLS::DTLS_Handshake_Layer::FRAGMENT_HEADER_LENGTH));
               });
            }),

      CHECK("parse ClientHello with fragmentation",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               // Split the ClientHello into two fragments
               const auto client_hello_bytes = client_hello_bare_bytes();
               const size_t fragment_size = client_hello_bytes.size() / 2;

               // Prepend HS headers
               const auto first_fragment_framed =
                  dtls_marshall_fragment(TLS::Handshake_Type::ClientHello,
                                         client_hello_bytes.size(),
                                         0 /* msg_seq */,
                                         0 /*frag_offset */,
                                         std::span{client_hello_bytes}.subspan(0, fragment_size));
               const auto second_fragment_framed =
                  dtls_marshall_fragment(TLS::Handshake_Type::ClientHello,
                                         client_hello_bytes.size(),
                                         0 /* msg_seq */,
                                         fragment_size /*frag_offset */,
                                         std::span{client_hello_bytes}.subspan(fragment_size));

               result.require(
                  "successful ingestion",
                  hl->copy_data(default_policy, handshake_record(first_fragment_framed)) == CopyDataResult::Consumed);
               result.test_opt_is_null("needs more bytes", hl->next_message(default_policy, th));
               result.test_is_true("holds pending message data", hl->has_pending_data());

               result.require(
                  "successful ingestion",
                  hl->copy_data(default_policy, handshake_record(second_fragment_framed)) == CopyDataResult::Consumed);
               auto msg = hl->next_message(default_policy, th);
               result.require("received something", msg.has_value());
               result.require("message is ClientHello", std::holds_alternative<TLS::Client_Hello_13>(msg.value()));

               result.test_bin_eq("received handshake message",
                                  std::get<TLS::Client_Hello_13>(msg.value()).serialize(),
                                  client_hello_bare_bytes());

               th.set_algorithm("SHA-256");
               result.test_bin_eq("transcript hash", th.current(), client_hello_transcript_hash());

               result.test_opt_is_null("no more records", hl->next_message(default_policy, th));
            }),

      CHECK("Messages are emitted in order of their sequence number",
            [&](Test::Result& result) {
               const auto ch = client_hello_bare_bytes();
               const auto cc = client_certificate_bare_bytes();
               const auto cv = certificate_verify_bare_bytes();
               const auto cf = client_finished_bare_bytes();

               constexpr uint16_t window = TLS::DTLS_Handshake_Layer::MAX_BUFFERED_FUTURE_MESSAGES;
               auto marshalled_finished = [&](uint16_t seqno) {
                  return dtls_marshall_fragment(TLS::Handshake_Type::Finished, cf.size(), seqno, 0, cf);
               };
               auto marshalled_client_hello = [&](uint16_t seqno) {
                  return dtls_marshall_fragment(TLS::Handshake_Type::ClientHello, ch.size(), seqno, 0, ch);
               };

               // Buffering window semantics for out-of-order messages. Messages
               // too far in the future are discarded right away, messages within
               // the window are buffered for reassembly (RFC 9147 5.2).
               //
               // The messages buffered here are deliberately never pulled: they
               // could only be emitted after a ClientHello or Finished, both of
               // which must be the final pending message when pulled because they
               // may immediately precede a key change (RFC 9846 5.1).
               {
                  auto hl = make_handshake_layer(TLS::Connection_Side::Server);
                  auto transcript_hash = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

                  result.test_enum_eq("message beyond the buffering window is discarded",
                                      hl->copy_data(default_policy, handshake_record(marshalled_finished(window + 1))),
                                      CopyDataResult::Discarded);
                  result.test_enum_eq("message at the edge of the buffering window is buffered",
                                      hl->copy_data(default_policy, handshake_record(marshalled_finished(window))),
                                      CopyDataResult::Consumed);

                  // A record that mixes a bufferable fragment with one beyond the
                  // window is consumed partially.
                  const auto mixed_record =
                     Botan::concat<std::vector<uint8_t>>(marshalled_client_hello(1), marshalled_finished(window + 1));
                  result.test_enum_eq("record with discarded and buffered fragments is consumed partially",
                                      hl->copy_data(default_policy, handshake_record(mixed_record)),
                                      CopyDataResult::ConsumedPartially);

                  // Nothing is emitted as long as the start of the sequence space
                  // is missing.
                  result.test_opt_is_null("no message to read yet", hl->next_message(default_policy, transcript_hash));
               }

               // Messages are emitted in order of their sequence number. Each
               // ClientHello and the final Finished are pulled without further
               // pending data, as they must align with a record boundary
               // (RFC 9846 5.1).
               {
                  auto hl = make_handshake_layer(TLS::Connection_Side::Server);
                  auto transcript_hash = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

                  result.require("successful ingestion of seqno 0",
                                 hl->copy_data(default_policy, handshake_record(marshalled_client_hello(0))) ==
                                    CopyDataResult::Consumed);
                  result.test_is_true("received message 0",
                                      std::holds_alternative<TLS::Client_Hello_13>(
                                         hl->next_message(default_policy, transcript_hash).value()));

                  // The second ClientHello (seqno 1) reflects the HelloRetryRequest
                  // case (RFC 8446 4.1.4).
                  result.require("successful ingestion of seqno 1",
                                 hl->copy_data(default_policy, handshake_record(marshalled_client_hello(1))) ==
                                    CopyDataResult::Consumed);
                  result.test_is_true("received message 1",
                                      std::holds_alternative<TLS::Client_Hello_13>(
                                         hl->next_message(default_policy, transcript_hash).value()));

                  // Buffer the Finished message that will complete the client
                  // authentication flight Certificate(2), CertificateVerify(3),
                  // Finished(4) further down (RFC 8446 4.4).
                  result.test_enum_eq("Finished of the client authentication flight is buffered",
                                      hl->copy_data(default_policy, handshake_record(marshalled_finished(4))),
                                      CopyDataResult::Consumed);

                  // The buffered Finished cannot be emitted before the gap in the
                  // sequence space is filled.
                  result.test_opt_is_null("buffered future message is not emitted out of order",
                                          hl->next_message(default_policy, transcript_hash));

                  result.test_enum_eq(
                     "successful ingestion of Certificate",
                     hl->copy_data(default_policy,
                                   handshake_record(dtls_marshall_fragment(
                                      TLS::Handshake_Type::Certificate, cc.size(), 2 /* seqno */, 0, cc))),
                     CopyDataResult::Consumed);
                  result.test_enum_eq(
                     "successful ingestion of CertificateVerify",
                     hl->copy_data(default_policy,
                                   handshake_record(dtls_marshall_fragment(
                                      TLS::Handshake_Type::CertificateVerify, cv.size(), 3 /* seqno */, 0, cv))),
                     CopyDataResult::Consumed);

                  // The buffered messages are emitted in order of their sequence
                  // numbers, ending with the Finished buffered further up. Because
                  // the gap fillers use different message types, the final message
                  // is provably the originally buffered one.
                  result.test_is_true("received message 2",
                                      std::holds_alternative<TLS::Certificate_13>(
                                         hl->next_message(default_policy, transcript_hash).value()));
                  result.test_is_true("received message 3",
                                      std::holds_alternative<TLS::Certificate_Verify_13>(
                                         hl->next_message(default_policy, transcript_hash).value()));
                  result.test_is_true("originally buffered Finished is emitted last",
                                      std::holds_alternative<TLS::Finished_13>(
                                         hl->next_message(default_policy, transcript_hash).value()));

                  result.test_opt_is_null("no more messages", hl->next_message(default_policy, transcript_hash));
               }
            }),
   };
}

std::vector<Test::Result> fragmentation() {
   const auto default_policy = TLS::Policy();
   const auto type = TLS::Handshake_Type::ClientHello;
   constexpr uint16_t msg_seq = 0;

   auto verify_client_hello =
      [](Test::Result& result, const std::optional<TLS::Handshake_Message_13>& msg, TLS::Transcript_Hash_State& th) {
         result.require("received something", msg.has_value());
         th.set_algorithm("SHA-256");
         result.test_bin_eq("transcript hash", th.current(), client_hello_transcript_hash());
         result.require("message is ClientHello", std::holds_alternative<TLS::Client_Hello_13>(msg.value()));
         result.test_bin_eq("received handshake message",
                            std::get<TLS::Client_Hello_13>(msg.value()).serialize(),
                            client_hello_bare_bytes());
      };

   return {
      CHECK("parse ClientHello reassembled from many small fragments",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();
               const auto pieces = split_into_pieces(message, equal_sizes(message.size(), 31));

               std::optional<TLS::Handshake_Message_13> msg;
               for(size_t i = 0; i < pieces.size(); ++i) {
                  result.require("successful ingestion",
                                 hl->copy_data(default_policy,
                                               handshake_record(dtls_marshall_fragment(
                                                  type, message.size(), msg_seq, pieces[i].offset, pieces[i].bytes))) ==
                                    CopyDataResult::Consumed);
                  msg = hl->next_message(default_policy, th);
                  const bool is_last = (i + 1 == pieces.size());
                  result.test_is_true(is_last ? "complete after last fragment" : "still incomplete",
                                      msg.has_value() == is_last);
               }

               verify_client_hello(result, msg, th);
            }),

      CHECK("parse ClientHello with multiple fragments in a single record",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();
               const auto pieces = split_into_pieces(message, equal_sizes(message.size(), 31));

               const auto record_with_multiple_fragments = [&]() {
                  std::vector<uint8_t> record;
                  for(const auto& piece : pieces) {
                     const auto fragment =
                        dtls_marshall_fragment(type, message.size(), msg_seq, piece.offset, piece.bytes);
                     record.insert(record.end(), fragment.begin(), fragment.end());
                  }
                  return record;
               }();

               result.require("successful ingestion",
                              hl->copy_data(default_policy, handshake_record(record_with_multiple_fragments)) ==
                                 CopyDataResult::Consumed);

               verify_client_hello(result, hl->next_message(default_policy, th), th);
            }),

      CHECK("parse ClientHello reassembled from unevenly sized fragments",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();
               const size_t a = message.size() / 10;
               const size_t b = message.size() / 3;
               const size_t c = message.size() / 20 + 1;
               const size_t d = message.size() - a - b - c;
               const auto pieces = split_into_pieces(message, std::array{a, b, c, d});

               for(const auto& piece : pieces) {
                  result.require("successful ingestion",
                                 hl->copy_data(default_policy,
                                               handshake_record(dtls_marshall_fragment(
                                                  type, message.size(), msg_seq, piece.offset, piece.bytes))) ==
                                    CopyDataResult::Consumed);
               }

               auto msg = hl->next_message(default_policy, th);

               verify_client_hello(result, msg, th);
            }),

      CHECK("parse ClientHello reassembled from fragments delivered out of order",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();
               const auto pieces = split_into_pieces(message, equal_sizes(message.size(), 4));

               // deliberately not in ascending offset order
               const auto delivery_order = std::array{2, 0, 3, 1};
               result.require("delivery order matches pieces", delivery_order.size() == pieces.size());

               std::optional<TLS::Handshake_Message_13> msg;
               for(size_t i = 0; i < delivery_order.size(); ++i) {
                  const auto& piece = pieces[delivery_order[i]];
                  result.require("successful ingestion",
                                 hl->copy_data(default_policy,
                                               handshake_record(dtls_marshall_fragment(
                                                  type, message.size(), msg_seq, piece.offset, piece.bytes))) ==
                                    CopyDataResult::Consumed);
                  msg = hl->next_message(default_policy, th);
                  const bool is_last = (i + 1 == delivery_order.size());
                  result.test_is_true(is_last ? "complete after last fragment" : "still incomplete",
                                      msg.has_value() == is_last);
               }

               verify_client_hello(result, msg, th);
            }),

      CHECK("parse ClientHello reassembled from overlapping fragments",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();
               const size_t mid = message.size() / 2;
               const size_t overlap = 20;
               result.require("overlap smaller than half the message", overlap + mid < message.size());

               // first fragment: [0, mid + overlap)
               // second fragment: [mid, message.size())
               // -> bytes [mid, mid + overlap) are covered by both fragments with identical content
               const auto first_span = std::span{message}.first(mid + overlap);
               const auto second_span = std::span{message}.subspan(mid);

               result.require(
                  "successful ingestion",
                  hl->copy_data(default_policy,
                                handshake_record(dtls_marshall_fragment(
                                   type, message.size(), msg_seq, 0, first_span))) == CopyDataResult::Consumed);
               result.test_opt_is_null("still incomplete", hl->next_message(default_policy, th));

               result.require(
                  "successful ingestion",
                  hl->copy_data(default_policy,
                                handshake_record(dtls_marshall_fragment(
                                   type, message.size(), msg_seq, mid, second_span))) == CopyDataResult::Consumed);

               auto msg = hl->next_message(default_policy, th);

               verify_client_hello(result, msg, th);
            }),

      CHECK("parse ClientHello stays incomplete when fragments leave a gap",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();
               const size_t gap_start = message.size() / 3;
               const size_t gap_end = 2 * message.size() / 3;
               result.require("gap smaller than message", gap_start < gap_end && gap_end < message.size());
               result.require("gap is not empty", gap_start + 1 < gap_end);

               // fragment covering [0, gap_start) and [gap_end, message.size()), leaving
               // [gap_start, gap_end) unfilled
               const auto before_gap = std::span{message}.first(gap_start);
               const auto after_gap = std::span{message}.subspan(gap_end);

               result.require(
                  "successful ingestion 1",
                  hl->copy_data(default_policy,
                                handshake_record(dtls_marshall_fragment(
                                   type, message.size(), msg_seq, 0, before_gap))) == CopyDataResult::Consumed);
               result.require(
                  "successful ingestion 2",
                  hl->copy_data(default_policy,
                                handshake_record(dtls_marshall_fragment(
                                   type, message.size(), msg_seq, gap_end, after_gap))) == CopyDataResult::Consumed);

               result.test_opt_is_null("message never completes due to the gap", hl->next_message(default_policy, th));
            }),

      CHECK("parse ClientHello detects an invalid oversized fragment",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();

               // a fragment whose offset + length overflows the declared total message length
               const std::vector<uint8_t> bogus_payload(50, 0x41);
               result.test_throws("bogus data is rejected", [&] {
                  std::ignore = hl->copy_data(default_policy,
                                              handshake_record(dtls_marshall_fragment(
                                                 type, message.size(), msg_seq, message.size() - 1, bogus_payload)));
               });
               result.test_opt_is_null("bogus fragment does not complete the message",
                                       hl->next_message(default_policy, th));

               // sending all the valid fragments afterwards should still reassemble correctly
               const auto pieces = split_into_pieces(message, equal_sizes(message.size(), 3));
               result.require("at least two pieces", pieces.size() >= 2);
               result.require("successful ingestion",
                              hl->copy_data(default_policy,
                                            handshake_record(dtls_marshall_fragment(
                                               type, message.size(), msg_seq, pieces[0].offset, pieces[0].bytes))) ==
                                 CopyDataResult::Consumed);

               // fragments whose header values disagree with the pending
               // reassembly (total length, message type) are rejected
               result.test_throws("inconsistent total message length is rejected", [&] {
                  std::ignore =
                     hl->copy_data(default_policy,
                                   handshake_record(dtls_marshall_fragment(
                                      type, message.size() + 1, msg_seq, pieces[1].offset, pieces[1].bytes)));
               });
               result.test_throws("inconsistent message type is rejected", [&] {
                  std::ignore = hl->copy_data(
                     default_policy,
                     handshake_record(dtls_marshall_fragment(
                        TLS::Handshake_Type::Finished, message.size(), msg_seq, pieces[1].offset, pieces[1].bytes)));
               });

               // fragments of one message must not span multiple record epochs
               result.test_throws("fragments spanning multiple epochs are rejected", [&] {
                  std::ignore = hl->copy_data(
                     default_policy,
                     handshake_record(
                        dtls_marshall_fragment(type, message.size(), msg_seq, pieces[1].offset, pieces[1].bytes),
                        TLS::EpochNumber::ApplicationTraffic_0));
               });

               // the pending reassembly is unharmed by the rejected fragments
               for(size_t i = 1; i < pieces.size(); ++i) {
                  result.require("successful ingestion",
                                 hl->copy_data(default_policy,
                                               handshake_record(dtls_marshall_fragment(
                                                  type, message.size(), msg_seq, pieces[i].offset, pieces[i].bytes))) ==
                                    CopyDataResult::Consumed);
               }

               auto msg = hl->next_message(default_policy, th);

               verify_client_hello(result, msg, th);
            }),

      CHECK("parse ClientHello detects incoming garbage data with invalid message type",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();

               // This resembles a fragment with a message length of 0 (which is allowed),
               // but the message type is invalid (0x00 does not exist in (D)TLS 1.3). The
               // message should be rejected because of the invalid message type, but the
               // rest of the fragment is in fact valid.
               const std::array<uint8_t, 12> garbage{0x00 /* msg type: 0x00 does not exist! */};
               result.test_throws("invalid message type is detected",
                                  [&] { std::ignore = hl->copy_data(default_policy, handshake_record(garbage)); });
               result.test_opt_is_null("bogus fragment does not complete the message",
                                       hl->next_message(default_policy, th));

               // sending all the valid fragments afterwards should still reassemble correctly
               const auto pieces = split_into_pieces(message, equal_sizes(message.size(), 3));
               for(const auto& piece : pieces) {
                  result.test_enum_eq("successful ingestion",
                                      hl->copy_data(default_policy,
                                                    handshake_record(dtls_marshall_fragment(
                                                       type, message.size(), msg_seq, piece.offset, piece.bytes))),
                                      CopyDataResult::Consumed);
               }

               verify_client_hello(result, hl->next_message(default_policy, th), th);
            }),

      CHECK("parse ClientHello detects incoming garbage data with valid message type",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               // A fragment whose message type is correct (ClientHello) but that
               // declares a zero-length message. copy_data() happily buffers it
               // (an empty message is immediately "complete"), and the bogus
               // content is only detected when parsing the message.
               //
               // TODO: The bogus message should ideally be detected and rejected
               //       already in copy_data(). Also, the unparsable message
               //       remains in the reassembly buffer after the failed parse,
               //       i.e. the handshake layer is wedged from this point on.
               const std::array<uint8_t, 12> garbage{0x01 /* msg type: 0x01 -  Client Hello! */};
               result.test_enum_eq("garbage is buffered like any other fragment",
                                   hl->copy_data(default_policy, handshake_record(garbage)),
                                   CopyDataResult::Consumed);
               result.test_throws("bogus message is detected at parse time",
                                  [&] { static_cast<void>(hl->next_message(default_policy, th)); });
            }),

      CHECK("parse ClientHello detects incoming short garbage data",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto th = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto message = client_hello_bare_bytes();

               // a fragment whose message type is correct but it is too short to be a valid message
               const std::array<uint8_t, 5> garbage{0x01 /* msg type: 0x01 -  Client Hello! */};
               result.test_throws("detects garbage",
                                  [&] { static_cast<void>(hl->copy_data(default_policy, handshake_record(garbage))); });
               result.test_opt_is_null("bogus fragment does not complete the message",
                                       hl->next_message(default_policy, th));

               // sending all the valid fragments afterwards should still reassemble correctly
               const auto pieces = split_into_pieces(message, equal_sizes(message.size(), 3));
               for(const auto& piece : pieces) {
                  result.require("successful ingestion",
                                 hl->copy_data(default_policy,
                                               handshake_record(dtls_marshall_fragment(
                                                  type, message.size(), msg_seq, piece.offset, piece.bytes))) ==
                                    CopyDataResult::Consumed);
               }

               verify_client_hello(result, hl->next_message(default_policy, th), th);
            }),

      CHECK("Fragmentation round-trip",
            [&](Test::Result& result) {
               auto hl_client = make_handshake_layer(TLS::Connection_Side::Client);
               auto hello = client_hello();

               const auto message = client_hello_bare_bytes();
               const uint16_t fragment_size = static_cast<uint16_t>(message.size() / 3);

               const auto fragments =
                  hl_client->fragment_message(hello.wire_type(), TLS::Handshake_Layer::serialize(hello), fragment_size);
               result.test_is_true("fragmented", fragments.size() > 1);

               // feed the fragments back into a new handshake layer and check that the original message is reassembled
               auto hl_server = make_handshake_layer(TLS::Connection_Side::Server);
               auto th_server = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);
               for(const auto& fragment : fragments) {
                  result.require("successful ingestion",
                                 hl_server->copy_data(default_policy, handshake_record(fragment.get())) ==
                                    CopyDataResult::Consumed);
               }

               auto msg = hl_server->next_message(default_policy, th_server);

               verify_client_hello(result, msg, th_server);
            }),

      CHECK("(Retransmitted) fragments of historic messages should be dropped",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Server);
               auto transcript_hash = TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);

               const auto ch = client_hello_bare_bytes();

               result.require("successful ingestion of seqno 0",
                              hl->copy_data(default_policy,
                                            handshake_record(dtls_marshall_fragment(
                                               TLS::Handshake_Type::ClientHello, ch.size(), 0 /* seqno */, 0, ch))) ==
                                 CopyDataResult::Consumed);
               verify_client_hello(result, hl->next_message(default_policy, transcript_hash), transcript_hash);

               result.test_enum_eq(
                  "retransmission of Client Hello is dropped",
                  hl->copy_data(default_policy,
                                handshake_record(dtls_marshall_fragment(
                                   TLS::Handshake_Type::ClientHello, ch.size(), 0 /* seqno */, 0, ch))),
                  CopyDataResult::DiscardedDuplicate);
               result.test_opt_is_null("no more messages", hl->next_message(default_policy, transcript_hash));
            }),
   };
}

std::vector<Test::Result> post_handshake() {
   const auto default_policy = TLS::Policy();

   auto marshalled_key_update = [](uint16_t msg_seq, bool request_peer_update) {
      const std::array<uint8_t, 1> body{static_cast<uint8_t>(request_peer_update ? 0x01 : 0x00)};
      return dtls_marshall_fragment(TLS::Handshake_Type::KeyUpdate, body.size(), msg_seq, 0, body);
   };

   return {
      CHECK("Key_Update messages are parsed",
            [&](Test::Result& result) {
               auto client = make_handshake_layer(TLS::Connection_Side::Client);
               auto server = make_handshake_layer(TLS::Connection_Side::Server);

               // send a Key_Update through the fragmenting send path
               const auto fragments = client->fragment_message(TLS::Handshake_Type::KeyUpdate,
                                                               TLS::Handshake_Layer::serialize(TLS::Key_Update(false)),
                                                               TLS::MAX_PLAINTEXT_SIZE);
               result.test_sz_eq("Key_Update fits into a single fragment", fragments.size(), 1);

               result.test_enum_eq(
                  "successful ingestion",
                  server->copy_data(default_policy,
                                    handshake_record(fragments.front().get(), TLS::EpochNumber::ApplicationTraffic_0)),
                  CopyDataResult::Consumed);

               auto msg = server->next_post_handshake_message(default_policy, TLS::EpochNumber::ApplicationTraffic_0);
               result.require("received something", msg.has_value());
               result.require("message is Key_Update", std::holds_alternative<TLS::Key_Update>(msg.value()));
               result.test_is_false("peer does not request reciprocation",
                                    std::get<TLS::Key_Update>(msg.value()).expects_reciprocation());

               result.test_enum_eq("successful ingestion",
                                   server->copy_data(default_policy,
                                                     handshake_record(marshalled_key_update(1, true),
                                                                      TLS::EpochNumber::ApplicationTraffic_0)),
                                   CopyDataResult::Consumed);
               auto msg2 = server->next_post_handshake_message(default_policy, TLS::EpochNumber::ApplicationTraffic_0);
               result.require("received something", msg2.has_value());
               result.require("message is Key_Update", std::holds_alternative<TLS::Key_Update>(msg2.value()));
               result.test_is_true("peer requests reciprocation",
                                   std::get<TLS::Key_Update>(msg2.value()).expects_reciprocation());
            }),

      CHECK("Post-handshake messages arriving on outdated epochs are rejected",
            [&](Test::Result& result) {
               auto hl = make_handshake_layer(TLS::Connection_Side::Client);

               // RFC 9147 Section 8
               //    Due to loss and/or reordering, DTLS 1.3 implementations may
               //    receive a record with an older epoch than the current one
               //    [...]. They SHOULD attempt to process those records with
               //    that epoch [...] but MAY opt to discard such out-of-epoch
               //    records.
               //
               // Simulate a KeyUpdate overtaking a NewSessionTicket in flight:
               // once the KeyUpdate is processed, the connection's current
               // epoch has advanced, but the reordered ticket still arrives on
               // the previous epoch and must be processed normally.
               result.test_enum_eq("successful ingestion of KeyUpdate",
                                   hl->copy_data(default_policy,
                                                 handshake_record(marshalled_key_update(0 /* seqno */, false),
                                                                  TLS::EpochNumber::ApplicationTraffic_0)),
                                   CopyDataResult::Consumed);
               result.require(
                  "received KeyUpdate",
                  hl->next_post_handshake_message(default_policy, TLS::EpochNumber::ApplicationTraffic_0).has_value());

               const auto nst = new_session_ticket_bare_bytes();
               result.test_enum_eq(
                  "successful ingestion on the outdated epoch",
                  hl->copy_data(default_policy,
                                handshake_record(dtls_marshall_fragment(
                                   TLS::Handshake_Type::NewSessionTicket, nst.size(), 1 /* seqno */, 0, nst))),
                  CopyDataResult::Consumed);

               result.test_throws<TLS::TLS_Exception>("NST was protected with a now-outdated epoch", [&] {
                  hl->next_post_handshake_message(default_policy, TLS::EpochNumber::ApplicationTraffic_0 + 1);
               });
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "dtls_handshake_layer_13_basic", basic);
BOTAN_REGISTER_TEST_FN("tls", "dtls_handshake_layer_13_fragmentation", fragmentation);
BOTAN_REGISTER_TEST_FN("tls", "dtls_handshake_layer_13_post_handshake", post_handshake);

}  // namespace Botan_Tests

#endif
