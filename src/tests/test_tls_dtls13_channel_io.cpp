/*
* Integration tests for the DTLS 1.3 Channel_IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DTLS_13)

   #include <botan/assert.h>
   #include <botan/exceptn.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_ciphersuite.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_magic.h>
   #include <botan/tls_messages_13.h>
   #include <botan/tls_policy.h>
   #include <botan/internal/buffer_slicer.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/tls_ack_record_dtls13.h>
   #include <botan/internal/tls_channel_io.h>
   #include <botan/internal/tls_cipher_state.h>
   #include <botan/internal/tls_cipher_state_dtls13.h>
   #include <botan/internal/tls_flight_13.h>
   #include <botan/internal/tls_handshake_layer_13.h>
   #include <botan/internal/tls_handshake_layer_dtls13.h>
   #include <botan/internal/tls_record_dtls13.h>
   #include <botan/internal/tls_record_layer_dtls13.h>
   #include <botan/internal/tls_transcript_hash_13.h>
   #include <algorithm>
   #include <functional>
   #include <memory>
   #include <optional>
   #include <utility>
   #include <vector>

namespace Botan_Tests {

namespace {

namespace TLS = Botan::TLS;

constexpr auto epoch_appdata_0 = TLS::EpochNumber::create(3);
constexpr auto epoch_appdata_1 = TLS::EpochNumber::create(4);

class Mock_Callbacks final : public TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> data) override { m_datagrams.emplace_back(data.begin(), data.end()); }

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> /*data*/) override {
         throw Botan::Invalid_State("Channel_IO does not invoke tls_record_received");
      }

      void tls_alert(TLS::Alert /*alert*/) override {}

      uint64_t tls_current_monotonic_clock_ms() override { return m_now_ms; }

      void tls_register_deferred_operation(uint64_t monotonic_delay_ms, std::function<void()> op) override {
         m_registered_delays.push_back(monotonic_delay_ms);
         m_deferred_operations.push_back({.deadline_ms = m_now_ms + monotonic_delay_ms, .op = std::move(op)});
      }

      /// Advances the virtual clock and runs all deferred operations that became due
      void advance_clock(uint64_t delta_ms) {
         m_now_ms += delta_ms;

         // Due operations may register new deferred operations (e.g. the
         // retransmission timer re-arms itself), hence collect them first.
         std::vector<std::function<void()>> due_ops;
         std::erase_if(m_deferred_operations, [&](Deferred_Operation& op) {
            if(op.deadline_ms <= m_now_ms) {
               due_ops.emplace_back(std::move(op.op));
               return true;
            }
            return false;
         });

         for(const auto& op : due_ops) {
            op();
         }
      }

      /// In DTLS, each invocation of tls_emit_data() carries exactly one datagram
      const std::vector<std::vector<uint8_t>>& datagrams() const { return m_datagrams; }

      void clear_datagrams() { m_datagrams.clear(); }

      /// Hands out all datagrams emitted so far and forgets about them
      std::vector<std::vector<uint8_t>> take_datagrams() { return std::exchange(m_datagrams, {}); }

      /// Delays of all deferred operations ever registered, in order of registration
      const std::vector<uint64_t>& registered_delays() const { return m_registered_delays; }

   private:
      struct Deferred_Operation {
            uint64_t deadline_ms;
            std::function<void()> op;
      };

      uint64_t m_now_ms = 0;
      std::vector<Deferred_Operation> m_deferred_operations;
      std::vector<uint64_t> m_registered_delays;
      std::vector<std::vector<uint8_t>> m_datagrams;
};

std::shared_ptr<const TLS::Policy> make_policy(std::optional<size_t> mtu = {},
                                               std::optional<size_t> initial_timeout_ms = {},
                                               std::optional<size_t> maximum_deprotection_failures = {}) {
   class Test_Policy final : public TLS::Policy {
      public:
         Test_Policy(std::optional<size_t> mtu,
                     std::optional<size_t> initial_timeout_ms,
                     std::optional<size_t> maximum_deprotection_failures) :
               m_mtu(mtu),
               m_initial_timeout_ms(initial_timeout_ms),
               m_maximum_deprotection_failures(maximum_deprotection_failures) {}

         size_t dtls_default_mtu() const override { return m_mtu.value_or(Policy::dtls_default_mtu()); }

         size_t dtls_initial_timeout() const override {
            return m_initial_timeout_ms.value_or(Policy::dtls_initial_timeout());
         }

         size_t dtls_maximum_deprotection_failures() const override {
            return m_maximum_deprotection_failures.value_or(Policy::dtls_maximum_deprotection_failures());
         }

      private:
         std::optional<size_t> m_mtu;
         std::optional<size_t> m_initial_timeout_ms;
         std::optional<size_t> m_maximum_deprotection_failures;
   };

   return std::make_shared<Test_Policy>(mtu, initial_timeout_ms, maximum_deprotection_failures);
}

/// Cipher state with handshake traffic keys derived from a synthetic shared
/// secret. Client and server states created by this are compatible.
std::shared_ptr<TLS::Cipher_State> handshake_traffic_cipher_state(TLS::Connection_Side side) {
   const auto cipher = TLS::Ciphersuite::from_name("AES_128_GCM_SHA256").value();
   return TLS::Cipher_State::init_with_server_hello(
      side, TLS::TLS_Flavor::DTLS, Botan::secure_vector<uint8_t>(32, 0x00), cipher, std::vector<uint8_t>(32, 0x00), {});
}

/// Cipher state of a completed handshake: application traffic keys (epoch 3) have
/// been derived. Client and server states created by this are compatible.
std::shared_ptr<TLS::Cipher_State> application_traffic_cipher_state(TLS::Connection_Side side) {
   auto cipher_state = handshake_traffic_cipher_state(side);
   const std::vector<uint8_t> transcript_hash(32, 0x00);
   cipher_state->advance_with_server_finished(transcript_hash);
   cipher_state->advance_with_client_finished(transcript_hash);
   return cipher_state;
}

enum class Keys : uint8_t { None, HandshakeTraffic, ApplicationTraffic };

/// A DTLS Channel_IO along with its callbacks and (optional) cipher state
struct Endpoint {
      std::shared_ptr<Mock_Callbacks> callbacks;
      std::shared_ptr<TLS::Channel_IO> io;
      std::shared_ptr<TLS::Cipher_State> cipher_state;
};

struct Endpoints {
      std::shared_ptr<const TLS::Policy> policy;
      Endpoint client;
      Endpoint server;
};

Endpoint make_endpoint(TLS::Connection_Side side,
                       const std::shared_ptr<const TLS::Policy>& policy,
                       std::shared_ptr<TLS::Cipher_State> cipher_state) {
   auto callbacks = std::make_shared<Mock_Callbacks>();
   auto io = TLS::Channel_IO::create(side, TLS::TLS_Flavor::DTLS, policy, callbacks);
   if(cipher_state != nullptr) {
      // Epoch steering: not done by Channel_IO but necessary for the tests
      io->set_cipher_state(cipher_state);
   }
   return {.callbacks = std::move(callbacks), .io = std::move(io), .cipher_state = std::move(cipher_state)};
}

Endpoints make_endpoints(std::shared_ptr<const TLS::Policy> policy, Keys keys = Keys::None) {
   const auto cipher_state = [&](TLS::Connection_Side side) -> std::shared_ptr<TLS::Cipher_State> {
      switch(keys) {
         case Keys::None:
            return nullptr;
         case Keys::HandshakeTraffic:
            return handshake_traffic_cipher_state(side);
         case Keys::ApplicationTraffic:
            return application_traffic_cipher_state(side);
      }
      BOTAN_ASSERT_UNREACHABLE();
   };

   auto client = make_endpoint(TLS::Connection_Side::Client, policy, cipher_state(TLS::Connection_Side::Client));
   auto server = make_endpoint(TLS::Connection_Side::Server, policy, cipher_state(TLS::Connection_Side::Server));
   return {.policy = std::move(policy), .client = std::move(client), .server = std::move(server)};
}

std::optional<TLS::Transcript_Hash_State> make_transcript_hash() {
   return TLS::Transcript_Hash_State(TLS::TLS_Flavor::DTLS);
}

/**
 * Pulls events off the channel until no more are pending.
 * Returns the events along with the terminal BytesNeeded value.
 */
struct Drained_Events {
      std::vector<TLS::Channel_IO::ReceiveEvent> events;
      TLS::BytesNeeded bytes_needed = 0;
};

Drained_Events drain_events(TLS::Channel_IO& io,
                            std::optional<TLS::Transcript_Hash_State>& transcript_hash,
                            bool handshake_complete) {
   Drained_Events drained;
   while(true) {
      auto event = io.next_pending_event(transcript_hash, handshake_complete);
      if(std::holds_alternative<TLS::BytesNeeded>(event)) {
         drained.bytes_needed = std::get<TLS::BytesNeeded>(event);
         return drained;
      }
      drained.events.emplace_back(std::move(event));
   }
}

/// A handshake message with arbitrary content. Channel_IO sends messages
/// without parsing them, so the content does not need to be well-formed.
TLS::Flight::Message_Info synthetic_message(TLS::Handshake_Type type, TLS::EpochNumber epoch, size_t size) {
   std::vector<uint8_t> content(size);
   for(size_t i = 0; i < size; ++i) {
      content[i] = static_cast<uint8_t>(static_cast<size_t>(type) + i);
   }

   return {
      .wire_type = type,
      .epoch = epoch,
      .header = TLS::TLS_Handshake_Layer::prepare_header(type, size),
      .serialized = TLS::SerializedHandshakeMessage(std::move(content)),
   };
}

void send_flight(const Endpoint& sender, const std::vector<TLS::Flight::Message_Info>& flight) {
   sender.io->send(std::vector<TLS::Flight::Message>(flight.begin(), flight.end()));
}

/// Wire view of handshake messages as decoded by the peer
struct Received_Fragment {
      TLS::Handshake_Type type;    // NOLINT(*-non-private-member-variables-in-classes)
      size_t message_length;       // NOLINT(*-non-private-member-variables-in-classes)
      uint16_t message_seq;        // NOLINT(*-non-private-member-variables-in-classes)
      size_t offset;               // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<uint8_t> bytes;  // NOLINT(*-non-private-member-variables-in-classes)

      bool operator==(const Received_Fragment&) const = default;
};

struct Received_Record {
      TLS::Record_Type type;                        // NOLINT(*-non-private-member-variables-in-classes)
      TLS::EpochNumber epoch;                       // NOLINT(*-non-private-member-variables-in-classes)
      uint64_t sequence_number;                     // NOLINT(*-non-private-member-variables-in-classes)
      size_t payload_length;                        // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<Received_Fragment> fragments;     // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<TLS::RecordNumber> acknowledged;  // NOLINT(*-non-private-member-variables-in-classes)

      TLS::RecordNumber number() const { return {.epoch = epoch, .sequence_number = sequence_number}; }
};

struct Received_Datagram {
      size_t length;
      std::vector<Received_Record> records;
};

uint32_t load_be24(std::span<const uint8_t, 3> bytes) {
   return Botan::make_uint32(0, bytes[0], bytes[1], bytes[2]);
}

std::vector<Received_Fragment> parse_fragments(std::span<const uint8_t> record_payload) {
   std::vector<Received_Fragment> fragments;
   Botan::BufferSlicer bs(record_payload);
   while(!bs.empty()) {
      // RFC 9147 5.2
      //    msg_type(1) || length(3) || message_seq(2) || fragment_offset(3) || fragment_length(3)
      const auto header = bs.take<TLS::DTLS_Handshake_Layer::FRAGMENT_HEADER_LENGTH>();
      fragments.push_back({
         .type = static_cast<TLS::Handshake_Type>(header[0]),
         .message_length = load_be24(header.subspan<1, 3>()),
         .message_seq = Botan::load_be(header.subspan<4, 2>()),
         .offset = load_be24(header.subspan<6, 3>()),
         .bytes = bs.copy_as_vector(load_be24(header.subspan<9, 3>())),
      });
   }
   return fragments;
}

/// A record as found in a datagram, before any deprotection
struct Raw_Record {
      bool is_protected;
      std::span<const uint8_t> bytes;
};

/// Splits a datagram into its consecutive records (RFC 9147 4.3)
std::vector<Raw_Record> split_records(std::span<const uint8_t> datagram) {
   std::vector<Raw_Record> records;
   Botan::BufferSlicer bs(datagram);
   while(!bs.empty()) {
      const size_t start = datagram.size() - bs.remaining();
      // RFC 9147 4.1: DTLSCiphertext records start with the bits 001
      const bool is_protected = (bs.peek_byte() & 0b11100000) == 0b00100000;
      if(is_protected) {
         const auto header = TLS::UnifiedHeader_DTLS::parse(bs, std::nullopt /* no CID */);
         bs.skip(header.length.value_or(bs.remaining()));
      } else {
         const auto header = TLS::PlaintextHeader_DTLS::parse(bs);
         bs.skip(header.length);
      }
      const size_t end = datagram.size() - bs.remaining();
      records.push_back({.is_protected = is_protected, .bytes = datagram.subspan(start, end - start)});
   }
   return records;
}

/**
 * Decodes @p datagrams the way the peer's record layer would. The peer's
 * cipher state is only used for records that are actually protected: a peer
 * that already holds handshake traffic keys discards plaintext records of an
 * earlier epoch (RFC 9147 4.2.1), but the first server flight's ServerHello
 * arrives before the peer derived these keys.
 */
std::vector<Received_Datagram> decode_datagrams(Test::Result& result,
                                                const std::vector<std::vector<uint8_t>>& datagrams,
                                                TLS::Cipher_State* peer_cipher_state) {
   TLS::DTLS_Record_Layer peer{Botan::TLS::Policy{}};

   std::vector<Received_Datagram> decoded;
   for(const auto& datagram : datagrams) {
      auto& received = decoded.emplace_back(Received_Datagram{.length = datagram.size(), .records = {}});
      for(const auto& raw_record : split_records(datagram)) {
         result.require("peer accepts the record", peer.copy_data(raw_record.bytes, false /* fail loudly */));
         const auto record = peer.next_record(raw_record.is_protected ? peer_cipher_state : nullptr);

         if(const auto* handshake_record = std::get_if<TLS::Handshake_Record>(&record)) {
            received.records.push_back({
               .type = TLS::Record_Type::Handshake,
               .epoch = handshake_record->epoch.value(),
               .sequence_number = handshake_record->sequence_number.value(),
               .payload_length = handshake_record->payload.size(),
               .fragments = parse_fragments(handshake_record->payload),
               .acknowledged = {},
            });
         } else if(const auto* ack_record = std::get_if<TLS::ACK_Record>(&record)) {
            const TLS::ACKs acks(ack_record->payload);
            received.records.push_back({
               .type = TLS::Record_Type::ACK,
               .epoch = ack_record->epoch.value(),
               .sequence_number = ack_record->sequence_number.value(),
               .payload_length = ack_record->payload.size(),
               .fragments = {},
               .acknowledged = {acks.record_numbers().begin(), acks.record_numbers().end()},
            });
         } else if(const auto* data_record = std::get_if<TLS::ApplicationData_Record>(&record)) {
            received.records.push_back({
               .type = TLS::Record_Type::ApplicationData,
               .epoch = data_record->epoch.value(),
               .sequence_number = data_record->sequence_number.value(),
               .payload_length = data_record->payload.size(),
               .fragments = {},
               .acknowledged = {},
            });
         } else {
            result.test_failure("peer received a handshake, ACK or application data record");
         }
      }
   }
   return decoded;
}

/// Bytes added to a record's payload on the wire (header plus protection overhead)
size_t record_overhead(TLS::EpochNumber epoch, const TLS::Policy& policy, const TLS::Cipher_State* cipher_state) {
   if(epoch.is_unprotected()) {
      return TLS::DTLS_HEADER_SIZE;
   }

   BOTAN_ASSERT_NONNULL(cipher_state);
   constexpr size_t content_type_length = 1;
   return TLS::UnifiedHeader_DTLS::expected_length(policy, std::nullopt /* no CID */) + content_type_length +
          cipher_state->encrypt_output_length(0);
}

/**
 * Sends @p flight from the server, decodes the emitted datagrams on the
 * client's side and checks invariants that must hold for any flight:
 *
 *  - every datagram fits into the MTU,
 *  - every record carries exactly the overhead mandated by its epoch,
 *  - fragments are only placed into records of their message's epoch, and
 *  - the reassembled messages equal the input.
 *
 * This assumes that the server did not send any handshake messages before,
 * i.e. the message_seq of each message equals its index in @p flight.
 */
std::vector<Received_Datagram> transmit_server_flight(Test::Result& result,
                                                      const Endpoints& endpoints,
                                                      const std::vector<TLS::Flight::Message_Info>& flight) {
   send_flight(endpoints.server, flight);
   auto wire = decode_datagrams(result, endpoints.server.callbacks->datagrams(), endpoints.client.cipher_state.get());

   const auto& policy = *endpoints.policy;
   std::vector<std::vector<uint8_t>> reassembled(flight.size());

   for(const auto& datagram : wire) {
      result.test_sz_lte("datagram fits into the MTU", datagram.length, policy.dtls_default_mtu());

      size_t expected_datagram_length = 0;
      for(const auto& record : datagram.records) {
         result.test_enum_eq("record is a handshake record", record.type, TLS::Record_Type::Handshake);
         expected_datagram_length +=
            record_overhead(record.epoch, policy, endpoints.server.cipher_state.get()) + record.payload_length;

         for(const auto& fragment : record.fragments) {
            result.require("fragment belongs to a message of the flight", fragment.message_seq < flight.size());
            const auto& message = flight[fragment.message_seq];
            result.test_enum_eq("fragment has the message's type", fragment.type, message.wire_type);
            result.test_sz_eq("fragment has the message's length", fragment.message_length, message.serialized.size());
            result.test_is_true("fragment is in a record of the message's epoch", record.epoch == message.epoch);

            auto& message_bytes = reassembled[fragment.message_seq];
            result.test_sz_eq("fragments are sent in order", fragment.offset, message_bytes.size());
            message_bytes.insert(message_bytes.end(), fragment.bytes.begin(), fragment.bytes.end());
         }
      }

      result.test_sz_eq(
         "datagram consists of records with their per-epoch overhead", datagram.length, expected_datagram_length);
   }

   for(size_t i = 0; i < flight.size(); ++i) {
      result.test_bin_eq("reassembled message equals the input", reassembled[i], flight[i].serialized.get());
   }

   return wire;
}

bool contains(std::span<const TLS::RecordNumber> numbers, const TLS::RecordNumber& number) {
   return std::ranges::find(numbers, number) != numbers.end();
}

/// The numbers of all records of @p type in @p wire in the order they were sent
std::vector<TLS::RecordNumber> record_numbers(const std::vector<Received_Datagram>& wire,
                                              TLS::Record_Type type = TLS::Record_Type::Handshake) {
   std::vector<TLS::RecordNumber> numbers;
   for(const auto& datagram : wire) {
      for(const auto& record : datagram.records) {
         if(record.type == type) {
            numbers.push_back(record.number());
         }
      }
   }
   return numbers;
}

size_t count_records(const std::vector<Received_Datagram>& wire, TLS::Record_Type type) {
   return record_numbers(wire, type).size();
}

/// All handshake fragments in @p wire, except those in records listed in @p excluded_records
std::vector<Received_Fragment> fragments_of(const std::vector<Received_Datagram>& wire,
                                            std::span<const TLS::RecordNumber> excluded_records = {}) {
   std::vector<Received_Fragment> fragments;
   for(const auto& datagram : wire) {
      for(const auto& record : datagram.records) {
         if(record.type == TLS::Record_Type::Handshake && !contains(excluded_records, record.number())) {
            fragments.insert(fragments.end(), record.fragments.begin(), record.fragments.end());
         }
      }
   }
   return fragments;
}

/// The record numbers acknowledged by all ACK records in @p wire
std::vector<TLS::RecordNumber> acknowledged_by(const std::vector<Received_Datagram>& wire) {
   std::vector<TLS::RecordNumber> numbers;
   for(const auto& datagram : wire) {
      for(const auto& record : datagram.records) {
         numbers.insert(numbers.end(), record.acknowledged.begin(), record.acknowledged.end());
      }
   }
   return numbers;
}

/**
 * A DTLS server under test (with handshake traffic keys) and a simulated
 * client peer. The peer is a second Channel_IO, such that its fragments and
 * retransmissions are real wire data, and it crafts ACK records with its
 * cipher state. Server-side output is always decoded the way the peer would.
 *
 * The timing is chosen such that all timers are distinct: the server's
 * retransmission timer fires after 400ms, its ACK timer after 100ms.
 */
class Exchange {
   public:
      static constexpr size_t mtu = 400;
      static constexpr size_t initial_timeout_ms = 400;
      static constexpr size_t ack_timeout_ms = initial_timeout_ms / 4;

   public:
      explicit Exchange(Test::Result& result,
                        Keys keys = Keys::HandshakeTraffic,
                        std::optional<size_t> maximum_deprotection_failures = {}) :
            m_result(result),
            m_endpoints(make_endpoints(make_policy(mtu, initial_timeout_ms, maximum_deprotection_failures), keys)),
            m_transcript_hash(make_transcript_hash()),
            m_handshake_complete(keys == Keys::ApplicationTraffic),
            m_client_record_layer{*m_endpoints.policy} {}

      const Endpoint& server() const { return m_endpoints.server; }

      const Endpoint& client() const { return m_endpoints.client; }

      /// The server learns that its peer indeed talks DTLS 1.3 (e.g. after receiving a ClientHello)
      void commit() const { server().io->notify_protocol_version_committed(); }

      static std::vector<TLS::Flight::Message_Info> default_server_flight() {
         using enum TLS::Handshake_Type;
         return {
            synthetic_message(ServerHello, TLS::EpochNumber::unprotected(), 90),
            synthetic_message(EncryptedExtensions, TLS::EpochNumber::handshake_traffic(), 40),
            synthetic_message(Certificate, TLS::EpochNumber::handshake_traffic(), 900),
            synthetic_message(CertificateVerify, TLS::EpochNumber::handshake_traffic(), 80),
            synthetic_message(Finished, TLS::EpochNumber::handshake_traffic(), 32),
         };
      }

      /// Sends a flight (by default one spanning several datagrams and both epochs)
      /// and returns what the peer receives
      std::vector<Received_Datagram> send_server_flight(
         const std::vector<TLS::Flight::Message_Info>& flight = default_server_flight()) {
         send_flight(server(), flight);
         return take_server_output();
      }

      /// Whatever the server emitted since the last call, as the peer sees it
      std::vector<Received_Datagram> take_server_output() {
         return decode_datagrams(m_result, server().callbacks->take_datagrams(), client().cipher_state.get());
      }

      /**
       * Advances the server's clock and runs the timers that became due.
       *
       * @returns the number of deferred operations scheduled in the meantime.
       *          A retransmission timer that expired without being cancelled
       *          re-arms itself, even if there is nothing left to retransmit.
       */
      size_t advance_server_clock(uint64_t delta_ms) const {
         const auto& delays = server().callbacks->registered_delays();
         const size_t registered_before = delays.size();
         server().callbacks->advance_clock(delta_ms);
         return delays.size() - registered_before;
      }

      /// The peer sends a handshake message of @p size bytes (by default protected with handshake traffic keys)
      std::vector<std::vector<uint8_t>> client_sends(
         TLS::Handshake_Type type, size_t size, TLS::EpochNumber epoch = TLS::EpochNumber::handshake_traffic()) const {
         send_flight(client(), {synthetic_message(type, epoch, size)});
         return client().callbacks->take_datagrams();
      }

      /// The peer sends a message that does not fit into a single datagram
      std::vector<std::vector<uint8_t>> client_sends_fragmented_message() {
         auto datagrams = client_sends(TLS::Handshake_Type::Certificate, 2000);
         m_result.require("message is fragmented into multiple datagrams", datagrams.size() > 2);
         return datagrams;
      }

      /// The peer's retransmission timer fires
      std::vector<std::vector<uint8_t>> client_retransmits() const {
         client().callbacks->advance_clock(initial_timeout_ms);
         return client().callbacks->take_datagrams();
      }

      /// Decodes datagrams sent by the peer, e.g. to learn their record numbers
      std::vector<Received_Datagram> decode_client_datagrams(const std::vector<std::vector<uint8_t>>& datagrams) {
         return decode_datagrams(m_result, datagrams, server().cipher_state.get());
      }

      /// The server receives @p datagram and its pending events are drained
      Drained_Events deliver_to_server(std::span<const uint8_t> datagram) {
         server().io->copy_data(datagram);
         return drain_events(*server().io, m_transcript_hash, m_handshake_complete);
      }

      /// The peer sends a protected ACK for @p records
      void client_acknowledges(std::span<const TLS::RecordNumber> records) {
         const auto& policy = *m_endpoints.policy;
         auto* cipher_state = client().cipher_state.get();

         const TLS::ACKs acks({records.begin(), records.end()});
         const auto max_payload_size = m_client_record_layer.record_payload_size_limit(policy, cipher_state);

         Botan::secure_vector<uint8_t> ack_record;
         m_client_record_layer.prepare_record(
            TLS::Record_Type::ACK, acks.serialize(max_payload_size), policy, cipher_state, ack_record);
         m_result.test_is_true("ACK does not surface as an event", deliver_to_server(ack_record).events.empty());
      }

      /// @name Post-handshake traffic (requires Keys::ApplicationTraffic)
      /// @{

      /// The server sends application data and the peer receives it
      std::vector<Received_Datagram> send_server_application_data() {
         const std::vector<uint8_t> payload(20, 0xAA);
         server().io->send(payload);
         return take_server_output();
      }

      /// The server receives @p count application data records that fail authentication
      void server_receives_tampered_records(size_t count) {
         for(size_t i = 0; i < count; ++i) {
            auto datagrams = client_sends_application_data();
            m_result.require("peer sends a single datagram", datagrams.size() == 1);

            datagrams.front().back() ^= 0x01;
            m_result.test_is_true("tampered record is silently discarded",
                                  deliver_to_server(datagrams.front()).events.empty());
         }
      }

      /// The peer sends application data
      std::vector<std::vector<uint8_t>> client_sends_application_data() const {
         const std::vector<uint8_t> payload(20, 0xBB);
         client().io->send(payload);
         return client().callbacks->take_datagrams();
      }

      /**
       * The peer sends a KeyUpdate that the server receives and passes on to
       * its Channel_IO, just like the channel would do.
       *
       * @returns the number of the record holding the KeyUpdate
       */
      TLS::RecordNumber server_receives_key_update(bool update_requested) {
         client().io->update_traffic_keys(update_requested);
         const auto datagrams = client().callbacks->take_datagrams();
         m_result.require("peer sends a single datagram", datagrams.size() == 1);

         const auto numbers = record_numbers(decode_client_datagrams(datagrams));
         m_result.require("peer sends a single record", numbers.size() == 1);

         const auto events = deliver_to_server(datagrams.front()).events;
         m_result.require("KeyUpdate is the only event", events.size() == 1);
         const auto* post_handshake_message = std::get_if<TLS::Post_Handshake_Message_13>(&events.front());
         m_result.require("event is a post-handshake message", post_handshake_message != nullptr);
         const auto* key_update = std::get_if<TLS::Key_Update>(post_handshake_message);
         m_result.require("message is a KeyUpdate", key_update != nullptr);

         server().io->handle_key_update(*key_update);
         return numbers.front();
      }

      /// The peer processes a KeyUpdate of the server and starts reading with the new keys
      void peer_reads_with_updated_keys() const { client().io->handle_key_update(TLS::Key_Update(false)); }

      /// The peer starts writing with the new keys, as if its own KeyUpdate was acknowledged
      void peer_writes_with_updated_keys() const { client().cipher_state->update_write_keys(); }

      /// Whether the server still holds the keys to protect records of the given write epoch
      bool server_can_write_epoch(TLS::EpochNumber epoch) const {
         auto* cipher_state = TLS::as_dtls_cipher_state(server().cipher_state.get());
         BOTAN_ASSERT_NONNULL(cipher_state);

         const std::vector<uint8_t> payload(1, 0x00);
         Botan::secure_vector<uint8_t> out;
         try {
            cipher_state->protect_record(TLS::Record_Type::ApplicationData, payload, 0, out, epoch);
            return true;
         } catch(const TLS::TLS_Exception&) {
            return false;
         }
      }

      TLS::EpochNumber server_write_epoch() const { return server().cipher_state->current_write_epoch_number(); }

      TLS::EpochNumber server_read_epoch() const { return server().cipher_state->current_read_epoch_number(); }

      /// @}

   private:
      Test::Result& m_result;
      Endpoints m_endpoints;
      std::optional<TLS::Transcript_Hash_State> m_transcript_hash;
      bool m_handshake_complete;
      TLS::DTLS_Record_Layer m_client_record_layer;
};

std::vector<Test::Result> send_flights() {
   using enum TLS::Handshake_Type;

   constexpr size_t min_fragment_size = TLS::DTLS_Handshake_Layer::FRAGMENT_HEADER_LENGTH + 1;

   const auto packing_up_to_the_mtu = [](const char* name, TLS::EpochNumber epoch) {
      return CHECK(name, [=](Test::Result& result) {
         const auto keys = (epoch.is_unprotected()) ? Keys::None : Keys::HandshakeTraffic;
         const auto endpoints = make_endpoints(make_policy(400), keys);
         const size_t mtu = endpoints.policy->dtls_default_mtu();

         // Sizes are chosen such that small messages share a record and large
         // messages span multiple datagrams. The message types are irrelevant.
         const auto wire = transmit_server_flight(result,
                                                  endpoints,
                                                  {
                                                     synthetic_message(EncryptedExtensions, epoch, 40),
                                                     synthetic_message(CertificateRequest, epoch, 300),
                                                     synthetic_message(Certificate, epoch, 1000),
                                                     synthetic_message(CertificateVerify, epoch, 25),
                                                     synthetic_message(Finished, epoch, 700),
                                                  });

         result.require("flight spans multiple datagrams", wire.size() > 1);
         for(const auto& datagram : wire) {
            result.test_sz_eq("single-epoch flight has one record per datagram", datagram.records.size(), 1);
         }

         for(size_t i = 0; i + 1 < wire.size(); ++i) {
            result.test_sz_lt("datagram leaves no room for another fragment", mtu - wire[i].length, min_fragment_size);
         }

         result.require("first datagram holds a record", !wire.front().records.empty());
         const auto& first_record = wire.front().records.front();
         result.require("first record is shared by the first three messages", first_record.fragments.size() == 3);
         for(uint16_t i = 0; i < 3; ++i) {
            result.test_u16_eq("message sequence number", first_record.fragments[i].message_seq, i);
         }
      });
   };

   return {
      packing_up_to_the_mtu("messages are packed into records and datagrams up to the MTU (unprotected)",
                            TLS::EpochNumber::unprotected()),
      packing_up_to_the_mtu("messages are packed into records and datagrams up to the MTU (protected)",
                            TLS::EpochNumber::handshake_traffic()),

      CHECK("a message larger than a datagram is fragmented, its first fragment filling up the pending record",
            [](Test::Result& result) {
               const auto endpoints = make_endpoints(make_policy(500), Keys::HandshakeTraffic);
               const size_t mtu = endpoints.policy->dtls_default_mtu();

               const auto wire = transmit_server_flight(
                  result,
                  endpoints,
                  {
                     synthetic_message(EncryptedExtensions, TLS::EpochNumber::handshake_traffic(), 50),
                     synthetic_message(Certificate, TLS::EpochNumber::handshake_traffic(), 2500),
                  });

               result.require("large message spans multiple datagrams", wire.size() > 2);

               result.require("first datagram holds one record", wire.front().records.size() == 1);
               const auto& first_record = wire.front().records.front();
               result.require("first record holds the small message and the beginning of the large one",
                              first_record.fragments.size() == 2);
               result.test_u16_eq("second fragment is of the large message", first_record.fragments[1].message_seq, 1);
               result.test_sz_eq("second fragment is the large message's first", first_record.fragments[1].offset, 0);
               result.test_sz_eq("first fragment of the large message fills up the datagram", wire.front().length, mtu);

               for(size_t i = 1; i < wire.size(); ++i) {
                  result.require("subsequent datagram holds one record", wire[i].records.size() == 1);
                  result.test_sz_eq(
                     "subsequent record holds a single fragment", wire[i].records.front().fragments.size(), 1);
                  if(i + 1 < wire.size()) {
                     result.test_sz_eq("non-final datagram is filled up to the MTU", wire[i].length, mtu);
                  }
               }
            }),

      CHECK("messages of different epochs may share a datagram but never a record",
            [](Test::Result& result) {
               const auto endpoints = make_endpoints(make_policy(500), Keys::HandshakeTraffic);

               // Epoch purity of the records is checked by transmit_server_flight()
               const auto wire = transmit_server_flight(
                  result,
                  endpoints,
                  {
                     synthetic_message(ServerHello, TLS::EpochNumber::unprotected(), 90),
                     synthetic_message(EncryptedExtensions, TLS::EpochNumber::handshake_traffic(), 40),
                     synthetic_message(Certificate, TLS::EpochNumber::handshake_traffic(), 900),
                     synthetic_message(CertificateVerify, TLS::EpochNumber::handshake_traffic(), 80),
                     synthetic_message(Finished, TLS::EpochNumber::handshake_traffic(), 32),
                  });

               result.require("first datagram holds two records", wire.front().records.size() == 2);
               const auto& unprotected_record = wire.front().records[0];
               const auto& protected_record = wire.front().records[1];

               result.test_is_true("first record is unprotected", unprotected_record.epoch.is_unprotected());
               result.test_sz_eq(
                  "unprotected record holds the ServerHello only", unprotected_record.fragments.size(), 1);

               result.test_is_true("second record is protected", protected_record.epoch.is_protected());
               result.require("protected record holds fragments", !protected_record.fragments.empty());
               result.test_u16_eq("protected record starts with the EncryptedExtensions",
                                  protected_record.fragments.front().message_seq,
                                  1);

               for(size_t i = 1; i < wire.size(); ++i) {
                  for(const auto& record : wire[i].records) {
                     result.test_is_true("subsequent records are protected", record.epoch.is_handshake_traffic());
                  }
               }
            }),

      CHECK("a dummy ChangeCipherSpec in a flight is rejected without emitting anything",
            [](Test::Result& result) {
               const auto endpoints = make_endpoints(make_policy(), Keys::HandshakeTraffic);

               // RFC 9147 5
               //    DTLS implementations do not use the TLS 1.3 "compatibility mode" [...].
               const std::vector<TLS::Flight::Message> flight = {
                  synthetic_message(ServerHello, TLS::EpochNumber::unprotected(), 90),
                  TLS::Flight::Dummy_ChangeCipherSpec{},
                  synthetic_message(EncryptedExtensions, TLS::EpochNumber::handshake_traffic(), 40),
               };

               result.test_throws<Botan::Internal_Error>("flight with a dummy CCS is rejected",
                                                         [&] { endpoints.server.io->send(flight); });
               result.test_is_true("nothing was emitted", endpoints.server.callbacks->datagrams().empty());
            }),

      CHECK("sending a flight arms the retransmission timer",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.send_server_flight();

               const auto& delays = exchange.server().callbacks->registered_delays();
               result.require("a deferred operation was registered", !delays.empty());
               result.test_u64_eq("retransmission timer is registered with the initial timeout",
                                  delays.back(),
                                  Exchange::initial_timeout_ms);
            }),
   };
}

/// Tests the server's reaction to incoming ACKs, the retransmission of its flight and its own ACKs
std::vector<Test::Result> retransmissions_and_acknowledgements() {
   using enum TLS::Handshake_Type;
   using enum TLS::Record_Type;

   constexpr size_t initial_timeout_ms = Exchange::initial_timeout_ms;
   constexpr size_t ack_timeout_ms = Exchange::ack_timeout_ms;

   struct Server_Response {
         std::vector<Received_Datagram> flight;
         std::vector<Received_Datagram> output;
         bool retransmission_timer_was_running;
   };

   // The server sent a flight and then receives the first fragment of the peer's next flight.
   // Returns the flight along with the server's reaction when the retransmission timer ran out.
   const auto server_output_after_first_fragment_of_next_flight = [](Test::Result& result, bool committed) {
      Exchange exchange(result);
      if(committed) {
         exchange.commit();
      }
      auto flight = exchange.send_server_flight();

      const auto peer_flight = exchange.client_sends_fragmented_message();
      result.test_is_true("fragment yields no event", exchange.deliver_to_server(peer_flight.front()).events.empty());

      const size_t rescheduled_operations = exchange.advance_server_clock(initial_timeout_ms);
      return Server_Response{
         .flight = std::move(flight),
         .output = exchange.take_server_output(),
         .retransmission_timer_was_running = rescheduled_operations > 0,
      };
   };

   return {
      CHECK("the retransmission timer re-sends the whole flight with new record numbers",
            [](Test::Result& result) {
               Exchange exchange(result);
               const auto original = exchange.send_server_flight();

               exchange.advance_server_clock(initial_timeout_ms - 1);
               result.test_is_true("nothing is re-sent before the timeout", exchange.take_server_output().empty());

               exchange.advance_server_clock(1);
               const auto retransmitted = exchange.take_server_output();
               result.test_is_true("handshake bytes are identical",
                                   fragments_of(retransmitted) == fragments_of(original));

               // The records are re-packed. Given that they are the same as before, the datagrams come out the same.
               result.require("flight is packed into the same number of datagrams",
                              retransmitted.size() == original.size());

               // RFC 9147 5.8.1: Retransmissions are new records, i.e. they use new record numbers
               const auto original_numbers = record_numbers(original);
               for(const auto& number : record_numbers(retransmitted)) {
                  const bool is_new = std::ranges::all_of(original_numbers, [&](const auto& original_number) {
                     return original_number.epoch != number.epoch ||
                            original_number.sequence_number < number.sequence_number;
                  });
                  result.test_is_true("record number is higher than any previous one in its epoch", is_new);
               }
            }),

      CHECK("a protected ACK covering all outstanding records cancels the retransmission timer",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();
               const auto flight = exchange.send_server_flight();

               exchange.client_acknowledges(record_numbers(flight));

               result.test_is_true("ACK does not cause output", exchange.take_server_output().empty());
               result.test_sz_eq(
                  "retransmission timer is cancelled", exchange.advance_server_clock(initial_timeout_ms), 0);
               result.test_is_true("flight is not re-sent", exchange.take_server_output().empty());
            }),

      CHECK("an ACK covering some records leaves the remaining ones to be retransmitted",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();
               const auto flight = exchange.send_server_flight();
               result.require("first datagram holds multiple records", flight.front().records.size() >= 2);

               // The first record holds the ServerHello only
               const std::vector acknowledged = {flight.front().records.front().number()};
               exchange.client_acknowledges(acknowledged);
               result.test_is_true("a partial ACK does not cause an immediate retransmission",
                                   exchange.take_server_output().empty());

               exchange.advance_server_clock(initial_timeout_ms);
               const auto retransmitted = exchange.take_server_output();
               const auto retransmitted_fragments = fragments_of(retransmitted);
               result.test_is_true("only the unacknowledged fragments are re-sent",
                                   retransmitted_fragments == fragments_of(flight, acknowledged));
               for(const auto& fragment : retransmitted_fragments) {
                  result.test_is_true("acknowledged ServerHello is not re-sent", fragment.message_seq != 0);
               }

               // Acknowledging any transmission of a record is sufficient
               exchange.client_acknowledges(record_numbers(retransmitted));
               result.test_sz_eq(
                  "retransmission timer is cancelled", exchange.advance_server_clock(2 * initial_timeout_ms), 0);
               result.test_is_true("acknowledging the retransmission cancels the timer",
                                   exchange.take_server_output().empty());
            }),

      CHECK("the first fragment of the peer's next flight implicitly acknowledges the flight",
            [=](Test::Result& result) {
               // RFC 9147 7
               //    In particular, receiving a message from a handshake flight implicitly
               //    acknowledges all messages from the previous flight(s).
               const auto response = server_output_after_first_fragment_of_next_flight(result, true);
               result.test_sz_eq("flight is not re-sent", count_records(response.output, Handshake), 0);
               result.test_is_false("retransmission timer is cancelled", response.retransmission_timer_was_running);
            }),

      CHECK("a duplicate of a previous message is not an implicit ACK",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();
               exchange.send_server_flight();

               // The peer's Finished completes the first flight, ...
               const auto finished = exchange.client_sends(Finished, 32);
               result.require("peer sends a single datagram", finished.size() == 1);
               result.test_sz_eq(
                  "Finished is delivered", exchange.deliver_to_server(finished.front()).events.size(), 1);

               // ... the server answers with another flight, ...
               const auto second_flight =
                  exchange.send_server_flight({synthetic_message(Finished, TLS::EpochNumber::handshake_traffic(), 32)});

               // ... and the peer retransmits its Finished, because it has not heard from the server yet.
               const auto duplicate = exchange.client_retransmits();
               result.require("peer retransmits a single datagram", duplicate.size() == 1);
               const auto duplicate_numbers = record_numbers(exchange.decode_client_datagrams(duplicate));
               result.test_is_true("duplicate yields no event",
                                   exchange.deliver_to_server(duplicate.front()).events.empty());

               // The duplicate is acknowledged but the second flight remains unacknowledged
               exchange.advance_server_clock(ack_timeout_ms);
               result.test_is_true("duplicate is acknowledged",
                                   contains(acknowledged_by(exchange.take_server_output()), duplicate_numbers.front()));

               exchange.advance_server_clock(initial_timeout_ms - ack_timeout_ms);
               result.test_is_true("second flight is re-sent",
                                   fragments_of(exchange.take_server_output()) == fragments_of(second_flight));
            }),

      CHECK("a fragment beyond the buffering window is no implicit ACK and not acknowledged",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();
               const auto flight = exchange.send_server_flight();

               // The server hasn't seen the peer's first message yet. The message sequence number of the next
               // fragment is further ahead than the server is willing to buffer. It is not delivered.
               const size_t skipped_messages = TLS::DTLS_Handshake_Layer::MAX_BUFFERED_FUTURE_MESSAGES + 1;
               for(size_t i = 0; i < skipped_messages; ++i) {
                  exchange.client_sends(Certificate, 5);
               }
               const auto fragment = exchange.client_sends(Certificate, 5);
               result.require("peer sends a single datagram", fragment.size() == 1);
               result.test_is_true("fragment yields no event",
                                   exchange.deliver_to_server(fragment.front()).events.empty());

               exchange.advance_server_clock(initial_timeout_ms);
               const auto output = exchange.take_server_output();
               result.test_is_true("flight is re-sent in full", fragments_of(output) == fragments_of(flight));
               result.test_sz_eq("fragment is not acknowledged", count_records(output, ACK), 0);
            }),

      CHECK("after a partial flight, the ACK timer emits an ACK for the received records",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();

               const auto peer_flight = exchange.client_sends_fragmented_message();
               const auto peer_records = record_numbers(exchange.decode_client_datagrams(peer_flight));

               exchange.deliver_to_server(peer_flight[0]);
               exchange.advance_server_clock(ack_timeout_ms / 2);
               exchange.deliver_to_server(peer_flight[1]);
               exchange.advance_server_clock(ack_timeout_ms / 2 - 1);
               result.test_is_true("no ACK before the ACK timeout", exchange.take_server_output().empty());

               exchange.advance_server_clock(1);
               const auto output = exchange.take_server_output();
               result.test_sz_eq("one ACK record is sent", count_records(output, ACK), 1);
               result.test_is_true("ACK lists the received records",
                                   acknowledged_by(output) == std::vector({peer_records[0], peer_records[1]}));

               exchange.advance_server_clock(initial_timeout_ms);
               result.test_is_true("the ACK is sent once", exchange.take_server_output().empty());
            }),

      CHECK("no ACKs are sent as long as the protocol version is not committed",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.deliver_to_server(exchange.client_sends_fragmented_message().front());

               exchange.advance_server_clock(initial_timeout_ms);
               result.test_is_true("no ACK is sent", exchange.take_server_output().empty());
            }),

      CHECK("sending a flight cancels the ACK timer",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();
               exchange.deliver_to_server(exchange.client_sends_fragmented_message().front());

               const auto flight = exchange.send_server_flight();

               exchange.advance_server_clock(ack_timeout_ms);
               result.test_is_true("no ACK is sent", exchange.take_server_output().empty());

               exchange.advance_server_clock(initial_timeout_ms - ack_timeout_ms);
               result.test_is_true("the retransmission timer is not affected",
                                   fragments_of(exchange.take_server_output()) == fragments_of(flight));
            }),

      CHECK("a complete flight makes pending ACKs obsolete",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();
               exchange.deliver_to_server(exchange.client_sends_fragmented_message().front());

               // The channel received the final message of the peer's flight and is about to respond
               exchange.server().io->notify_received_complete_flight();

               exchange.advance_server_clock(ack_timeout_ms);
               result.test_is_true("ACK timer does not emit an ACK", exchange.take_server_output().empty());

               exchange.server().io->notify_received_final_flight();
               result.test_is_true("there is nothing left to acknowledge", exchange.take_server_output().empty());
            }),

      CHECK("the final flight is acknowledged immediately",
            [](Test::Result& result) {
               Exchange exchange(result);
               exchange.commit();

               const auto finished = exchange.client_sends(Finished, 32);
               result.require("peer sends a single datagram", finished.size() == 1);
               const auto finished_numbers = record_numbers(exchange.decode_client_datagrams(finished));
               result.test_sz_eq(
                  "Finished is delivered", exchange.deliver_to_server(finished.front()).events.size(), 1);
               result.test_is_true("Finished is not acknowledged right away", exchange.take_server_output().empty());

               // There is no response to the peer's last flight that could implicitly acknowledge it.
               exchange.server().io->notify_received_final_flight();
               const auto output = exchange.take_server_output();
               result.test_sz_eq("one ACK record is sent", count_records(output, ACK), 1);
               result.test_is_true("ACK lists the peer's Finished", acknowledged_by(output) == finished_numbers);
            }),

      CHECK("closing for writing or shutting down cancels the retransmission and ACK timers",
            [](Test::Result& result) {
               // Closing the write side (close_notify sent) is sufficient, a full shutdown includes it
               const std::vector<std::pair<std::string, std::function<void(TLS::Channel_IO&)>>> closures = {
                  {"closed for writing", [](TLS::Channel_IO& io) { io.notify_closed_for_writing(); }},
                  {"shutdown", [](TLS::Channel_IO& io) { io.notify_shutdown(); }},
               };

               for(const auto& [name, close] : closures) {
                  {
                     Exchange exchange(result);
                     exchange.commit();
                     exchange.send_server_flight();

                     close(*exchange.server().io);

                     result.test_sz_eq("retransmission timer is cancelled (" + name + ")",
                                       exchange.advance_server_clock(10 * initial_timeout_ms),
                                       0);
                     result.test_is_true("flight is not re-sent (" + name + ")", exchange.take_server_output().empty());
                  }

                  {
                     Exchange exchange(result);
                     exchange.commit();
                     exchange.deliver_to_server(exchange.client_sends_fragmented_message().front());

                     close(*exchange.server().io);

                     exchange.advance_server_clock(10 * initial_timeout_ms);
                     result.test_is_true("ACK timer is cancelled, no ACK is sent (" + name + ")",
                                         exchange.take_server_output().empty());
                  }
               }
            }),

      CHECK(
         "the handshake epoch is retained for twice the maximum segment lifetime",
         [=](Test::Result& result) {
            // RFC 9293 3.4.1: Maximum Segment Lifetime of 2 minutes
            constexpr uint64_t msl_ms = 2 * 60 * 1000;

            Exchange exchange(result);
            exchange.commit();

            // The peer's Finished is the last message of the handshake, the server acknowledges it
            const auto finished = exchange.client_sends(Finished, 32);
            result.require("peer sends a single datagram", finished.size() == 1);
            result.test_sz_eq("Finished is delivered", exchange.deliver_to_server(finished.front()).events.size(), 1);
            exchange.server().io->notify_received_final_flight();
            exchange.advance_server_clock(ack_timeout_ms);
            exchange.take_server_output();

            // The peer never sees that ACK and retransmits its Finished (protected with the handshake keys)
            // several times. These are sent now but only delivered to the server later on.
            const auto retransmission = [&](uint64_t delay_ms) {
               exchange.client().callbacks->advance_clock(delay_ms);
               const auto datagrams = exchange.client().callbacks->take_datagrams();
               result.require("peer retransmits a single datagram", datagrams.size() == 1);
               const auto numbers = record_numbers(exchange.decode_client_datagrams(datagrams));
               result.require("peer retransmits a single record", numbers.size() == 1);
               return std::pair{datagrams.front(), numbers.front()};
            };
            const auto [retransmission_1, number_1] = retransmission(initial_timeout_ms);
            const auto [retransmission_2, number_2] = retransmission(2 * initial_timeout_ms);
            const auto [retransmission_3, number_3] = retransmission(4 * initial_timeout_ms);

            // The handshake completes on both sides: the application epoch is now available
            const std::vector<uint8_t> transcript_hash(32, 0x00);
            for(const auto* endpoint : {&exchange.client(), &exchange.server()}) {
               endpoint->cipher_state->advance_with_server_finished(transcript_hash);
               endpoint->cipher_state->advance_with_client_finished(transcript_hash);
            }
            result.test_is_true("server reads the application epoch",
                                exchange.server_read_epoch().application_traffic_index() == 0);

            // The peer's first record in the application epoch. The handshake epoch is kept for a little longer.
            const auto& delays = exchange.server().callbacks->registered_delays();
            const size_t registered_before = delays.size();
            const auto application_data = exchange.client_sends_application_data();
            result.require("peer sends a single datagram", application_data.size() == 1);
            const auto events = exchange.deliver_to_server(application_data.front()).events;
            result.test_is_true("application data is delivered",
                                events.size() == 1 && std::holds_alternative<TLS::ApplicationData_Record>(events[0]));
            result.test_is_true("a timer for twice the maximum segment lifetime is registered",
                                delays.size() > registered_before && delays.back() == 2 * msl_ms);

            // Delivers a retransmitted Finished and tells whether the server could deprotect and acknowledge it
            const auto acknowledged = [&](const std::vector<uint8_t>& datagram, const TLS::RecordNumber& number) {
               result.test_is_true("retransmission yields no event",
                                   exchange.deliver_to_server(datagram).events.empty());
               exchange.advance_server_clock(ack_timeout_ms);
               return contains(acknowledged_by(exchange.take_server_output()), number);
            };

            // One maximum segment lifetime would be sufficient for a regular epoch change
            exchange.advance_server_clock(msl_ms);
            result.test_is_true("handshake epoch is readable after one maximum segment lifetime",
                                acknowledged(retransmission_1, number_1));

            exchange.advance_server_clock(msl_ms - ack_timeout_ms - 1);
            result.test_is_true("handshake epoch is readable until the timer expires",
                                acknowledged(retransmission_2, number_2));

            // The timer expired in the meantime
            result.test_is_false("handshake epoch is discarded when the timer expires",
                                 acknowledged(retransmission_3, number_3));
         }),
   };
}

/// Tests KeyUpdates in both directions (RFC 9147 8.)
std::vector<Test::Result> key_updates() {
   using enum TLS::Handshake_Type;
   using enum TLS::Record_Type;

   constexpr auto old_epoch = epoch_appdata_0;
   constexpr auto new_epoch = epoch_appdata_1;
   constexpr size_t initial_timeout_ms = Exchange::initial_timeout_ms;
   constexpr size_t ack_timeout_ms = Exchange::ack_timeout_ms;

   // RFC 9293 3.4.1: Maximum Segment Lifetime of 2 minutes, see RFC 9147 4.2.1
   constexpr uint64_t msl_ms = 2 * 60 * 1000;

   const auto single_record = [](Test::Result& result, const std::vector<Received_Datagram>& wire) -> const auto& {
      result.require("a single datagram holding a single record was sent",
                     wire.size() == 1 && wire.front().records.size() == 1);
      return wire.front().records.front();
   };

   const auto expect_key_update = [=](Test::Result& result,
                                      const std::vector<Received_Datagram>& wire,
                                      TLS::EpochNumber epoch,
                                      bool update_requested) {
      const auto& record = single_record(result, wire);
      result.test_enum_eq("record is a handshake record", record.type, Handshake);
      result.test_is_true("record is protected with the current epoch", record.epoch == epoch);
      result.require("record holds a single fragment", record.fragments.size() == 1);
      result.test_enum_eq("fragment is a KeyUpdate", record.fragments.front().type, KeyUpdate);
      result.test_bin_eq(
         "update_requested", record.fragments.front().bytes, std::vector<uint8_t>(1, update_requested ? 1 : 0));
   };

   const auto expect_application_data =
      [=](Test::Result& result, const std::vector<Received_Datagram>& wire, TLS::EpochNumber epoch) {
         const auto& record = single_record(result, wire);
         result.test_enum_eq("record is an application data record", record.type, ApplicationData);
         result.test_is_true("record is protected with the expected epoch", record.epoch == epoch);
      };

   const auto delivers_application_data = [](Exchange& exchange, const std::vector<uint8_t>& datagram) {
      const auto events = exchange.deliver_to_server(datagram).events;
      return events.size() == 1 && std::holds_alternative<TLS::ApplicationData_Record>(events.front());
   };

   // The server sends a (post-handshake) message ahead of its KeyUpdate. The
   // message is not part of the KeyUpdate, which allows ACKing one without the other.
   const auto send_other_post_handshake_message = [&](Exchange& exchange) {
      return exchange.send_server_flight({synthetic_message(NewSessionTicket, old_epoch, 30)});
   };

   // The server receives a KeyUpdate and the application subsequently sends data
   const auto server_sends_data_after_key_update = [=](Test::Result& result, bool update_requested) {
      Exchange exchange(result, Keys::ApplicationTraffic);
      exchange.commit();
      exchange.server_receives_key_update(update_requested);
      result.test_is_true("nothing is sent right away", exchange.take_server_output().empty());

      auto wire = exchange.send_server_application_data();

      // RFC 9147 8. Reciprocation is a KeyUpdate that has to be acknowledged as any other.
      result.test_is_true("post-handshake messages are blocked while a reciprocating KeyUpdate is pending",
                          exchange.server().io->can_send_post_handshake_messages() != update_requested);
      return wire;
   };

   return {
      CHECK("a KeyUpdate is sent under the current epoch and blocks post-handshake messages until acknowledged",
            [=](Test::Result& result) {
               Exchange exchange(result, Keys::ApplicationTraffic);
               exchange.commit();
               result.require("post-handshake messages are allowed",
                              exchange.server().io->can_send_post_handshake_messages());

               exchange.server().io->update_traffic_keys(false);

               expect_key_update(result, exchange.take_server_output(), old_epoch, false);
               result.test_is_false("post-handshake messages are blocked",
                                    exchange.server().io->can_send_post_handshake_messages());

               // RFC 9147 8.
               //    [...] implementations MUST NOT send records with the new keys [...] until the previous
               //    KeyUpdate has been acknowledged [...].
               result.test_is_true("write epoch is not advanced", exchange.server_write_epoch() == old_epoch);
               expect_application_data(result, exchange.send_server_application_data(), old_epoch);
            }),

      CHECK("the ACK of the KeyUpdate record switches to the new write keys",
            [=](Test::Result& result) {
               Exchange exchange(result, Keys::ApplicationTraffic);
               exchange.commit();
               exchange.server().io->update_traffic_keys(false);
               const auto key_update = exchange.take_server_output();

               exchange.client_acknowledges(record_numbers(key_update));

               result.test_is_true("write epoch is advanced", exchange.server_write_epoch() == new_epoch);
               result.test_is_true("post-handshake messages are allowed again",
                                   exchange.server().io->can_send_post_handshake_messages());

               exchange.peer_reads_with_updated_keys();
               expect_application_data(result, exchange.send_server_application_data(), new_epoch);

               result.test_sz_eq(
                  "retransmission timer is cancelled", exchange.advance_server_clock(2 * initial_timeout_ms), 0);
            }),

      CHECK("an ACK that does not cover the KeyUpdate record does not advance the write keys",
            [=](Test::Result& result) {
               Exchange exchange(result, Keys::ApplicationTraffic);
               exchange.commit();
               const auto other_message = send_other_post_handshake_message(exchange);
               exchange.server().io->update_traffic_keys(false);
               const auto key_update = exchange.take_server_output();

               exchange.client_acknowledges(record_numbers(other_message));

               result.test_is_true("write epoch is not advanced", exchange.server_write_epoch() == old_epoch);
               result.test_is_false("post-handshake messages are still blocked",
                                    exchange.server().io->can_send_post_handshake_messages());
               expect_application_data(result, exchange.send_server_application_data(), old_epoch);

               // The KeyUpdate is retransmitted on its own
               exchange.advance_server_clock(initial_timeout_ms);
               result.test_is_true("only the KeyUpdate is re-sent",
                                   fragments_of(exchange.take_server_output()) == fragments_of(key_update));
            }),

      CHECK("an unacknowledged KeyUpdate is retransmitted under the old epoch",
            [=](Test::Result& result) {
               Exchange exchange(result, Keys::ApplicationTraffic);
               exchange.commit();
               exchange.server().io->update_traffic_keys(false);

               const auto& delays = exchange.server().callbacks->registered_delays();
               result.require("a deferred operation was registered", !delays.empty());
               result.test_u64_eq(
                  "retransmission timer is armed with the initial timeout", delays.back(), initial_timeout_ms);

               const auto original = exchange.take_server_output();
               exchange.advance_server_clock(initial_timeout_ms - 1);
               result.test_is_true("nothing is re-sent before the timeout", exchange.take_server_output().empty());

               exchange.advance_server_clock(1);
               const auto retransmitted = exchange.take_server_output();
               expect_key_update(result, retransmitted, old_epoch, false);
               result.test_is_true("handshake bytes are identical",
                                   fragments_of(retransmitted) == fragments_of(original));
               result.test_is_false("the retransmission is a new record",
                                    contains(record_numbers(original), record_numbers(retransmitted).front()));

               result.test_is_true("write epoch is not advanced", exchange.server_write_epoch() == old_epoch);
               result.test_is_false("post-handshake messages are still blocked",
                                    exchange.server().io->can_send_post_handshake_messages());

               // Acknowledging the retransmission is as good as acknowledging the original
               exchange.client_acknowledges(record_numbers(retransmitted));
               result.test_is_true("write epoch is advanced", exchange.server_write_epoch() == new_epoch);
            }),

      CHECK("old write epochs are discarded once no unacknowledged records remain",
            [=](Test::Result& result) {
               Exchange exchange(result, Keys::ApplicationTraffic);
               exchange.commit();
               const auto other_message = send_other_post_handshake_message(exchange);
               exchange.server().io->update_traffic_keys(false);
               const auto key_update = exchange.take_server_output();

               exchange.client_acknowledges(record_numbers(key_update));
               result.test_is_true("write epoch is advanced", exchange.server_write_epoch() == new_epoch);
               result.test_is_true("old epoch is kept as long as it holds unacknowledged records",
                                   exchange.server_can_write_epoch(old_epoch));

               // Those records are still retransmitted under the epoch they were sent in
               exchange.advance_server_clock(initial_timeout_ms);
               const auto retransmitted = exchange.take_server_output();
               result.test_is_true("the other message is re-sent",
                                   fragments_of(retransmitted) == fragments_of(other_message));
               for(const auto& datagram : retransmitted) {
                  for(const auto& record : datagram.records) {
                     result.test_is_true("record is protected with the old epoch", record.epoch == old_epoch);
                  }
               }

               exchange.client_acknowledges(record_numbers(retransmitted));
               result.test_is_false("old epoch is discarded", exchange.server_can_write_epoch(old_epoch));
               result.test_is_true("new epoch is retained", exchange.server_can_write_epoch(new_epoch));
            }),

      CHECK("a received KeyUpdate advances the read keys and is acknowledged",
            [=](Test::Result& result) {
               Exchange exchange(result, Keys::ApplicationTraffic);
               exchange.commit();

               const auto key_update_record = exchange.server_receives_key_update(false);

               result.test_is_true("read epoch is advanced", exchange.server_read_epoch() == new_epoch);
               result.test_is_true("write epoch is not advanced", exchange.server_write_epoch() == old_epoch);
               result.test_is_true("no immediate response", exchange.take_server_output().empty());

               // KeyUpdates must be acknowledged (RFC 9147 8.), by the same means as other handshake messages
               exchange.advance_server_clock(ack_timeout_ms);
               const auto output = exchange.take_server_output();
               result.test_sz_eq("one ACK record is sent", count_records(output, ACK), 1);
               result.test_is_true("ACK lists the KeyUpdate record",
                                   acknowledged_by(output) == std::vector{key_update_record});
            }),

      CHECK("a received KeyUpdate is not reciprocated unless requested",
            [=](Test::Result& result) {
               expect_application_data(result, server_sends_data_after_key_update(result, false), old_epoch);
            }),

      CHECK("a requested KeyUpdate is reciprocated before the next application data is sent",
            [=](Test::Result& result) {
               const auto wire = server_sends_data_after_key_update(result, true);
               result.require("KeyUpdate and application data are sent in separate datagrams", wire.size() == 2);

               // RFC 9846 4.7.3: [...] MUST send a KeyUpdate of its own with request_update set to
               //                 "update_not_requested" prior to sending its next Application Data record.
               expect_key_update(result, {wire[0]}, old_epoch, false);
               expect_application_data(result, {wire[1]}, old_epoch);
            }),

      CHECK(
         "the previous read epoch is discarded two minutes after the peer started using the new keys",
         [=](Test::Result& result) {
            Exchange exchange(result, Keys::ApplicationTraffic);
            exchange.commit();
            exchange.server_receives_key_update(false);

            // The peer continues with the old keys until it learns that the KeyUpdate was acknowledged.
            // These records are protected now but delivered later on.
            const auto old_epoch_before_any_expiry = exchange.client_sends_application_data().front();
            const auto old_epoch_before_expiry = exchange.client_sends_application_data().front();
            const auto old_epoch_after_expiry = exchange.client_sends_application_data().front();

            // RFC 9147 8.
            //    [...] receivers MUST retain the pre-update keying material until receipt and
            //    successful decryption of a message using the new keys.
            exchange.advance_server_clock(10 * msl_ms);
            result.test_is_true("previous epoch is retained as long as the peer does not use the new keys",
                                delivers_application_data(exchange, old_epoch_before_any_expiry));

            // The peer learned that the KeyUpdate was acknowledged and starts using the new keys
            const auto& delays = exchange.server().callbacks->registered_delays();
            const size_t registered_before = delays.size();
            exchange.peer_writes_with_updated_keys();
            result.test_is_true("new epoch is readable",
                                delivers_application_data(exchange, exchange.client_sends_application_data().front()));
            result.test_is_true("a timer for the maximum segment lifetime is registered",
                                delays.size() > registered_before && delays.back() == msl_ms);

            exchange.advance_server_clock(msl_ms - 1);
            result.test_is_true("previous epoch is readable until the timer expires",
                                delivers_application_data(exchange, old_epoch_before_expiry));

            exchange.advance_server_clock(1);
            result.test_is_false("previous epoch is discarded when the timer expires",
                                 delivers_application_data(exchange, old_epoch_after_expiry));

            result.test_is_true("latest epoch is retained",
                                delivers_application_data(exchange, exchange.client_sends_application_data().front()));
         }),

      CHECK("a post-handshake message under an outdated read epoch is rejected",
            [=](Test::Result& result) {
               Exchange exchange(result, Keys::ApplicationTraffic);
               exchange.commit();
               exchange.server_receives_key_update(false);

               // The peer did not receive the ACK yet and still sends under the old epoch
               const auto message = exchange.client_sends(NewSessionTicket, 20, old_epoch);
               result.require("peer sends a single datagram", message.size() == 1);

               result.test_throws<TLS::TLS_Exception>("message is rejected",
                                                      "Received a new post-handshake message under an outdated epoch",
                                                      [&] { exchange.deliver_to_server(message.front()); });
            }),

      CHECK("a KeyUpdate is requested before the deprotection failure limit is reached",
            [=](Test::Result& result) {
               // RFC 9147 4.5.3
               //    Implementations SHOULD initiate a key update with update_requested before reaching
               //    [the deprotection failure limit].
               constexpr size_t failure_limit = 4;
               Exchange exchange(result, Keys::ApplicationTraffic, failure_limit);
               exchange.commit();

               exchange.server_receives_tampered_records(failure_limit - 1);
               result.test_u64_eq("failures are counted",
                                  exchange.server().cipher_state->current_read_epoch_deprotection_failures(),
                                  failure_limit - 1);

               const auto wire = exchange.send_server_application_data();
               result.require("KeyUpdate and application data are sent in separate datagrams", wire.size() == 2);
               expect_key_update(result, {wire[0]}, old_epoch, true);
               expect_application_data(result, {wire[1]}, old_epoch);
            }),

      CHECK("a deprotection failure limit of zero or one does not provoke KeyUpdates",
            [=](Test::Result& result) {
               for(const size_t failure_limit : {0, 1}) {
                  Exchange exchange(result, Keys::ApplicationTraffic, failure_limit);
                  exchange.commit();

                  expect_application_data(result, exchange.send_server_application_data(), old_epoch);

                  result.test_throws<TLS::TLS_Exception>("first deprotection failure closes the connection",
                                                         "Too many deprotection failures in current read epoch",
                                                         [&] { exchange.server_receives_tampered_records(1); });

                  result.test_is_true("no KeyUpdate was triggered before closing",
                                      exchange.take_server_output().empty());
               }
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls", "tls_channel_io_dtls", send_flights, retransmissions_and_acknowledgements, key_updates);

}  // namespace Botan_Tests

#endif
