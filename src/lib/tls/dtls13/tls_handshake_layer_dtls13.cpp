/*
* TLS handshake layer implementation for DTLS 1.3
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_layer_dtls13.h>

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_transcript_hash_13.h>

#include <iostream>

namespace Botan::TLS {

namespace {

std::array<uint8_t, 3> store_be24(uint32_t value) {
   BOTAN_ASSERT_NOMSG(value <= 0xFFFFFF);
   const auto be = store_be(value);
   std::array<uint8_t, 3> result{};
   copy_mem(result, std::span{be}.last<3>());
   return result;
}

struct PreparedHeader {
      std::array<uint8_t, 4> tls_header_bytes = {};
      std::array<uint8_t, 8> dtls_header_bytes = {};
};

constexpr size_t header_length = 12;

struct DTLS_Handshake_Header {
      // NOLINTBEGIN(*-non-private-member-variables-in-classes)

      Handshake_Type msg_type;
      uint32_t message_length;
      uint16_t message_sequence_number;
      uint32_t fragment_offset;
      uint32_t fragment_length;

      // NOLINTEND(*-non-private-member-variables-in-classes)

      std::array<uint8_t, header_length> serialize() const {
         return concat(store_be(to_underlying(msg_type)),
                       store_be24(message_length),
                       store_be(message_sequence_number),
                       store_be24(fragment_offset),
                       store_be24(fragment_length));
      }
};

}  // namespace

bool DTLS_Handshake_Layer::copy_data(const Policy& policy, std::span<const uint8_t> bytes) {
   BufferSlicer bs(bytes);
   while(!bs.empty()) {
      if(bs.remaining() < header_length) {
         throw TLS_Exception(AlertType::DecodeError, "Bad lengths in DTLS header");
      }

      const auto header_bytes = bs.take(header_length);

      // TODO: Implement the parsing in DTLS_Handshake_Header
      const auto msg_len = make_uint32(0, header_bytes[1], header_bytes[2], header_bytes[3]);
      const auto msg_seq = make_uint16(header_bytes[4], header_bytes[5]);
      const auto frag_offset = make_uint32(0, header_bytes[6], header_bytes[7], header_bytes[8]);
      const auto frag_len = make_uint32(0, header_bytes[9], header_bytes[10], header_bytes[11]);

      if(policy.maximum_handshake_message_size() > 0 && msg_len > policy.maximum_handshake_message_size()) {
         throw TLS_Exception(Alert::DecodeError, "msg_len exceeds maximum handshake message size");
      }

      if(frag_offset + frag_len > msg_len) {
         throw TLS_Exception(Alert::IllegalParameter, "Invalid DTLS handshake fragment received");
      }

      // RFC 9147 Section 5.2
      //   If the sequence number is less than next_receive_seq, the message
      //   MUST be discarded.
      //
      // Note that the given `bytes` span might contain more fragments which we
      // would then just drop as well. It seems highly unlikely that those would
      // not be part of the same retransmission anyway.
      if(msg_seq < m_read_message_seq) {
         return false;
      }

      // TODO: iterative allocation of the reassembled message to avoid DoS attacks with large messages
      // TODO: It could make sense to commit fragments only once the entire `bytes` buffer was
      //       processed successfully. It might be surprising that datagrams are processed
      //       partially. E.g., in the record layer we're using this approach as well.
      m_current_read_message.try_emplace(
         msg_seq,
         ReassembledMessage{
            // TODO: Parse the header already now and error-out if the header
            //       appears bogus. Note: There's also a commented-out test
            //       for that in test_tls_dtls13_handshake_layer.cpp, called
            //       "parse ClientHello detects incoming garbage data with invalid message type".
            .header = {header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]},
            .payload = DTLSPayload(msg_len),
            .received_bytes = bitvector(msg_len),
            .complete = false,
         });
      // TODO: use the iterator from try_emplace
      auto& reassembled = m_current_read_message.at(msg_seq);

      if(reassembled.payload.size() != msg_len || reassembled.received_bytes.size() != msg_len ||
         load_be(header_bytes.first<4>()) != load_be(reassembled.header)) {
         throw TLS_Exception(Alert::IllegalParameter, "Inconsistent values in fragmented DTLS handshake header");
      }

      // RFC 9147 5.5
      //
      //    DTLS implementations MUST be able to handle overlapping fragment
      //    ranges. This allows senders to retransmit handshake messages with
      //    smaller fragment sizes if the PMTU estimate changes. Senders MUST
      //    NOT change handshake message bytes upon retransmission. Receivers
      //    MAY check that retransmitted bytes are identical and SHOULD abort
      //    the handshake with an "illegal_parameter" alert if the value of a
      //    byte changes
      //
      // We choose to not check that retransmitted bytes are identical to
      // simplify the implementation. Possible bogus bytes will be recognized
      // in the transcript hash check.

      // Advance bs and copy the fragment into the reassembled message
      if(bs.remaining() < frag_len) {
         throw TLS_Exception(AlertType::DecodeError, "Truncated DTLS handshake fragment received");
      }
      copy_mem(std::span(reassembled.payload).subspan(frag_offset, frag_len), bs.take(frag_len));

      for(size_t i = frag_offset; i < frag_offset + frag_len; ++i) {
         reassembled.received_bytes.set(i);  // TODO: an efficient way to set a range of bits
      }

      if(reassembled.received_bytes.all_vartime()) {
         reassembled.complete = true;
      }
   }

   BOTAN_ASSERT_NOMSG(bs.empty());

   return true;
}

Handshake_Layer::NextMessageStep DTLS_Handshake_Layer::next_message_buffer(std::span<const uint8_t> bytes,
                                                                           const Policy& policy) {
   // TODO: Remove
   BOTAN_UNUSED(bytes, policy);
   throw Not_Implemented("will be removed");
}

std::optional<Handshake_Message_13> DTLS_Handshake_Layer::next_message(const Policy& policy,
                                                                       Transcript_Hash_State& transcript_hash) {
   auto message = m_current_read_message.find(m_read_message_seq);
   if(message == m_current_read_message.end()) {
      return std::nullopt;
   }

   auto& reassembled = message->second;
   if(!reassembled.complete) {
      return std::nullopt;
   }

   auto msg = parse_handshake_message(read_handshake_message_type(reassembled.header[0]), reassembled.payload, policy);

   // Update the transcript hash and remove the reassembled message from the map in case of successful parsing
   transcript_hash.update(reassembled.header, reassembled.payload);
   m_current_read_message.erase(m_read_message_seq++);

   return msg;
}

std::optional<Post_Handshake_Message_13> DTLS_Handshake_Layer::next_post_handshake_message(const Policy& policy) {
   BOTAN_UNUSED(policy);

   auto message = m_current_read_message.find(m_read_message_seq);
   if(message == m_current_read_message.end()) {
      return std::nullopt;
   }

   auto& reassembled = message->second;
   if(!reassembled.complete) {
      return std::nullopt;
   }

   auto msg = parse_post_handshake_message(read_handshake_message_type(reassembled.header[0]), reassembled.payload);

   m_current_read_message.erase(m_read_message_seq++);
   return msg;
}

namespace {
//TODO: de-duplicate, this is copied from TLS handshake layer
template <typename T>
const T& get(const std::reference_wrapper<T>& v) {
   return v.get();
}

template <typename T>
const T& get(const T& v) {
   // NOLINTNEXTLINE(bugprone-return-const-ref-from-parameter)
   return v;
}

template <typename T>
auto serialize_message(const T& message) {
   return std::visit([](const auto& msg) { return std::pair(get(msg).wire_type(), get(msg).serialize()); }, message);
}

}  //namespace

PreparedHandshakeMessage DTLS_Handshake_Layer::prepare_message(const Handshake_Message_13_Ref message,
                                                               Transcript_Hash_State& transcript_hash,
                                                               std::optional<uint16_t> dtls_max_fragment_size) {
   // TODO: Clean this up: the code duplication with prepare_post_handshake_message() is unfortunate.

   BOTAN_ARG_CHECK(dtls_max_fragment_size.has_value(), "DTLS max fragment size must be provided");
   BOTAN_ARG_CHECK(dtls_max_fragment_size.value() > header_length,
                   "DTLS max fragment size must be larger than header length");

   auto [type, msg_bytes] = serialize_message(message);

   const uint16_t message_seq = m_send_message_seq++;

   const auto max_bytes_per_fragment = dtls_max_fragment_size.value() - header_length;
   const auto number_of_fragments = ceil_division(msg_bytes.size(), max_bytes_per_fragment);
   BOTAN_ASSERT_NOMSG(number_of_fragments > 0);

   std::vector<MarshalledHandshakeMessageFragment> fragments;
   fragments.reserve(number_of_fragments);

   BufferSlicer bs(msg_bytes);
   while(!bs.empty()) {
      const auto bytes_in_this_fragment = std::min(bs.remaining(), max_bytes_per_fragment);
      const auto header = DTLS_Handshake_Header{
         .msg_type = type,
         .message_length = static_cast<uint32_t>(msg_bytes.size()),
         .message_sequence_number = message_seq,
         .fragment_offset = static_cast<uint32_t>(msg_bytes.size() - bs.remaining()),
         .fragment_length = static_cast<uint32_t>(bytes_in_this_fragment),
      };
      fragments.push_back(
         concat<MarshalledHandshakeMessageFragment>(header.serialize(), bs.take(bytes_in_this_fragment)));
   }
   BOTAN_ASSERT_NOMSG(fragments.size() == number_of_fragments);

   const auto tls_header = std::span{fragments.front()}.first<4>();
   transcript_hash.update(tls_header, msg_bytes);

   return fragments;
}

PreparedHandshakeMessage DTLS_Handshake_Layer::prepare_post_handshake_message(
   const Post_Handshake_Message_13& message, std::optional<uint16_t> dtls_max_fragment_size) {
   // TODO: Clean this up: the code duplication with prepare_message() is unfortunate.

   BOTAN_ARG_CHECK(dtls_max_fragment_size.has_value(), "DTLS max fragment size must be provided");
   BOTAN_ARG_CHECK(dtls_max_fragment_size.value() > header_length,
                   "DTLS max fragment size must be larger than header length");

   auto [type, msg_bytes] = serialize_message(message);

   const uint16_t message_seq = m_send_message_seq++;

   const auto max_bytes_per_fragment = dtls_max_fragment_size.value() - header_length;
   const auto number_of_fragments = ceil_division(msg_bytes.size(), max_bytes_per_fragment);
   BOTAN_ASSERT_NOMSG(number_of_fragments > 0);

   std::vector<MarshalledHandshakeMessageFragment> fragments;
   fragments.reserve(number_of_fragments);

   BufferSlicer bs(msg_bytes);
   while(!bs.empty()) {
      const auto bytes_in_this_fragment = std::min(bs.remaining(), max_bytes_per_fragment);
      const auto header = DTLS_Handshake_Header{
         .msg_type = type,
         .message_length = static_cast<uint32_t>(msg_bytes.size()),
         .message_sequence_number = message_seq,
         .fragment_offset = static_cast<uint32_t>(msg_bytes.size() - bs.remaining()),
         .fragment_length = static_cast<uint32_t>(bytes_in_this_fragment),
      };
      fragments.push_back(
         concat<MarshalledHandshakeMessageFragment>(header.serialize(), bs.take(bytes_in_this_fragment)));
   }
   BOTAN_ASSERT_NOMSG(fragments.size() == number_of_fragments);

   return fragments;
}

Handshake_Message_13 DTLS_Handshake_Layer::parse_handshake_message(Handshake_Type type,
                                                                   std::span<const uint8_t> msg,
                                                                   const Policy& policy) const {
   switch(type) {
      case Handshake_Type::HelloVerifyRequest:
         // DTLS 1.2 cookie exchange; triggers a client-side downgrade when
         // DTLS 1.2 is allowed. Acceptance is enforced by Client_Impl_13.
         return Hello_Verify_Request(msg);
      default:
         return Handshake_Layer::parse_handshake_message(type, msg, policy);
   }
}

}  // namespace Botan::TLS
