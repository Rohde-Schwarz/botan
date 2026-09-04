/*
* TLS handshake state (machine) implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_layer_13.h>

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_transcript_hash_13.h>

#if defined(BOTAN_HAS_DTLS_13)
   #include <botan/internal/tls_handshake_layer_dtls13.h>
#endif

namespace Botan::TLS {

namespace {

constexpr size_t HEADER_LENGTH = 4;

template <typename Msg_Type>
Handshake_Type handshake_type_from_byte(uint8_t byte_value) {
   const auto type = static_cast<Handshake_Type>(byte_value);

   if constexpr(std::is_same_v<Msg_Type, Handshake_Message_13>) {
      switch(type) {
         case Handshake_Type::ClientHello:
         case Handshake_Type::ServerHello:
         // case Handshake_Type::EndOfEarlyData:  // NYI: needs PSK/resumption support -- won't be offered in Client Hello for now
         case Handshake_Type::EncryptedExtensions:
         case Handshake_Type::Certificate:
         case Handshake_Type::CertificateRequest:
         case Handshake_Type::CertificateVerify:
         case Handshake_Type::Finished:
            return type;
         default:
            throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown handshake message received");
      }
   } else {
      switch(type) {
         case Handshake_Type::NewSessionTicket:
         case Handshake_Type::KeyUpdate:
            // case Handshake_Type::CertificateRequest:  // NYI: post-handshake client auth (RFC 8446 4.6.2) -- won't be offered in Client Hello for now
            return type;
         default:
            throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown post-handshake message received");
      }
   }
}

void verify_handshake_message_size(size_t msg_len, size_t max_size) {
   if(max_size > 0 && msg_len > max_size) {
      throw TLS_Exception(Alert::HandshakeFailure,
                          Botan::fmt("Handshake message is {} bytes, policy maximum is {}", msg_len, max_size));
   }
}

std::array<uint8_t, 4> prepare_tls_header(Handshake_Type type, std::span<const uint8_t> msg_bytes) {
   BOTAN_ASSERT_NOMSG(msg_bytes.size() <= 0xFFFFFF);
   const uint32_t msg_size = static_cast<uint32_t>(msg_bytes.size());

   return {
      static_cast<uint8_t>(type),
      get_byte<1>(msg_size),
      get_byte<2>(msg_size),
      get_byte<3>(msg_size),
   };
}

class TLS_Handshake_Layer final : public Handshake_Layer {
   public:
      explicit TLS_Handshake_Layer(Connection_Side whoami) : Handshake_Layer(whoami) {}

      bool has_pending_data() const override { return m_read_offset < m_read_buffer.size(); }

      bool copy_data(const Policy& /* policy */, std::span<const uint8_t> data_from_peer) override {
         // Compact consumed data before appending new data
         BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());
         if(m_read_offset > 0) {
            m_read_buffer.erase(m_read_buffer.begin(), m_read_buffer.begin() + m_read_offset);
            m_read_offset = 0;
         }

         m_read_buffer.insert(m_read_buffer.end(), data_from_peer.begin(), data_from_peer.end());
         return true;
      }

      NextMessageStep next_message_buffer(std::span<const uint8_t> bytes, const Policy& policy) override {
         // read the message header
         if(bytes.size() < HEADER_LENGTH) {
            return IncompleteNotProcessed{};
         }

         const auto type = read_handshake_message_type(bytes[0]);
         const auto msg_len = make_uint32(0, bytes[1], bytes[2], bytes[3]);

         // TODO(Botan4) this is split out due to a GCC 11 ICE, can be inlined
         verify_handshake_message_size(msg_len, policy.maximum_handshake_message_size());

         if(bytes.size() < HEADER_LENGTH + msg_len) {
            return IncompleteNotProcessed{};
         }

         return NextMessageResult{
            .type = type,
            .tls_header_bytes = bytes.subspan<0, HEADER_LENGTH>(),
            .message_bytes = bytes.subspan(HEADER_LENGTH, msg_len),
            .bytes_consumed = HEADER_LENGTH + msg_len,
         };
      }

      std::optional<Handshake_Message_13> next_message(const Policy& policy,
                                                       Transcript_Hash_State& transcript_hash) override {
         BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());
         auto pending = std::span<const uint8_t>{m_read_buffer}.subspan(m_read_offset);

         while(!pending.empty()) {
            const auto step = next_message_buffer(pending, policy);
            if(std::holds_alternative<IncompleteNotProcessed>(step)) {
               // We need more bytes and do not need to advance the read offset
               break;
            }

            if(const auto* processed = std::get_if<IncompleteProcessed>(&step)) {
               // We have processed a fragment and advanced the state accordingly, but
               // the message is not complete yet. We need to advance the read offset
               // and continue processing.
               m_read_offset += processed->bytes_consumed;
               BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());
               pending = std::span<const uint8_t>{m_read_buffer}.subspan(m_read_offset);
               continue;
            }

            BOTAN_ASSERT_NOMSG(std::holds_alternative<NextMessageResult>(step));

            const auto& result = std::get<NextMessageResult>(step);
            auto msg = parse_handshake_message(result.type, result.message_bytes, policy);

            transcript_hash.update(result.tls_header_bytes, result.message_bytes);
            m_read_offset += result.bytes_consumed;
            BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());

            if(m_read_offset == m_read_buffer.size()) {
               m_read_buffer.clear();
               m_read_offset = 0;
            }

            return msg;
         }

         return std::nullopt;
      }

      std::optional<Post_Handshake_Message_13> next_post_handshake_message(const Policy& policy) override {
         // TODO: Looping like in next_message() to handle fragmented post-handshake messages.
         BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());
         auto pending = std::span<const uint8_t>{m_read_buffer}.subspan(m_read_offset);

         const auto header_and_msg = next_message_buffer(pending, policy);
         if(std::holds_alternative<IncompleteNotProcessed>(header_and_msg)) {
            return std::nullopt;
         }

         if(const auto* processed = std::get_if<NextMessageResult>(&header_and_msg)) {
            auto msg = parse_post_handshake_message(processed->type, processed->message_bytes);

            m_read_offset += processed->bytes_consumed;
            BOTAN_ASSERT_NOMSG(m_read_offset <= m_read_buffer.size());

            if(m_read_offset == m_read_buffer.size()) {
               m_read_buffer.clear();
               m_read_offset = 0;
            }

            return msg;
         }

         return std::nullopt;
      }

   protected:
      TLS_Flavor tls_flavor() const override { return TLS_Flavor::TLS; }

   private:
      std::vector<uint8_t> m_read_buffer;
      size_t m_read_offset = 0;
};

}  // namespace

Handshake_Message_13 Handshake_Layer::parse_handshake_message(Handshake_Type type,
                                                              std::span<const uint8_t> msg,
                                                              const Policy& policy) const {
   switch(type) {
      // Client Hello and Server Hello messages are ambiguous. Both may come
      // from non-TLS 1.3 peers. Hence, their parsing is somewhat different.
      case Handshake_Type::ClientHello:
         // ... might be TLS 1.2 Client Hello or TLS 1.3 Client Hello
         return generalize_to<Handshake_Message_13>(Client_Hello_13::parse(msg));
      case Handshake_Type::ServerHello:
         // ... might be TLS 1.2 Server Hello or TLS 1.3 Server Hello or
         // a TLS 1.3 Hello Retry Request disguising as a Server Hello
         return generalize_to<Handshake_Message_13>(Server_Hello_13::parse(msg, tls_flavor()));
      // case Handshake_Type::EndOfEarlyData:
      //    return End_Of_Early_Data(msg);
      case Handshake_Type::EncryptedExtensions:
         return Encrypted_Extensions(msg);
      case Handshake_Type::Certificate:
         return Certificate_13(msg, policy, peer(), certificate_type());
      case Handshake_Type::CertificateRequest:
         return Certificate_Request_13(msg, peer());
      case Handshake_Type::CertificateVerify:
         return Certificate_Verify_13(msg, peer());
      case Handshake_Type::Finished:
         return Finished_13({msg.begin(), msg.end()});
      default:
         throw TLS_Exception(AlertType::UnexpectedMessage, "Unexpected handshake message received");
   }
}

Post_Handshake_Message_13 Handshake_Layer::parse_post_handshake_message(Handshake_Type type,
                                                                        std::span<const uint8_t> msg) const {
   switch(type) {
      case Handshake_Type::NewSessionTicket:
         return New_Session_Ticket_13(msg, peer());
      case Handshake_Type::KeyUpdate:
         return Key_Update(msg);
      default:
         throw TLS_Exception(AlertType::UnexpectedMessage, "Unexpected post-handshake message received");
   }
}

std::unique_ptr<Handshake_Layer> Handshake_Layer::create(Connection_Side whoami, TLS_Flavor flavor) {
   if(flavor == TLS_Flavor::DTLS) {
#if defined(BOTAN_HAS_DTLS_13)
      return std::make_unique<DTLS_Handshake_Layer>(whoami);
#else
      throw TLS_Exception(AlertType::InternalError, "DTLS 1.3 is not supported in this build");
#endif
   } else {
      return std::make_unique<TLS_Handshake_Layer>(whoami);
   }
}

namespace {

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

PreparedHandshakeMessage Handshake_Layer::prepare_message(Handshake_Message_13_Ref message,
                                                          Transcript_Hash_State& transcript_hash,
                                                          std::optional<uint16_t> dtls_max_fragment_size) {
   BOTAN_UNUSED(dtls_max_fragment_size);  // Only relevant for DTLS

   auto [type, msg_bytes] = serialize_message(message);

   const auto tls_header = prepare_tls_header(type, msg_bytes);

   transcript_hash.update(tls_header, msg_bytes);

   return concat<MarshalledHandshakeMessage>(tls_header, msg_bytes);
}

void Handshake_Layer::update_transcript_for_psk_binder_calc(const Client_Hello_13& message,
                                                            Transcript_Hash_State& transcript_hash) {
   const auto msg_bytes = message.serialize();

   transcript_hash.update(prepare_tls_header(message.wire_type(), msg_bytes), msg_bytes);
}

PreparedHandshakeMessage Handshake_Layer::prepare_post_handshake_message(
   const Post_Handshake_Message_13& message, std::optional<uint16_t> dtls_max_fragment_size) {
   BOTAN_UNUSED(dtls_max_fragment_size);  // Only relevant for DTLS

   auto [type, msg_bytes] = serialize_message(message);

   const auto tls_header = prepare_tls_header(type, msg_bytes);

   return concat<MarshalledHandshakeMessage>(tls_header, msg_bytes);
}

Handshake_Type Handshake_Layer::read_handshake_message_type(uint8_t value) {
   constexpr auto supported_hs_msgs = std::array{
      Handshake_Type::ClientHello,
      Handshake_Type::ServerHello,
      Handshake_Type::HelloVerifyRequest,
      // NYI: needs PSK/resumption support -- won't be offered in Client Hello for now
      // Handshake_Type::EndOfEarlyData,
      Handshake_Type::EncryptedExtensions,
      Handshake_Type::Certificate,
      Handshake_Type::CertificateRequest,
      Handshake_Type::CertificateVerify,
      Handshake_Type::Finished,
      Handshake_Type::NewSessionTicket,
      Handshake_Type::KeyUpdate,
   };

   const auto type = static_cast<Handshake_Type>(value);
   if(std::find(supported_hs_msgs.begin(), supported_hs_msgs.end(), type) == supported_hs_msgs.end()) {
      throw TLS_Exception(AlertType::UnexpectedMessage, "Unknown handshake message received");
   }

   return type;
}

}  // namespace Botan::TLS
