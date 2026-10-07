/*
* TLS 1.3 Flights
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_flight_13.h>

#include <botan/tls_callbacks.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_transcript_hash_13.h>

#include <utility>

namespace Botan::TLS {

namespace {

/**
 * @returns the static protection epoch number for a given handshake type as
 *          defined in RFC 9846.
 */
std::optional<Epoch_Number> epoch_for_handshake_type(Handshake_Type handshake_type,
                                                     const Flight::PostHandshake post_handshake) {
   // Post-handshake messages are encrypted with whatever application traffic
   // epoch that is currently active, we can't determine this statically.
   if(post_handshake == Flight::PostHandshake::Yes) {
      return std::nullopt;
   }

   // RFC 9846 2.  Figure 1 as well as RFC 9846 2.3 Figure 4
   switch(handshake_type) {
      using enum Handshake_Type;

      case ClientHello:
      case ServerHello:
      case HelloRetryRequest:
         return Epoch_Number::Unprotected;

      case EncryptedExtensions:
      case Certificate:
      case CertificateRequest:
      case CertificateVerify:
      case Finished:
         return Epoch_Number::HandshakeTraffic;

      case EndOfEarlyData:
         return Epoch_Number::EarlyTraffic;

      case NewSessionTicket:
      case KeyUpdate:
         // KeyUpdate and NewSessionTicket are always post-handshake messages,
         // so this function should never reach here (but return early with
         // std::nullopt above).
         BOTAN_ASSERT_UNREACHABLE();

      case HelloRequest:
      case HelloVerifyRequest:
      case ServerKeyExchange:
      case ServerHelloDone:
      case ClientKeyExchange:
      case CertificateUrl:
      case CertificateStatus:
      case HandshakeCCS:
      case MessageHash:
      case None:
         // These messages are not used in TLS 1.3, hence, no TLS 1.3 flight
         // should ever be constructed with one of these messages.
         // (MessageHash is a synthetic transcript-only message, RFC 9846 4.1)
         BOTAN_ASSERT_UNREACHABLE();
   }
}

Flight::Message_Info make_message_info(const Handshake_Message& message, const Flight::PostHandshake post_handshake) {
   auto serialized_message = Handshake_Layer::serialize(message);
   return {
      .wire_type = message.wire_type(),
      .epoch = epoch_for_handshake_type(message.type(), post_handshake),
      .header = TLS_Handshake_Layer::prepare_header(message.wire_type(), serialized_message.size()),
      .serialized = std::move(serialized_message),
   };
}

/**
 * Ensures that the constructed flight sequence is legal. In a sense that,
 * unprotected messages (if any) always come first and never after any
 * protected message. Dummy cipher specs don't interleave with protected
 * messages, and post-handshake flights never contain dummy cipher specs or
 * statically pinned epochs.
 *
 * This function is for debugging purposes and won't be used if the build
 * was configured --without-debug-asserts (the default setting).
 *
 * @throws Internal_Error if the flight message sequence is illegal
 * @returns true if the flight message sequence is legal
 */
[[maybe_unused]] bool valid_message_sequence(std::span<const Flight::Message> flight,
                                             Flight::PostHandshake post_handshake) {
   bool in_protected_portion = false;
   bool change_cipher_spec_seen = false;

   for(const auto& msg_info : flight) {
      std::visit(  //
         overloaded{
            [&](const Flight::Dummy_ChangeCipherSpec&) {
               if(post_handshake == Flight::PostHandshake::Yes) {
                  throw Internal_Error("Flight contains a dummy ChangeCipherSpec in a post-handshake flight");
               }
               if(change_cipher_spec_seen) {
                  throw Internal_Error("Flight contains multiple dummy ChangeCipherSpec messages");
               }
               if(in_protected_portion) {
                  throw Internal_Error("Flight contains a dummy ChangeCipherSpec after a protected message");
               }

               change_cipher_spec_seen = true;
            },
            [&](const Flight::Message_Info& msg_info) {
               const bool static_epoch = msg_info.epoch.has_value();
               const bool protected_message = static_epoch && msg_info.epoch != Epoch_Number::Unprotected;

               if(post_handshake == Flight::PostHandshake::Yes) {
                  if(static_epoch) {
                     throw Internal_Error("Post-handshake flight contains a message with a pre-defined epoch");
                  }
               } else {
                  if(!static_epoch) {
                     throw Internal_Error("Handshake messages must have a pre-defined epoch");
                  }
                  if(protected_message) {
                     in_protected_portion = true;
                  } else if(in_protected_portion) {
                     throw Internal_Error("Flight contains an unprotected message after a protected message");
                  }
               }
            },
         },
         msg_info);
   }

   return true;
}

}  // namespace

std::vector<Flight::Message> Flight::commit() {
   BOTAN_STATE_CHECK(m_messages.has_value());
   BOTAN_STATE_CHECK(!m_messages->empty());

   [[maybe_unused]] const auto post_handshake = m_transcript_hash.has_value() ? PostHandshake::No : PostHandshake::Yes;
   BOTAN_DEBUG_ASSERT(valid_message_sequence(*m_messages, post_handshake));

   return std::exchange(m_messages, {}).value();
}

void Flight::append(const Handshake_Message& message, PostHandshake post_handshake) {
   BOTAN_STATE_CHECK(m_messages.has_value());

   m_callbacks.tls_inspect_handshake_msg(message);

   auto msg_info = make_message_info(message, post_handshake);
   if(post_handshake == PostHandshake::No) {
      BOTAN_ASSERT_NOMSG(m_transcript_hash.has_value());
      m_transcript_hash->get().update(msg_info.header, msg_info.serialized);
   }
   m_messages->push_back(std::move(msg_info));
}

void Flight::append_ccs() {
   BOTAN_STATE_CHECK(m_messages.has_value());
   m_messages->push_back(Dummy_ChangeCipherSpec{});
}

}  // namespace Botan::TLS
