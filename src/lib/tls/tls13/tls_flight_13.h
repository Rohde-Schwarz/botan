/*
* TLS 1.3 Flights
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_FLIGHT_13_H_
#define BOTAN_TLS_FLIGHT_13_H_

#include <botan/tls_magic.h>
#include <botan/tls_messages_13.h>
#include <botan/internal/tls_types_13.h>
#include <optional>
#include <variant>
#include <vector>

namespace Botan::TLS {

class Callbacks;
class Transcript_Hash_State;

/**
 * Helper class to coalesce handshake messages into a TLS flight.
 * The class keeps score of the contained messages. It does not marshal
 * them.
 */
class Flight {
   public:
      enum class PostHandshake : bool { No = false, Yes = true };

      struct Dummy_ChangeCipherSpec {};

      struct Message_Info {
            Handshake_Type type;
            std::optional<Epoch_Number> epoch;
            HandshakeProtocolHeader header;
            SerializedHandshakeMessage serialized;
      };

      using Message = std::variant<Dummy_ChangeCipherSpec, Message_Info>;

   protected:
      explicit Flight(PostHandshake post_handshake) : m_post_handshake(post_handshake) {}

   public:
      Flight() : Flight(PostHandshake::No) {}

      Flight(const Flight& other) = delete;
      Flight(Flight&& other) = default;
      Flight& operator=(const Flight& other) = delete;
      Flight& operator=(Flight&& other) = default;
      ~Flight() = default;

      /**
       * Add @p msg to the flight, updating @p transcript_hash in the process and
       * letting the user inspect the message via @p callbacks. Use this variant
       * of `add` to add handshake messages where the transcript hash needs to be
       * updated. For post-handshake messages, the corresponding `add()` variant
       * without a transcript hash needs to be used.
       */
      void add(Handshake_Message_13_Ref msg, Transcript_Hash_State& transcript_hash, Callbacks& callbacks);

      /**
       * Add a dummy ChangeCipherSpec message to the flight when following the
       * compatibility mode for TLS 1.3. See RFC 9846 E.4 for details.
       */
      void add_dummy_change_cipher_spec();

      /**
       * Extract the messages from the flight for sending. This invalidates the
       * flight object and it cannot be used anymore.
       */
      std::vector<Message> commit();

   protected:
      PostHandshake m_post_handshake;   // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<Message> m_messages;  // NOLINT(*-non-private-member-variables-in-classes)
};

/**
 * Helper class to coalesce post-handshake messages into a TLS flight.
 */
class PostHandshakeFlight final : public Flight {
   public:
      PostHandshakeFlight() : Flight(PostHandshake::Yes) {}

   public:
      void add(Handshake_Message_13_Ref msg, Transcript_Hash_State& transcript_hash, Callbacks& callbacks) = delete;
      void add_dummy_change_cipher_spec() = delete;

   public:
      /**
       * Add @p msg to the flight, letting the user
       * inspect the message via @p callbacks. Use this variant of `add` to add
       * post-handshake messages. For handshake messages, the transcript hash
       * needs to be updated, so the corresponding `add()` variant needs to be
       * used in that case.
       */
      void add(Post_Handshake_Message_13 msg, Callbacks& callbacks);
};

}  // namespace Botan::TLS

#endif
