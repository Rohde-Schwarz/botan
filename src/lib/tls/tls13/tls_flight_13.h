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
 * Helper class to coalesce handshake messages into a TLS flight. The class
 * keeps score of the contained messages. It does not marshal them.
 *
 * Note that this class takes references to transcript hash and callbacks
 * objects. The caller is responsible for ensuring that these objects remain
 * valid for the lifetime of the Flight object. The flight object is meant to be
 * used in a single stack frame and not stored for later use.
 */
class Flight {
   public:
      struct Dummy_ChangeCipherSpec {
            static constexpr std::array<uint8_t, 1> serialized = {0x01};
      };

      struct Message_Info {
            Handshake_Type type;
            std::optional<Epoch_Number> epoch;
            HandshakeProtocolHeader header;
            SerializedHandshakeMessage serialized;
      };

      using Message = std::variant<Dummy_ChangeCipherSpec, Message_Info>;

   protected:
      Flight(Transcript_Hash_State* transcript_hash, Callbacks* callbacks) :
            m_transcript_hash(transcript_hash), m_callbacks(callbacks) {}

   public:
      Flight(Transcript_Hash_State& transcript_hash, Callbacks& callbacks) : Flight(&transcript_hash, &callbacks) {}

      Flight(const Flight& other) = delete;
      Flight(Flight&& other) = delete;
      Flight& operator=(const Flight& other) = delete;
      Flight& operator=(Flight&& other) = delete;
      ~Flight() = default;

      /**
       * Add a @p msg to this flight, updating the transcript hash associated
       * with this flight and letting the user inspect the message first via the
       * callbacks.
       *
       * @param msg The handshake message to add to the flight
       */
      void add(Handshake_Message_13_Ref msg);

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
      Transcript_Hash_State* m_transcript_hash;  // NOLINT(*-non-private-member-variables-in-classes)
      Callbacks* m_callbacks;                    // NOLINT(*-non-private-member-variables-in-classes)

      std::vector<Message> m_messages;  // NOLINT(*-non-private-member-variables-in-classes)
};

/**
 * Helper class to coalesce post-handshake messages into a TLS flight.
 */
class PostHandshakeFlight final : public Flight {
   public:
      explicit PostHandshakeFlight(Callbacks& callbacks) : Flight(nullptr, &callbacks) {}

   public:
      void add(Handshake_Message_13_Ref msg, Transcript_Hash_State& transcript_hash, Callbacks& callbacks) = delete;
      void add_dummy_change_cipher_spec() = delete;

   public:
      /**
       * Add a @p msg to this flight, letting the user inspect the message first
       * via the callbacks. The transcript hash is unchanged for post-handshake
       * messages.
       *
       * @param msg The post-handshake message to add to the flight
       */
      void add(Post_Handshake_Message_13 msg);
};

}  // namespace Botan::TLS

#endif
