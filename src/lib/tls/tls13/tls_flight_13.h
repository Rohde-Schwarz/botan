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

namespace Botan::TLS {

/**
 * Helper class to coalesce handshake messages into a TLS flight.
 * The class keeps score of the contained messages. It does not marshal
 * them.
 */
class Flight final {
   public:
      struct Message_Info {
            Handshake_Type type;                    // NOLINT(*non-private-member-variable*)
            HandshakeProtocolHeader header;         // NOLINT(*non-private-member-variable*)
            SerializedHandshakeMessage serialized;  // NOLINT(*non-private-member-variable*)

            Message_Info(Handshake_Type type, SerializedHandshakeMessage serialized_message);
      };

   public:
      Flight() = default;

      Flight(const Flight& other) = delete;
      Flight(Flight&& other) = default;
      Flight& operator=(const Flight& other) = delete;
      Flight& operator=(Flight&& other) = default;
      ~Flight() = default;

      /**
       * Create a flight containing a single (post-)handshake message.
       */
      template <typename... ParamTs>
      static Flight from_message(ParamTs&&... params) {
         Flight flight;
         flight.add(std::forward<ParamTs>(params)...);
         return flight;
      }

      /**
       * Add @p msg to the flight, updating @p transcript_hash in the process and letting
       * the user inspect the message via @p callbacks.
       * Use this variant of `add` to add handshake messages where the transcript hash
       * needs to be updated. For post-handshake messages, the corresponding `add()`
       * variant without a transcript hash needs to be used.
       */
      void add(Handshake_Message_13_Ref msg, Transcript_Hash_State& transcript_hash, Callbacks& callbacks);

      /**
       * Add @p msg to the flight, letting the user inspect the message via @p callbacks.
       * Use this variant of `add` to add post-handshake messages. For handshake messages, the transcript
       * hash needs to be updated, so the corresponding `add()` variant needs to be used in that case.
       */
      void add(Post_Handshake_Message_13 msg, Callbacks& callbacks);

      bool contains_messages() const { return !m_messages.empty(); }

      bool empty() const { return !contains_messages(); }

      const std::vector<Message_Info>& messages() const { return m_messages; }

   private:
      std::vector<Message_Info> m_messages;
};

}  // namespace Botan::TLS

#endif
