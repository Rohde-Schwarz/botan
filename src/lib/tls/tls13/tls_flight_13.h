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

            /// Set for handshake messages to differentiate between Unprotected
            /// and HandshakeTraffic, allowing one flight to contain messages
            /// from different epochs. For post-handshake messages, this is
            /// always std::nullopt.
            std::optional<Epoch_Number> desired_epoch;  // NOLINT(*non-private-member-variable*)

            Message_Info(Handshake_Type type,
                         SerializedHandshakeMessage serialized_message,
                         std::optional<Epoch_Number> desired_epoch);
      };

   public:
      /**
       * Create an empty flight that can be filled with add().
       * If @p send_ccs is true, a dummy ChangeCipherSpec record will
       * also be put into the outgoing record stream for middlebox
       * compatibility.
       */
      explicit Flight(bool send_ccs = false) : m_send_ccs(send_ccs) {}

      Flight(const Flight& other) = delete;
      Flight(Flight&& other) = default;
      Flight& operator=(const Flight& other) = delete;
      Flight& operator=(Flight&& other) = default;
      ~Flight() = default;

      /**
       * Create a flight from a single handshake message  under
       *  @p desired_epoch, updating @p transcript_hash in the process and
       * letting the user inspect the message via @p callbacks.
       * If @p send_ccs is true, a dummy ChangeCipherSpec record will
       * also be put into the outgoing record stream for middlebox
       * compatibility.
       */
      static Flight from_message(Epoch_Number desired_epoch,
                                 Handshake_Message_13_Ref msg,
                                 Transcript_Hash_State& transcript_hash,
                                 Callbacks& callbacks,
                                 bool send_ccs = false) {
         Flight flight(send_ccs);
         flight.add(desired_epoch, msg, transcript_hash, callbacks);
         return flight;
      }

      /**
       * Add @p msg to the flight under @p desired_epoch, updating @p
       * transcript_hash in the process and letting the user inspect the message
       * via @p callbacks. Use this variant of `add` to add handshake messages
       * where the transcript hash needs to be updated. For post-handshake
       * messages, the corresponding `add()` variant without a transcript hash
       * needs to be used.
       */
      void add(Epoch_Number desired_epoch,
               Handshake_Message_13_Ref msg,
               Transcript_Hash_State& transcript_hash,
               Callbacks& callbacks);

      /**
       * Add @p msg to the flight, letting the user
       * inspect the message via @p callbacks. Use this variant of `add` to add
       * post-handshake messages. For handshake messages, the transcript hash
       * needs to be updated, so the corresponding `add()` variant needs to be
       * used in that case.
       */
      void add(Post_Handshake_Message_13 msg, Callbacks& callbacks);

      bool contains_messages() const { return !m_messages.empty(); }

      bool empty() const { return !contains_messages(); }

      const std::vector<Message_Info>& messages() const { return m_messages; }

      bool send_ccs() const { return m_send_ccs; }

   private:
      std::vector<Message_Info> m_messages;

      bool m_send_ccs;
};

}  // namespace Botan::TLS

#endif
