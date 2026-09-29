/*
* TLS handshake layer implementation for DTLS 1.3
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_LAYER_DTLS13_H_
#define BOTAN_TLS_HANDSHAKE_LAYER_DTLS13_H_

#include <botan/internal/bitvector.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_types_13.h>

namespace Botan::TLS {

/**
 * Implementation of the DTLS 1.3 handshake protocol layer
 *
 * This component transforms bytes received from the peer into bytes
 * containing plaintext TLS handshake messages and vice versa.
 */
class BOTAN_TEST_API DTLS_Handshake_Layer final : public Handshake_Layer {
   public:
      using TLSHeader = HandshakeProtocolHeader;
      using DTLSPayload = SerializedHandshakeMessage;

      /// The byte length of a DTLS handshake fragment header (RFC 9147 Section 5.2)
      static constexpr size_t FRAGMENT_HEADER_LENGTH = 12;

      /**
       * RFC 9147 Section 5.2
       *    If the sequence number is greater than next_receive_seq, the
       *    implementation SHOULD queue the message but MAY discard it.
       *
       * The maximum number of handshake messages beyond the next expected one
       * whose fragments are buffered for reassembly. Fragments of messages
       * further in the future are discarded. This bounds the memory a peer can
       * make us allocate for reassembly and prevents stale reassembly state
       * from lingering until the message sequence space eventually reaches it.
       *
       * The value covers the longest possible flight (ServerHello..Finished
       * including client authentication, 6 messages) plus some slack for
       * multiple post-handshake messages (e.g. NewSessionTicket)
       */
      static constexpr uint16_t MAX_BUFFERED_FUTURE_MESSAGES = 8;

      explicit DTLS_Handshake_Layer(Connection_Side side) : Handshake_Layer(side) {}

      bool has_pending_data() const override {
         // TODO: This probably doesn't make sense for DTLS, not sure...
         return false;
      }

      CopyDataResult copy_data(const Policy& policy, const Handshake_Record& data_from_peer) override;

      NextMessageStep next_message_buffer(std::span<const uint8_t> bytes, const Policy& policy) override;

      /**
       * Splits a handshake message into marshalled fragments, each prefixed
       * with a DTLS handshake fragment header.
       *
       * When @p first_fragment_max_size is provided, the first fragment is
       * capped accordingly. All further fragments are capped by
       * @p max_fragment_size. This allows callers to fill up space remaining in
       * a record that already holds fragments of previous messages. Otherwise,
       * all fragments are capped by @p max_fragment_size.
       *
       * @param type The handshake message type
       * @param msg_bytes The serialized handshake message to fragment
       * @param max_fragment_size The maximum size of each fragment, including
       *                          the DTLS handshake fragment header
       * @param first_fragment_max_size Optional maximum size of the first
       *                                fragment, including the header size.
       *
       * @returns A vector of marshalled handshake message fragments
       */
      std::vector<MarshalledHandshakeMessageFragment> fragment_message(
         Handshake_Type type,
         StrongSpan<const SerializedHandshakeMessage> msg_bytes,
         uint16_t max_fragment_size,
         std::optional<uint16_t> first_fragment_max_size = std::nullopt);

      std::optional<Handshake_Message_13> next_message(const Policy& policy,
                                                       Transcript_Hash_State& transcript_hash) override;

      std::optional<Post_Handshake_Message_13> next_post_handshake_message(const Policy& policy) override;

   protected:
      TLS_Flavor tls_flavor() const override { return TLS_Flavor::DTLS; }

      Handshake_Message_13 parse_handshake_message(Handshake_Type type,
                                                   std::span<const uint8_t> msg,
                                                   const Policy& policy) const override;

   private:
      uint16_t m_send_message_seq = 0;
      uint32_t m_read_message_seq = 0;  // 32-bit to detect msg seqno exhaustion

      struct ReassembledMessage {
            Epoch_Number epoch;        // The record protection epoch this message was received in.
            TLSHeader header;          // msg_type + 3-byte total length, filled in on first fragment
            DTLSPayload payload;       // sized to msg_len once known, filled in as fragments arrive
            bitvector received_bytes;  // tracks which bytes of the payload have been received so far
            bool complete = false;
      };

      Epoch_Number m_current_epoch = Epoch_Number::ApplicationTraffic_0;
      std::map<uint16_t, ReassembledMessage> m_current_read_message;  // keyed by message_seq
};

}  // namespace Botan::TLS

#endif
