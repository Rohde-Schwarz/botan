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

namespace Botan::TLS {

/**
 * Implementation of the DTLS 1.3 handshake protocol layer
 *
 * This component transforms bytes received from the peer into bytes
 * containing plaintext TLS handshake messages and vice versa.
 */
class BOTAN_TEST_API DTLS_Handshake_Layer final : public Handshake_Layer {
   public:
      using TLSHeader = std::array<uint8_t, 4>;
      using DTLSPayload = std::vector<uint8_t>;

      explicit DTLS_Handshake_Layer(Connection_Side side) : Handshake_Layer(side) {}

      bool has_pending_data() const override {
         // TODO: Check if this is correct
         return !m_current_read_message.empty();
      }

      bool copy_data(const Policy& policy, std::span<const uint8_t> bytes) override;

      NextMessageStep next_message_buffer(std::span<const uint8_t> bytes, const Policy& policy) override;

      PreparedHandshakeMessage prepare_message(Handshake_Message_13_Ref message,
                                               Transcript_Hash_State& transcript_hash,
                                               std::optional<uint16_t> dtls_max_fragment_size) override;

      PreparedHandshakeMessage prepare_post_handshake_message(const Post_Handshake_Message_13& message,
                                                              std::optional<uint16_t> dtls_max_fragment_size) override;

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
      uint16_t m_read_message_seq = 0;

      struct ReassembledMessage {
            TLSHeader header;          // msg_type + 3-byte total length, filled in on first fragment
            DTLSPayload payload;       // sized to msg_len once known, filled in as fragments arrive
            bitvector received_bytes;  // tracks which bytes of the payload have been received so far
            bool complete = false;
      };

      std::map<uint16_t, ReassembledMessage> m_current_read_message;  // keyed by message_seq
};

}  // namespace Botan::TLS

#endif
