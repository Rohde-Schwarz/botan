/*
* DTLS Channel IO - handle DTLS IO specifics
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IO_DTLS13_H_
#define BOTAN_TLS_CHANNEL_IO_DTLS13_H_

#include <botan/assert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_channel_io.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_layer_dtls13.h>
#include <botan/internal/tls_record_layer_dtls13.h>
#include <botan/internal/tls_timer_dtls13.h>
#include <chrono>
#include <optional>

namespace Botan::TLS {

class Channel_Impl_13;

class DTLS_Channel_IO final : public Channel_IO {
   private:
      class TimerToken;

   public:
      DTLS_Channel_IO(Connection_Side side,
                      std::weak_ptr<Channel_Impl_13> channel,
                      std::shared_ptr<const Policy> policy_ptr,
                      std::shared_ptr<Callbacks> callbacks);

   public:
      void process(const Handshake_Record& record) override;

      void process(const ACK_Record& ack_record) override;

      void send_records(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override;

      void send_flight(std::vector<Flight::Message> flight) override;

      void send_key_update(Key_Update msg) override;

      void send_acknowledgements();

      void notify_protocol_version_committed() override { m_dtls_version_committed = true; }

      void notify_protocol_version_committed_and_flight_superseded() override;

      void notify_received_complete_flight() override;

      void notify_received_final_flight() override;

      bool has_pending_key_update() const override { return m_pending_key_update_record.has_value(); }

   private:
      void notify_sent_handshake_flight() { m_retransmission_timer.flight_sent(); }

      void maybe_clear_resend_buffer() {
         // If we're not sure that the peer is using DTLS 1.3, we must not clear
         // the resend buffer as soon as we received any fragment of the peer's
         // flight. If some fragment got lost, we can't ACK and therefore are
         // forced to retransmit our entire previous flight.
         if(m_dtls_version_committed) {
            record_layer().clear_resend_buffer();

            // Nothing left to retransmit, stop the timer
            m_retransmission_timer.stop();
         }
      }

      void maybe_retransmit(Cipher_State* cipher_state);

      std::optional<std::chrono::milliseconds> next_retransmission_timeout() const {
         if(!m_retransmission_timer.started()) {
            return std::nullopt;
         }

         return m_retransmission_timer.next_timeout();
      }

      void maybe_arm_dtls_acknowledgement_timer();

      std::vector<uint8_t> current_ack_record(size_t max_plaintext_length) const {
         return record_layer().acknowledgements().serialize(max_plaintext_length);
      }

   private:
      void arm_dtls_retransmission_timer();
      void on_retransmission_timer();

      void maybe_cancel_dtls_acknowledgement_timer();

      DTLS_Record_Layer& record_layer() override { return m_record_layer; }

      const DTLS_Record_Layer& record_layer() const override { return m_record_layer; }

      DTLS_Handshake_Layer& handshake_layer() override { return m_handshake_layer; }

      const DTLS_Handshake_Layer& handshake_layer() const override { return m_handshake_layer; }

   private:
      DTLS_Record_Layer m_record_layer;
      DTLS_Handshake_Layer m_handshake_layer;

      std::shared_ptr<TimerToken> m_ack_token;

      std::shared_ptr<TimerToken> m_retransmission_token;
      DTLS_Retransmission_Timer m_retransmission_timer;

      std::optional<RecordNumber> m_pending_key_update_record;

      bool m_dtls_version_committed = false;
};

}  // namespace Botan::TLS

#endif
