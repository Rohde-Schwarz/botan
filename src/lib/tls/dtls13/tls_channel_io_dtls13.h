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
#include <optional>

namespace Botan::TLS {

class Channel_Impl_13;

class DTLS_Channel_IO final : public Channel_IO,
                              public std::enable_shared_from_this<DTLS_Channel_IO> {
   private:
      class TimerToken;

   public:
      DTLS_Channel_IO(Connection_Side side,
                      std::shared_ptr<const Policy> policy_ptr,
                      std::shared_ptr<Callbacks> callbacks);

   private:
      void process(const Handshake_Record& record) override;
      void process(const ACK_Record& ack_record) override;

      void send_flight(std::vector<Flight::Message> flight) override;
      void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override;
      void send_acknowledgements();
      void send_key_update(const Key_Update& msg) override;
      bool can_send_key_update() const override;

      void notify_protocol_version_committed() override { m_dtls_version_committed = true; }

      void notify_protocol_version_committed_and_flight_superseded() override;
      void notify_received_complete_flight() override;
      void notify_received_final_flight() override;

      void schedule_read_epoch_pruning(Epoch_Number latest_epoch) override;

      bool has_unacknowledged_key_update() const { return m_pending_key_update_record.has_value(); }

      void arm_retransmission_timer();
      void maybe_clear_retransmission_buffer();
      void retransmit();

      DTLS_Record_Layer& record_layer() override { return m_record_layer; }

      const DTLS_Record_Layer& record_layer() const override { return m_record_layer; }

      DTLS_Handshake_Layer& handshake_layer() override { return m_handshake_layer; }

      const DTLS_Handshake_Layer& handshake_layer() const override { return m_handshake_layer; }

   private:
      DTLS_Record_Layer m_record_layer;
      DTLS_Handshake_Layer m_handshake_layer;

      SingleshotTimer m_ack_timer;
      RetransmissionTimer m_retransmission_timer;

      std::optional<RecordNumber> m_pending_key_update_record;

      bool m_dtls_version_committed = false;
};

}  // namespace Botan::TLS

#endif
