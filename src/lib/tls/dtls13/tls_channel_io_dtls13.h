/*
* DTLS Channel Mix-in - adding DTLS-specific functionality on demand
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

class DTLS_Channel_IO : public Channel_IO {
   private:
      class TimerToken;

   public:
      DTLS_Channel_IO(Channel_Impl_13& channel,
                      std::shared_ptr<const Policy> policy,
                      std::shared_ptr<Callbacks> callbacks,
                      std::shared_ptr<Record_Layer> record_layer,
                      std::shared_ptr<Handshake_Layer> handshake_layer);

   public:
      void send_record(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) override;

      void send_record(const Flight& flight, Cipher_State* cipher_state) override;

      void send_key_update(Key_Update msg, Cipher_State* cipher_state, const Secret_Logger& logger) override;

      void send_acknowledgements() override;

      void notify_protocol_version_committed() override { m_dtls_version_committed = true; }

      void notify_sent_handshake_flight() override { m_retransmission_timer.flight_sent(); }

      bool protocol_version_committed() const override { return m_dtls_version_committed; }

      void register_pending_key_update(const RecordNumber& record_number) override {
         m_pending_key_update_record = record_number;
      }

      bool has_pending_key_update() const override { return m_pending_key_update_record.has_value(); }

      void maybe_clear_resend_buffer() override {
         // If we're not sure that the peer is using DTLS 1.3, we must not clear
         // the resend buffer as soon as we received any fragment of the peer's
         // flight. If some fragment got lost, we can't ACK and therefore are
         // forced to retransmit our entire previous flight.
         if(m_dtls_version_committed) {
            m_record_layer->clear_resend_buffer();

            // Nothing left to retransmit, stop the timer
            m_retransmission_timer.stop();
         }
      }

      void clear_outstanding_acknowledgements() override { m_record_layer->clear_outstanding_acknowledgements(); }

      bool timeout_check(Cipher_State* cipher_state) override;

      std::optional<std::chrono::milliseconds> next_retransmission_timeout() const override {
         if(!m_retransmission_timer.started()) {
            return std::nullopt;
         }

         return m_retransmission_timer.next_timeout();
      }

      void maybe_arm_dtls_acknowledgement_timer();

      std::vector<uint8_t> current_ack_record(size_t max_plaintext_length) const override {
         return m_record_layer->acknowledgements().serialize(max_plaintext_length);
      }

      void process_acknowledgements(Cipher_State* cipher_state,
                                    std::span<const uint8_t> ack_record,
                                    const Secret_Logger& secret_logger) override {
         // If we receive ACKs before we know for sure that the peer is using
         // DTLS 1.3, we ignore them. The peer might still pick DTLS 1.2, and as
         // a result would depend on a full flight retransmission.
         //
         // This mirrors the behavior of BoringSSL and is needed to pass
         // relevant BoGo tests.
         if(!m_dtls_version_committed) {
            return;
         }

         const auto acks = ACKs(ack_record);
         if(m_record_layer->handle_acknowledgements(acks)) {
            // Nothing left to retransmit, stop the timer
            m_retransmission_timer.stop();
         }

         if(has_pending_key_update() &&
            !m_record_layer->has_unacknowledged_record(m_pending_key_update_record.value())) {
            cipher_state->update_write_keys(secret_logger);
            m_pending_key_update_record.reset();
         }

         // If there's nothing left to retransmit, we can safely discard any
         // outdated write epochs.
         if(!m_record_layer->has_unacknowledged_records()) {
            cipher_state->prune_outdated_write_epochs();
         }

         // RFC 9147 7.2
         //    Upon receipt of an ACK that leaves it with only some messages from
         //    a flight having been acknowledged, an implementation SHOULD
         //    retransmit the unacknowledged messages or fragments.
         //
         // TODO: In the future we might want to use this cipher_state to trigger
         //       an immediate retransmission after receiving a partial ACK from
         //       the peer. For now, we just wait until `timeout_check` is called.
         //
         // Not sending retransmissions immediately mirrors the current behavior
         // of BoringSSL and is expected by BoGo tests.
      }

   private:
      void arm_dtls_retransmission_timer();
      void on_retransmission_timer();

      void maybe_cancel_dtls_acknowledgement_timer();

   private:
      std::shared_ptr<const Policy> m_policy;
      std::shared_ptr<Callbacks> m_callbacks;
      std::shared_ptr<DTLS_Record_Layer> m_record_layer;
      std::shared_ptr<DTLS_Handshake_Layer> m_handshake_layer;

      // This channel owns us and will therefore outlive us
      Channel_Impl_13& m_channel;

      std::shared_ptr<TimerToken> m_ack_token;

      std::shared_ptr<TimerToken> m_retransmission_token;
      DTLS_Retransmission_Timer m_retransmission_timer;

      std::optional<RecordNumber> m_pending_key_update_record;

      bool m_dtls_version_committed = false;
};

}  // namespace Botan::TLS

#endif
