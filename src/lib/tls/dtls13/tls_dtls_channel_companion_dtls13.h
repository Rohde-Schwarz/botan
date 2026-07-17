/*
* DTLS Channel Mix-in - adding DTLS-specific functionality on demand
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_COMPANION_DTLS13_H_
#define BOTAN_TLS_CHANNEL_COMPANION_DTLS13_H_

#include <botan/assert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_dtls_channel_companion.h>
#include <botan/internal/tls_record_layer_dtls13.h>
#include <botan/internal/tls_timer_dtls13.h>
#include <chrono>
#include <optional>

namespace Botan::TLS {

class DTLS_Channel_Companion_DTLS : public DTLS_Channel_Companion {
   public:
      DTLS_Channel_Companion_DTLS(std::shared_ptr<const Policy> policy,
                                  std::shared_ptr<Callbacks> callbacks,
                                  std::shared_ptr<Record_Layer> record_layer) :
            m_policy(std::move(policy)),
            m_callbacks(std::move(callbacks)),
            m_record_layer(std::dynamic_pointer_cast<DTLS_Record_Layer>(std::move(record_layer))),
            m_retransmission_timer(*m_policy, m_callbacks) {
         BOTAN_ASSERT_NONNULL(m_callbacks);
         BOTAN_ASSERT_NONNULL(m_record_layer);
      }

   public:
      void notify_protocol_version_committed() override { m_dtls_version_committed = true; }

      void notify_sent_handshake_flight() override { m_retransmission_timer.flight_sent(); }

      void clear_resend_buffer() override { m_record_layer->clear_resend_buffer(); }

      void clear_outstanding_acknowledgements() override { m_record_layer->clear_outstanding_acknowledgements(); }

      bool timeout_check(Cipher_State* cipher_state) override {
         if(!m_retransmission_timer.started()) {
            return false;
         }

         if(m_retransmission_timer.retransmissions_exhausted()) {
            throw TLS_Exception(Alert::None, "DTLS handshake timed out: maximum retransmissions exceeded");
         }

         if(!m_retransmission_timer.expired()) {
            return false;  // timer has not yet expired
         }

         for(const auto& record_to_write : m_record_layer->prepare_unacknowledged_records(cipher_state)) {
            m_callbacks->tls_emit_data(record_to_write);
         }
         m_retransmission_timer.retransmitted();
         return true;
      }

      std::optional<std::chrono::milliseconds> next_retransmission_timeout() const override {
         if(!m_retransmission_timer.started()) {
            return std::nullopt;
         }

         return m_retransmission_timer.next_timeout();
      }

      std::vector<uint8_t> current_ack_record() const override {
         return m_record_layer->acknowledgements().serialize();
      }

      void process_acknowledgements(Cipher_State* cipher_state, std::span<const uint8_t> ack_record) override {
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
         m_record_layer->handle_acknowledgements(acks);

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
         BOTAN_UNUSED(cipher_state);
      }

   private:
      std::shared_ptr<const Policy> m_policy;
      std::shared_ptr<Callbacks> m_callbacks;
      std::shared_ptr<DTLS_Record_Layer> m_record_layer;

      DTLS_Retransmission_Timer m_retransmission_timer;

      bool m_dtls_version_committed = false;
};

}  // namespace Botan::TLS

#endif
