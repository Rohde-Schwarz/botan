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
#include <botan/internal/tls_dtls_channel_companion_base.h>
#include <botan/internal/tls_dtls_timer.h>
#include <botan/internal/tls_record_layer_13.h>
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
            m_record_layer(std::move(record_layer)),
            m_retransmission_timer(*m_policy, m_callbacks) {
         BOTAN_ASSERT_NONNULL(m_callbacks);
         // TODO: we could down-cast this to a DTLS_Record_Layer...
         BOTAN_ASSERT_NONNULL(m_record_layer);
      }

      void notify_sent_handshake_flight() override {
         if(m_retransmission_timer.started()) {
            m_retransmission_timer.flight_sent();
         }
      }

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

      void send_acknowledgements() override {}

      void process_acknowledgements(std::span<const uint8_t> ack_record) override {
         BOTAN_UNUSED(ack_record);
         throw TLS_Exception(AlertType::UnexpectedMessage, "Received ACKs despite not being DTLS");
      }

   private:
      std::shared_ptr<const Policy> m_policy;
      std::shared_ptr<Callbacks> m_callbacks;
      std::shared_ptr<Record_Layer> m_record_layer;

      DTLS_Retransmission_Timer m_retransmission_timer;
};

}  // namespace Botan::TLS

#endif
