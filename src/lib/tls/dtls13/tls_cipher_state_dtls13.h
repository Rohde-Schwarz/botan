/*
* DTLS 1.3 cipher state
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_DTLS_CIPHER_STATE_13_H_
#define BOTAN_TLS_DTLS_CIPHER_STATE_13_H_

#include <botan/tls_magic.h>
#include <botan/internal/tls_cipher_state.h>
#include <string_view>

namespace Botan::TLS {

class DTLS_Cipher_State final : public Cipher_State {
   public:
      struct Epoch : Cipher_State::Epoch {
            secure_vector<uint8_t> sequence_number_key;
      };

   public:
      DTLS_Cipher_State(Connection_Side side, std::string_view prf_algo);

      ~DTLS_Cipher_State() override;
      DTLS_Cipher_State(const DTLS_Cipher_State&) = delete;
      DTLS_Cipher_State& operator=(const DTLS_Cipher_State&) = delete;
      DTLS_Cipher_State(DTLS_Cipher_State&&) = delete;
      DTLS_Cipher_State& operator=(DTLS_Cipher_State&&) = delete;

      /**
       * Protect a DTLS record using the traffic secret keys and the current
       * sequence number of the latest epoch, or the ones identified by the
       * given @p epoch number. This will internally increment the respective
       * sequence number. Hence, multiple calls with the same input will not
       * produce the same result.
       *
       * @param type           the record type to be protected
       * @param payload        the record plaintext to be protected in-place
       * @param padding_bytes  the number of padding zero-bytes to be added
       * @param epoch          the optional epoch number to use for protection
       *
       * @returns the marshalled and protected record to be sent on the wire
       */
      MarshalledRecordAndNumber protect_record(Record_Type type,
                                               std::span<const uint8_t> payload,
                                               size_t padding_bytes,
                                               std::optional<Epoch_Number> epoch = std::nullopt);

      /**
       * Deprotect a DTLS record using the traffic secret keys and the current
       * sequence number of the epoch identified by the epoch bits in the record
       * header. If that epoch is not available, deprotection will fail and
       * std::nullopt will be returned.
       *
       * @param record                      the record to be deprotected in-place
       * @param incoming_record_size_limit  the maximum allowed size for the incoming record
       *
       * @returns the record payload and deprotected content type
       */
      std::optional<Record> deprotect_record(ProtectedRecord_DTLS record, size_t incoming_record_size_limit);

      void clear_write_keys() override;
      void clear_read_keys() override;

      void prune_write_epochs_older_than(Epoch_Number epoch_number);
      void prune_read_epochs_older_than(Epoch_Number epoch_number);

   private:
      Epoch create_dtls_epoch(Epoch_Number epoch_number,
                              Cipher_Dir direction,
                              const secure_vector<uint8_t>& traffic_secret);

      std::array<uint8_t, 6> expansion_label_prefix() const override;

      Epoch_Number advance_write_epoch(const secure_vector<uint8_t>& traffic_secret,
                                       std::optional<Epoch_Number> epoch_number = {}) override;
      Epoch_Number advance_read_epoch(const secure_vector<uint8_t>& traffic_secret,
                                      std::optional<Epoch_Number> epoch_number = {}) override;

      bool has_write_epoch() const override { return !m_write_epochs.empty(); }

      bool has_read_epoch() const override { return !m_read_epochs.empty(); }

      Cipher_State::Epoch& latest_write_epoch() override {
         BOTAN_ASSERT_NOMSG(has_write_epoch());
         return m_write_epochs.back();
      }

      const Cipher_State::Epoch& latest_write_epoch() const override {
         BOTAN_ASSERT_NOMSG(has_write_epoch());
         return m_write_epochs.back();
      }

      Cipher_State::Epoch& latest_read_epoch() override {
         BOTAN_ASSERT_NOMSG(has_read_epoch());
         return m_read_epochs.back();
      }

      const Cipher_State::Epoch& latest_read_epoch() const override {
         BOTAN_ASSERT_NOMSG(has_read_epoch());
         return m_read_epochs.back();
      }

      std::optional<std::reference_wrapper<Epoch>> latest_epoch_matching_epoch_hint(uint8_t epoch_hint);

   private:
      std::vector<Epoch> m_write_epochs;
      std::vector<Epoch> m_read_epochs;
};

inline DTLS_Cipher_State* as_dtls_cipher_state(Cipher_State* cs) {
   auto* dtls_cs = dynamic_cast<DTLS_Cipher_State*>(cs);
   BOTAN_ASSERT_IMPLICATION(
      dtls_cs == nullptr, cs == nullptr, "If the cipher state is not a DTLS_Cipher_State, it must be null");
   return dtls_cs;
}

}  // namespace Botan::TLS

#endif
