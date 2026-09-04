/*
* TLS record layer implementation for DTLS 1.3
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_RECORD_LAYER_DTLS13_H_
#define BOTAN_TLS_RECORD_LAYER_DTLS13_H_

#include <botan/concepts.h>
#include <botan/strong_type.h>
#include <botan/tls_version.h>
#include <botan/internal/tls_ack_record_dtls13.h>
#include <botan/internal/tls_record_dtls13.h>
#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_types_13.h>
#include <botan/internal/tls_utils_dtls13.h>
#include <deque>

namespace Botan {

class BufferSlicer;

}

namespace Botan::TLS {

/**
 * Implementation of the DTLS 1.3 record protocol layer
 *
 * This component transforms bytes received from the peer into bytes
 * containing plaintext TLS messages and vice versa.
 */
class BOTAN_TEST_API DTLS_Record_Layer final : public Record_Layer {
   public:
      using IncomingRecord = std::variant<PlaintextRecord_DTLS, ProtectedRecord_DTLS>;

      struct HandshakeRecordInfo /* NOLINT(*-member-init) */ {
            std::vector<RecordNumber> record_numbers;  // Includes numbers of previous transmissions
            MarshalledHandshakeMessageFragment fragment;
      };

   public:
      DTLS_Record_Layer(Connection_Side side, std::shared_ptr<const Policy> policy);

      /**
       * Ingests datagrams received from the peer. This assumes being called for
       * each individual datagram received from the peer.
       *
       * @param data_from_peer  A complete and single datagram from the peer
       * @param has_cryptographic_association  Indicates whether the data was received
       *                                       while the connection has key material.
       *
       * @returns false if the datagram got discarded due to some error
       *          (e.g., invalid formatting), true otherwise
       */
      bool copy_data(std::span<const uint8_t> data_from_peer, bool has_cryptographic_association) override;

      ReadResult<Record_Content> next_record(Cipher_State* cipher_state = nullptr) override;

      std::vector<MarshalledRecord> prepare_records(Record_Type type,
                                                    std::span<const uint8_t> fragment,
                                                    Cipher_State* cipher_state) const override;

      std::vector<MarshalledRecord> prepare_records(const PreparedHandshakeMessageFlight& flight,
                                                    Cipher_State* cipher_state) const override;

      /**
       * Re-prepares all records that are currently not acknowledged by the
       * peer. Acknowledgements could either be explicit (via ACK records) or
       * implicit (via flight state progress).
       *
       * @note This call is relevant for DTLS only.
       *
       * @returns a vector of ready-to-send records re-prepared in the
       *          respective epoch of their first transmission.
       */
      std::vector<MarshalledRecord> prepare_unacknowledged_records(Cipher_State* cipher_state) const;

      uint16_t record_payload_size_limit(const Policy& policy, Cipher_State* cipher_state) const override;

      void clear_read_buffer() override;

      /**
      * Generates a serialized ACK message containing all records that were
      * successfully received and processed by the record layer. This list is
      * cleared whenever progress is made in the handshake state machine, see
      * `clear_dtls_outstanding_acknowledgements()`.
      */
      ACKs acknowledgements() const;

      /**
       * Processes an incoming ACK message and removes all acknowledged records
       * from the list of unacknowledged outgoing handshake records.
       *
       * @returns true if there are no more unacknowledged records left, false
       *          otherwise
       */
      bool handle_acknowledgements(const ACKs& ack_payload);

      void clear_resend_buffer();
      void clear_outstanding_acknowledgements();

      std::optional<Epoch0_SequenceNumbers> epoch0_sequence_numbers() const noexcept override {
         return Epoch0_SequenceNumbers{
            .read = m_unprotected_read_seq_no,
            .write = m_unprotected_write_seq_no,
         };
      }

   private:
      bool read_datagram(std::span<const uint8_t> datagram);

      PlaintextRecord_DTLS read_plaintext_record(BufferSlicer& bs);
      ProtectedRecord_DTLS read_protected_record(BufferSlicer& bs);

      std::pair<MarshalledRecord, RecordNumber> prepare_record(Record_Type type,
                                                               std::span<const uint8_t> fragment,
                                                               Cipher_State* cipher_state,
                                                               std::optional<Epoch_Number> epoch = std::nullopt) const;

      IncomingRecord next_incoming_record();

      Replay_Window_13& replay_window_for_epoch(Epoch_Number epoch);

   private:
      std::deque<IncomingRecord> m_incoming_records;
      mutable std::vector<HandshakeRecordInfo>
         m_unacked_outgoing_handshake_records;  // TODO: prepare_records shouldn't be const

      std::map<Epoch_Number, Replay_Window_13> m_replay_windows;

      mutable uint64_t m_unprotected_write_seq_no = 0;  // TODO: maybe just make prepare_records non-const
      mutable uint64_t m_unprotected_read_seq_no = 0;   // TODO: maybe just make deprotect_fragment non-const

      mutable std::vector<RecordNumber> m_record_numbers_to_ack;
};

}  // namespace Botan::TLS

#endif
