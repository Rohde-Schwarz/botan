/*
* (D)TLS Channel IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IO_BASE_H_
#define BOTAN_TLS_CHANNEL_IO_BASE_H_

#include <botan/internal/tls_flight_13.h>
#include <botan/internal/tls_record_13.h>
#include <optional>

namespace Botan::TLS {

class Alert;
class Record_Layer;
class Handshake_Layer;
class Channel_Impl;
class Channel_Impl_13;
class Cipher_State;
struct RecordNumber;

class Channel_IO {
   public:
      using ReceiveEvent = std::variant<BytesNeeded,
                                        Handshake_Message_13,
                                        Post_Handshake_Message_13,
                                        ChangeCipherSpec_Record,
                                        Alert_Record,
                                        ApplicationData_Record>;

      static std::unique_ptr<Channel_IO> create(TLS_Flavor flavor,
                                                Connection_Side side,
                                                const std::shared_ptr<Channel_Impl>& channel,
                                                std::shared_ptr<const Policy> policy,
                                                std::shared_ptr<Callbacks> callbacks);

   protected:
      Channel_IO(std::weak_ptr<Channel_Impl_13> channel,
                 std::shared_ptr<const Policy> policy,
                 std::shared_ptr<Callbacks> callbacks) :
            m_channel(std::move(channel)), m_policy(std::move(policy)), m_callbacks(std::move(callbacks)) {}

   public:
      Channel_IO(const Channel_IO&) = delete;
      Channel_IO& operator=(const Channel_IO&) = delete;
      Channel_IO(Channel_IO&&) = delete;
      Channel_IO& operator=(Channel_IO&&) = delete;

      virtual ~Channel_IO() = default;

      /// @name Ingestion of incoming data
      /// @{

      /**
       * Ingests incoming data from the network and processes it into a stream
       * of events. @sa next_pending_event().
       */
      void copy_data(std::span<const uint8_t> data);

      /**
       * Retrieves the next pending event from the processed incoming data. If
       * no more events are available, this will return a BytesNeeded event
       * indicating how many more bytes are needed to continue processing.
       */
      ReceiveEvent next_pending_event(Transcript_Hash_State* transcript_hash, bool handshake_complete);

      /// @}

      /// @name Emission of outgoing data
      /// @{

      void send(std::span<const uint8_t> payload);
      void send(const Alert& alert);
      void send_dummy_change_cipher_spec();
      virtual void send_flight(std::vector<Flight::Message> flight) = 0;
      virtual void send_key_update(Key_Update msg) = 0;

      /// @}

      /// @name DTLS-specific state management
      /// @{

      /**
       * Whether a previously sent KeyUpdate is still awaiting acknowledgement
       * by the peer. This can only happen via DTLS, TLS always returns false.
       */
      virtual bool has_pending_key_update() const { return false; }

      /**
       * Notifies that the TLS state machine is sure that we're talking to a
       * peer using (D)TLS 1.3. Typically that is the case after receiving and
       * processing a ServerHello or a ClientHello indicating support for (D)TLS
       * 1.3.
       *
       * This is relevant for DTLS: before this point, lost records must be
       * recovered by retransmitting entire flights (1.2-style); only afterwards
       * may the ACK mechanism (RFC 9147 7.) be relied upon.
       *
       * For the case of receiving a HelloRetryRequest, use
       * notify_protocol_version_committed_and_flight_superseded().
       */
      virtual void notify_protocol_version_committed() { /* don't care */ }

      /**
       * Like notify_protocol_version_committed(), but for the case where
       * committing message additionally supersedes the flight currently held
       * for retransmission. This is the case exactly for a HelloRetryRequest.
       *
       * This difference is only relevant for DTLS: Since the buffered flight
       * (the initial ClientHello) is superseded by the response about to be
       * sent, retransmitting it would be wrong. So in addition to commiting the
       * protocol version, this method also clears the resend buffer and
       * retransmission timer.
       */
      virtual void notify_protocol_version_committed_and_flight_superseded() { /* don't care */ }

      /**
       * Notifies that the last message completing a flight was received.
       *
       * This is relevant for DTLS: At that point, everything we need
       * was received and the ACK mechanism is no longer needed.
       */
      virtual void notify_received_complete_flight() { /* don't care */ }

      /**
       * Notifies that a complete flight was received that expects no response,
       * i.e., the final flight of the peer (the client's Finished).
       *
       * This is relevant for DTLS: since there is no response flight
       * that would implicitly acknowledge it, the flight must be acknowledged
       * explicitly with an ACK message.
       */
      virtual void notify_received_final_flight() { /* don't care */ }

      std::optional<Epoch0_SequenceNumbers> epoch0_sequence_numbers() const;

      /// @}

      /**
       * Notifies that the channel is closed for reading (close_notify received).
       * The IO can discard any read-side state; no further data will be processed.
       */
      void notify_closed_for_reading();
      void set_record_size_limits(uint16_t out, uint16_t in);
      void set_selected_certificate_type(Certificate_Type t);

   protected:
      std::optional<ReceiveEvent> next_pending_handshake_message(Transcript_Hash_State* transcript_hash,
                                                                 bool handshake_complete);

      virtual void process(const Handshake_Record& record) = 0;
      virtual void process(const ACK_Record& ack_record) = 0;

      virtual void send_data(Record_Type record_type, std::span<const uint8_t> payload, Cipher_State* cipher_state) = 0;

      virtual Record_Layer& record_layer() = 0;

      virtual Handshake_Layer& handshake_layer() = 0;

      virtual const Record_Layer& record_layer() const = 0;

      virtual const Handshake_Layer& handshake_layer() const = 0;

      std::shared_ptr<const Channel_Impl_13> channel() const;
      std::shared_ptr<Channel_Impl_13> channel();

      const Policy& policy() const { return *m_policy; }

      const Callbacks& callbacks() const { return *m_callbacks; }

      Callbacks& callbacks() { return *m_callbacks; }

   private:
      bool m_first_message_delivered = false;

      std::weak_ptr<Channel_Impl_13> m_channel;
      std::shared_ptr<const Policy> m_policy;
      std::shared_ptr<Callbacks> m_callbacks;
};

}  // namespace Botan::TLS

#endif
