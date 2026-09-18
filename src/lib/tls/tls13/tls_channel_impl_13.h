/*
* TLS Channel - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IMPL_13_H_
#define BOTAN_TLS_CHANNEL_IMPL_13_H_

#include <botan/tls_messages_13.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_impl.h>
#include <botan/internal/tls_connection_state_13.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_record_layer_13.h>

namespace Botan::TLS {

class Cipher_State;
class Transcript_Hash_State;
class Channel_IO;
class Flight;

/**
 * Encapsulates the callbacks in the state machine described in RFC 8446 7.1,
 * that will make the realisation the SSLKEYLOGFILE for connection debugging
 * specified in ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
 *
 * The class is split from the rest of the Channel_Impl_13 for mockability.
 */
class Secret_Logger /* NOLINT(*-special-member-functions) */ {
   public:
      virtual ~Secret_Logger() = default;

      friend class Cipher_State;

   protected:
      /**
       * Used exclusively in the Cipher_State to pass secret data to
       * a user-provided Callbacks::tls_ssl_key_log_data() iff
       * Policy::allow_ssl_key_log_file() returns true.
       */
      virtual void maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const = 0;
};

/**
* Generic interface for TLS 1.3 endpoint
*/
class Channel_Impl_13 : public Channel_Impl,
                        protected Secret_Logger {
   public:
      /**
      * Set up a new (D)TLS 1.3 session
      *
      * @param callbacks contains a set of callback function references
      *        required by the TLS endpoint.
      * @param session_manager manages session state
      * @param credentials_manager manages application/user credentials
      * @param rng a random number generator
      * @param policy specifies other connection policy information
      * @param connection_side whether this is a client or server session
      * @param flavor whether TLS1.3 or DTLS1.3 is used
      */
      explicit Channel_Impl_13(const std::shared_ptr<Callbacks>& callbacks,
                               const std::shared_ptr<Session_Manager>& session_manager,
                               const std::shared_ptr<Credentials_Manager>& credentials_manager,
                               const std::shared_ptr<RandomNumberGenerator>& rng,
                               const std::shared_ptr<const Policy>& policy,
                               Connection_Side connection_side,
                               TLS_Flavor flavor);

      Channel_Impl_13(const Channel_Impl_13& other) = delete;
      Channel_Impl_13(Channel_Impl_13&& other) = delete;
      Channel_Impl_13& operator=(const Channel_Impl_13& other) = delete;
      Channel_Impl_13& operator=(Channel_Impl_13&& other) = delete;

      ~Channel_Impl_13() override;

      size_t from_peer(std::span<const uint8_t> data) override;
      void to_peer(std::span<const uint8_t> data) override;

      /**
      * Send a TLS alert message. If the alert is fatal, the internal
      * state (keys, etc) will be reset.
      * @param alert the Alert to send
      */
      void send_alert(const Alert& alert) override;

      /**
      * @return true iff the connection is active for sending application data
      *
      * Note that the connection is active until the application has called
      * `close()`, even if a CloseNotify has been received from the peer.
      */
      bool is_active() const override;

      /**
      * @return true iff the connection has been closed, i.e. CloseNotify
      * has been received from the peer.
      */
      bool is_closed() const override { return is_closed_for_reading() && is_closed_for_writing(); }

      bool is_closed_for_reading() const override { return !m_can_read; }

      bool is_closed_for_writing() const override { return !m_can_write; }

      /**
      * Key material export (RFC 5705)
      * @param label a disambiguating label string
      * @param context a per-association context value
      * @param length the length of the desired key in bytes
      * @return key of length bytes
      */
      SymmetricKey key_material_export(std::string_view label, std::string_view context, size_t length) const override;

      /**
      * Attempt to renegotiate the session
      */
      void renegotiate(bool /* unused */) override {
         throw Invalid_Argument("renegotiation is not allowed in TLS 1.3");
      }

      /**
      * Attempt to update the session's traffic key material
      * Note that this is possible with a TLS 1.3 channel, only.
      *
      * @param request_peer_update if true, require a reciprocal key update
      */
      void update_traffic_keys(bool request_peer_update = false) override;

      /**
      * @return true iff the counterparty supports the secure
      * renegotiation extensions.
      */
      bool secure_renegotiation_supported() const override {
         // Secure renegotiation is not supported in TLS 1.3, though BoGo
         // tests expect us to claim that it is available.
         return true;
      }

      /**
      * Perform a handshake timeout check that the user can call. This is no
      * longer relevant for DTLS 1.3.
      * @throws for DTLS 1.3, since the callback mechanism
      *         tls_register_deferred_operation() shall be used insead of
      *         timeout_check.
      * @returns false for TLS 1.3
      */
      bool timeout_check() override;

      /**
      * Tells the user when to call Channel::timeout_check() next. This is no
      * longer relevant for DTLS 1.3.
      * @throws for DTLS 1.3, since the callback mechanism
      *         tls_register_deferred_operation() shall be used insead of
      *         timeout_check.
      * @returns std::nullopt for TLS 1.3
      */
      std::optional<std::chrono::milliseconds> next_retransmission_timeout() const override;

      Cipher_State* cipher_state() { return m_cipher_state.get(); }

   protected:
      virtual void process_handshake_msg(Handshake_Message_13 msg) = 0;
      virtual void process_post_handshake_msg(Post_Handshake_Message_13 msg) = 0;
      virtual void process_dummy_change_cipher_spec() = 0;

      enum class Compat_Mode_Situation : uint8_t {
         BeforeSendingAlert,
         AfterSendingFirstClientHello,
         BeforeSendingSecondClientHello,
         BeforeSendingEncryptedClientFlight,
         AfterSendingFirstServerHello,
         AfterSendingHelloRetryRequest,
      };

      virtual void maybe_handle_compatibility_mode(Compat_Mode_Situation situation) = 0;

      void handle(const Key_Update& key_update);

      /**
       * Schedule a traffic key update to opportunistically happen before the
       * channel sends application data the next time. Such a key update will
       * never request a reciprocal key update from the peer.
       */
      void opportunistically_update_traffic_keys() { m_opportunistic_key_update = true; }

      void send_dummy_change_cipher_spec();

      Callbacks& callbacks() const { return *m_callbacks; }

      Session_Manager& session_manager() { return *m_session_manager; }

      Credentials_Manager& credentials_manager() { return *m_credentials_manager; }

      RandomNumberGenerator& rng() { return *m_rng; }

      const Policy& policy() const { return *m_policy; }

      bool is_datagram() const { return m_flavor == TLS_Flavor::DTLS; }

      void send_record(Record_Type record_type, std::span<const uint8_t> payload);
      void send(Flight flight);

   private:
      void process_alert(const secure_vector<uint8_t>& record);

      std::optional<size_t> process_event(Handshake_Message_13 handshake_msg);
      std::optional<size_t> process_event(Post_Handshake_Message_13 post_handshake_msg);
      std::optional<size_t> process_event(const Record_Content& record);

      /**
       * Terminate the connection (on sending or receiving an error alert) and
       * clear secrets
       */
      void shutdown();

   protected:
      const Connection_Side m_side;                              // NOLINT(*non-private-member-variable*)
      std::unique_ptr<Transcript_Hash_State> m_transcript_hash;  // NOLINT(*non-private-member-variable*)
      std::unique_ptr<Cipher_State> m_cipher_state;              // NOLINT(*non-private-member-variable*)
      std::optional<Active_Connection_State_13> m_active_state;  // NOLINT(*non-private-member-variable*)
      TLS_Flavor m_flavor;                                       // NOLINT(*-non-private-member-*)

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
      /**
       * Indicate that we have to expect a downgrade to TLS 1.2. In which case the current
       * implementation (i.e. Client_Impl_13 or Server_Impl_13) will need to be replaced
       * by their respective counter parts.
       *
       * This will prepare an internal structure where any information required to downgrade
       * can be preserved.
       * @sa `Channel_Impl::Downgrade_Information`
       */
      void expect_downgrade(const Server_Information& server_info, const std::vector<std::string>& next_protocols);
#endif

      /**
       * Set the record size limits as negotiated by the "record_size_limit"
       * extension (RFC 8449).
       *
       * @param outgoing_limit  the maximal number of plaintext bytes to be
       *                        sent in a protected record
       * @param incoming_limit  the maximal number of plaintext bytes to be
       *                        accepted in a received protected record
       */
      void set_record_size_limits(uint16_t outgoing_limit, uint16_t incoming_limit);

      /**
       * Set the expected certificate type needed to parse Certificate
       * messages in the handshake layer. See RFC 7250 and 8446 4.4.2 for
       * further details.
       */
      void set_selected_certificate_type(Certificate_Type cert_type);

   protected:
      /* IO Handling */
      std::unique_ptr<Channel_IO> m_channel_io;  // NOLINT(*-non-private-member-*)

   private:
      /* callbacks */
      std::shared_ptr<Callbacks> m_callbacks;

      /* external state */
      std::shared_ptr<Session_Manager> m_session_manager;
      std::shared_ptr<Credentials_Manager> m_credentials_manager;
      std::shared_ptr<RandomNumberGenerator> m_rng;
      std::shared_ptr<const Policy> m_policy;

      bool m_can_read;
      bool m_can_write;

      bool m_opportunistic_key_update;

      /**
       * True while a KeyUpdate with "update_requested" is outstanding, i.e.
       * the peer has not yet replied with a KeyUpdate of its own.
       */
      bool m_key_update_requested;

      uint64_t m_last_key_update_ms = 0;
};
}  // namespace Botan::TLS

#endif
