/*
* TLS handshake layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_LAYER_13_H_
#define BOTAN_TLS_HANDSHAKE_LAYER_13_H_

#include <optional>
#include <vector>

#include <botan/tls_magic.h>
#include <botan/tls_messages_13.h>

#include <botan/internal/tls_record_layer_13.h>
#include <botan/internal/tls_types_13.h>

namespace Botan::TLS {

class Transcript_Hash_State;

/**
 * Implementation of the TLS 1.3 handshake protocol layer
 *
 * This component transforms payload bytes received in TLS records
 * from the peer into parsed handshake messages and vice versa.
 */
class BOTAN_TEST_API Handshake_Layer {
   protected:
      explicit Handshake_Layer(Connection_Side whoami) :
            m_peer(whoami == Connection_Side::Server ? Connection_Side::Client : Connection_Side::Server)
            // RFC 8446 4.4.2
            //    If the corresponding certificate type extension
            //    ("server_certificate_type" or "client_certificate_type") was not
            //    negotiated in EncryptedExtensions, or the X.509 certificate type
            //    was negotiated, then each CertificateEntry contains a DER-encoded
            //    X.509 certificate.
            //
            // We need the certificate_type info to parse Certificate messages.
            ,
            m_certificate_type(Certificate_Type::X509) {}

   public:
      static std::unique_ptr<Handshake_Layer> create(Connection_Side whoami, TLS_Flavor flavor);

      Handshake_Layer(const Handshake_Layer&) = delete;
      Handshake_Layer(Handshake_Layer&&) = delete;
      Handshake_Layer& operator=(const Handshake_Layer&) = delete;
      Handshake_Layer& operator=(Handshake_Layer&&) = delete;

      virtual ~Handshake_Layer() = default;

   public:
      /**
       * Reads data that was received in handshake records and stores it internally for further
       * processing during the invocation of `next_message()`.
       *
       * @param policy          The TLS policy
       * @param data_from_peer  The data to be parsed. In DTLS this is assumed to be one or
       *                        more full handshake message fragments. In TLS it might be a
       *                        an in-order portion of any size.
       *
       * @returns true if the data was successfully ingested, false if something
       *          went wrong. Typically DTLS handshake layers will return false
       *          if the data was not a valid fragment of a handshake message
       *          and got discarded.
       */
      virtual bool copy_data(const Policy& policy, std::span<const uint8_t> data_from_peer) = 0;

      /**
       * Parses one handshake message off the internal buffer that is being filled using `copy_data`.
       *
       * @param policy the TLS policy
       * @param transcript_hash the transcript hash state to be updated
       *
       * @return the parsed handshake message, or nullopt if more data is needed to complete the message
       */
      virtual std::optional<Handshake_Message_13> next_message(const Policy& policy,
                                                               Transcript_Hash_State& transcript_hash) = 0;

      /**
       * Parses one post-handshake message off the internal buffer that is being filled using `copy_data`.
       *
       * @param policy the TLS policy
       *
       * @return the parsed post-handshake message, or nullopt if more data is needed to complete the message
       */
      virtual std::optional<Post_Handshake_Message_13> next_post_handshake_message(const Policy& policy) = 0;

      /**
       * Marshals one handshake @p message for sending in an (encrypted) record and updates the
       * provided transcript hash state accordingly. For DTLS, multiple fragments may be
       * produced if the handshake message is too large to fit into a single record.
       *
       * @param message the handshake message to be marshalled
       * @param transcript_hash the transcript hash state to be updated
       * @param dtls_max_fragment_size the maximum size of the payload in a single record,
                                       used to determine if fragmentation is needed in DTLS.
       *
       * @return a single marshalled handshake message either in one piece or fragmented for DTLS
       */
      virtual PreparedHandshakeMessage prepare_message(Handshake_Message_13_Ref message,
                                                       Transcript_Hash_State& transcript_hash,
                                                       std::optional<uint16_t> dtls_max_fragment_size = std::nullopt);

      /**
       * Marshals a ClientHello prematurely for a truncated transcript hash
       * calculation (cf. RFC 8446 Section 4.2.11.2).
       *
       * @param message the ClientHello message to be marshalled
       * @param transcript_hash the transcript hash state to be updated
       */
      static void update_transcript_for_psk_binder_calc(const Client_Hello_13& message,
                                                        Transcript_Hash_State& transcript_hash);

      /**
       * Marshals one post-handshake message for sending in an (encrypted) record.
       *
       * @param message the post handshake message to be marshalled
       * @param dtls_max_fragment_size the maximum size of the payload in a single record,
                                       used to determine if fragmentation is needed in DTLS.
       *
       * @return the marshalled post-handshake message
       */
      virtual PreparedHandshakeMessage prepare_post_handshake_message(
         const Post_Handshake_Message_13& message, std::optional<uint16_t> dtls_max_fragment_size = std::nullopt);

      /**
       * Check if the Handshake_Layer has stored a partial message in its internal buffer.
       * This can happen if a handshake message spans multiple records.
       */
      virtual bool has_pending_data() const = 0;

      /**
       * Set the certificate_type used for parsing Certificate messages. This
       * is determined via (client/server)_certificate_type extensions during
       * the handshake.
       *
       * RFC 7250 4.3 and 4.4
       *    When the TLS server has specified RawPublicKey as the
       *    [client_certificate_type/server_certificate_type], authentication
       *    of the TLS [client/server] to the TLS [server/client] is supported
       *    only through authentication of the received client
       *    SubjectPublicKeyInfo via an out-of-band method.
       *
       * If the peer sends a Certificate message containing an incompatible
       * means of authentication, a 'decode_error' will be generated.
       */
      void set_selected_certificate_type(Certificate_Type cert_type) { m_certificate_type = cert_type; }

   protected:
      static Handshake_Type read_handshake_message_type(uint8_t value);

      /// Could not process a message because not enough bytes were available.
      /// The read offset must not be advanced.
      using IncompleteNotProcessed = std::monostate;

      /// Relevant for DTLS (a fragment was processed, but the message is not
      /// complete yet). We now have to advance the read offset
      struct IncompleteProcessed {
            size_t bytes_consumed;
      };

      struct NextMessageResult {
            Handshake_Type type;
            std::span<const uint8_t, 4> tls_header_bytes;
            std::span<const uint8_t> message_bytes;
            size_t bytes_consumed;  // only includes the bytes processed by the last next_message_buffer() call
      };

      using NextMessageStep = std::variant<IncompleteNotProcessed, IncompleteProcessed, NextMessageResult>;

      virtual NextMessageStep next_message_buffer(std::span<const uint8_t> bytes, const Policy& policy) = 0;

      virtual TLS_Flavor tls_flavor() const = 0;

      Connection_Side peer() const { return m_peer; }

      Certificate_Type certificate_type() const { return m_certificate_type; }

      virtual Handshake_Message_13 parse_handshake_message(Handshake_Type type,
                                                           std::span<const uint8_t> msg,
                                                           const Policy& policy) const;

      Post_Handshake_Message_13 parse_post_handshake_message(Handshake_Type type, std::span<const uint8_t> msg) const;

   private:
      Connection_Side m_peer;
      Certificate_Type m_certificate_type;
};

}  // namespace Botan::TLS

#endif
