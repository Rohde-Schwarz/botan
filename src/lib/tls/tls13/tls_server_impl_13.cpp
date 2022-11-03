/*
* TLS Server - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_server_impl_13.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/credentials_manager.h>

// TODO: remove me
#include <botan/internal/tls_handshake_io.h>

namespace Botan::TLS {

Server_Impl_13::Server_Impl_13(Callbacks& callbacks,
                               Session_Manager& session_manager,
                               Credentials_Manager& credentials_manager,
                               const Policy& policy,
                               RandomNumberGenerator& rng)
   : Channel_Impl_13(callbacks, session_manager, credentials_manager,
                     rng, policy, true /* is_server */)
   {
#if defined(BOTAN_HAS_TLS_12)
   if(policy.allow_tls12())
      { expect_downgrade({}); }
#endif

   m_transitions.set_expected_next(CLIENT_HELLO);
   }

std::string Server_Impl_13::application_protocol() const
   {
   // ALPN is NYI for TLS 1.3 server
   return "";
   }

std::vector<X509_Certificate> Server_Impl_13::peer_cert_chain() const
   {
   return {}; // TODO: implement!
              //       Should return the client authentication certificate chain
              //       once client authentication for the server side is ready.
   }

void Server_Impl_13::process_handshake_msg(Handshake_Message_13 message)
   {
   std::visit([&](auto msg)
      {
      // first verify that the message was expected by the state machine...
      m_transitions.confirm_transition_to(msg.get().type());

      // ... then allow the library user to abort on their discretion
      callbacks().tls_inspect_handshake_msg(msg.get());

      // ... finally handle the message
      handle(msg.get());
      }, m_handshake_state.received(std::move(message)));
   }

void Server_Impl_13::process_post_handshake_msg(Post_Handshake_Message_13 /*msg*/)
   {
   throw Not_Implemented("NYI: process_post_handshake_msg");
   }

void Server_Impl_13::process_dummy_change_cipher_spec()
   {
   // RFC 8446 5.
   //    If an implementation detects a change_cipher_spec record received before
   //    the first ClientHello message or after the peer's Finished message, it MUST be
   //    treated as an unexpected record type [("unexpected_message" alert)].
   if(!m_handshake_state.has_client_hello() || m_handshake_state.has_client_finished())
      {
      throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received an unexpected dummy Change Cipher Spec");
      }

   // RFC 8446 5.
   //    An implementation may receive an unencrypted record of type change_cipher_spec [...]
   //    at any time after the first ClientHello message has been sent or received
   //    and before the peer's Finished message has been received [...]
   //    and MUST simply drop it without further processing.
   //
   // ... no further processing.
   }

bool Server_Impl_13::handshake_finished() const
   {
   // TODO: implement!
   //       Currently, we're just developing the TLS 1.3 server handshake, so
   //       it cannot be finished by definition. :o)
   return false;
   }


void Server_Impl_13::downgrade()
   {
   BOTAN_ASSERT_NOMSG(expects_downgrade());

   request_downgrade();

   // After this, no further messages are expected here because this instance
   // will be replaced by a Server_Impl_12.
   m_transitions.set_expected_next({});
   }

void Server_Impl_13::handle(const Client_Hello_12& ch)
   {
   // The detailed handling of the TLS 1.2 compliant Client Hello is left to
   // the TLS 1.2 server implementation.
   BOTAN_UNUSED(ch);

   // RFC 8446 Appendix D.2
   //    If the "supported_versions" extension is absent and the server only
   //    supports versions greater than ClientHello.legacy_version, the server
   //    MUST abort the handshake with a "protocol_version" alert.
   //
   // If we're not expecting a downgrade, we only support TLS 1.3.
   if(!expects_downgrade())
      {
      throw TLS_Exception(Alert::PROTOCOL_VERSION, "Received a legacy Client Hello");
      }

   downgrade();
   }

void Server_Impl_13::handle(const Client_Hello_13& client_hello)
   {
   const auto& exts = client_hello.extensions();

   const auto preferred_version = client_hello.preferred_version(policy());
   if(!preferred_version)
      {
      throw TLS_Exception(Alert::PROTOCOL_VERSION, "No shared TLS version");
      }

   // RFC 8446 4.2.1
   //    Servers MUST be prepared to receive ClientHellos that include [the
   //    supported_versions] extension but do not include 0x0304 in the list
   //    of versions.
   //
   // Also, the client's preferred version may not be TLS 1.3 which results in
   // a regular protocol downgrade despite the compliant TLS 1.3 Client Hello.
   if(preferred_version->is_pre_tls_13())
      {
      downgrade();

      // Simply await being replaced by a TLS 1.2 implementation...
      return;
      }

   // TODO: Implement support for PSK. For now, we ignore any such extensions
   //       and always revert to a standard key exchange.
   if(!exts.has<Supported_Groups>())
      {
      throw Not_Implemented("PSK-only handshake NYI");
      }

   // RFC 8446 9.2
   //    If containing a "supported_groups" extension, [Client Hello] MUST
   //    also contain a "key_share" extension, and vice versa.
   //
   // This was previously checked in the Client_Hello_13 constructor.
   BOTAN_ASSERT_NOMSG(exts.has<Key_Share>());

   // TODO: We might (or might not) want to move this group selection into the
   //       Server_Hello_13 constructor (or factory method). Let's defer this
   //       decision until the implementation of Hello Retry Request where we
   //       might want to have a factory method returning either HRR or SH
   //       depending on the outcome. Potentially, the handshake state will
   //       be the decisive factor?
   const auto selected_group = exts.get<Key_Share>()->select_group(policy());
   if(!selected_group.has_value())
      {
      throw Not_Implemented("No matching Key Share found; Hello Retry Request not yet implemented");
      }

   callbacks().tls_examine_extensions(exts, CLIENT);
   send_handshake_message(m_handshake_state.sending(Server_Hello_13(client_hello, selected_group, rng(), callbacks(),
                          policy())));

   // RFC 8446 Appendix D.4  (Middlebox Compatibility Mode)
   //    The server sends a dummy change_cipher_spec record immediately after
   //    its first handshake message. This may either be after a ServerHello or
   //    a HelloRetryRequest.
   //
   //    [...] if the client sends a non-empty session ID, the server MUST send
   //    the change_cipher_spec as described in this appendix.
   if(policy().tls_13_middlebox_compatibility_mode() || !client_hello.session_id().empty())
      {
      send_dummy_change_cipher_spec();
      }

   const auto& server_hello = m_handshake_state.server_hello();
   const auto cipher = Ciphersuite::by_id(server_hello.ciphersuite());
   m_transcript_hash.set_algorithm(cipher->prf_algo());

   const auto my_keyshare = server_hello.extensions().get<Key_Share>();
   auto shared_secret = my_keyshare->exchange(*exts.get<Key_Share>(), policy(), callbacks(), rng());
   my_keyshare->erase();

   m_cipher_state = Cipher_State::init_with_server_hello(m_side, std::move(shared_secret), cipher.value(),
                    m_transcript_hash.current());

   // TODO: OCSP stapling: Invoke Callbacks::tls_provide_cert_status() to obtain an OCSP response
   auto server_cert_chain = client_hello.find_certificate_chain(credentials_manager());
   BOTAN_ASSERT_NOMSG(!server_cert_chain.empty());

   auto private_key = credentials_manager().private_key_for(server_cert_chain.front(), "tls-server", client_hello.sni_hostname());
   BOTAN_ASSERT_NONNULL(private_key);

   // TODO: ALPN - Invoke Callbacks::tls_server_choose_app_protocol() with
   //       suggestions sent by the client. This might happen in the Encrypted
   //       Extensions constructor. Also implement Channel::application_protocol().

   aggregate_handshake_messages()
      .add(m_handshake_state.sending(Encrypted_Extensions(client_hello, policy(), callbacks())))
      .add(m_handshake_state.sending(Certificate_13(server_cert_chain, Connection_Side::SERVER)))
      .add(m_handshake_state.sending(Certificate_Verify_13(client_hello.signature_schemes(), Connection_Side::SERVER, *private_key, policy(), m_transcript_hash.current(), callbacks(), rng())))
      .add(m_handshake_state.sending(Finished_13(m_cipher_state.get(), m_transcript_hash.current())))
      .send();

   // TODO: At this point the server could derive the Application Traffic secret
   //       and start sending data. This is currently not implemented.
   // Note: When we would want to add this, the Cipher_State must hold back on
   //       advancing the "receiving" traffic secrets (keep handshake keys),
   //       otherwise we would not be able to decrypt the yet-to-come client's
   //       Finished message.

   m_transitions.set_expected_next(FINISHED);
   }

void Server_Impl_13::handle(const Certificate_13& certificate_msg)
   {
   BOTAN_UNUSED(certificate_msg);
   throw Not_Implemented("Client Auth is currently not supported by the server");
   }

void Server_Impl_13::handle(const Certificate_Verify_13& certificate_verify_msg)
   {
   BOTAN_UNUSED(certificate_verify_msg);
   throw Not_Implemented("Client Auth is currently not supported by the server");
   }

void Server_Impl_13::handle(const Finished_13& finished_msg)
   {
   // RFC 8446 4.4.4
   //    Recipients of Finished messages MUST verify that the contents are
   //    correct and if incorrect MUST terminate the connection with a
   //    "decrypt_error" alert.
   if(!finished_msg.verify(m_cipher_state.get(),
                           m_transcript_hash.previous()))
      { throw TLS_Exception(Alert::DECRYPT_ERROR, "Finished message didn't verify"); }

   // TODO: If the application traffic secret must be derived before receiving
   //       the client's Finished, `advance_with_server_finished` should be
   //       called in the Client Hello handler already. See TODO there, for
   //       further information.
   m_cipher_state->advance_with_server_finished(m_transcript_hash.previous());
   m_cipher_state->advance_with_client_finished(m_transcript_hash.current());

   // no more handshake messages expected
   m_transitions.set_expected_next({});

   callbacks().tls_session_activated();
   }

}  // namespace Botan::TLS
