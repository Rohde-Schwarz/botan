/*
* TLS Server
* (C) 2004-2011,2012,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_server.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_server_impl_12.h>
#include <botan/tls_magic.h>

#include <botan/internal/tls_server_impl_12.h>
#if defined(BOTAN_HAS_TLS_13)
  #include <botan/internal/tls_server_impl_13.h>
#endif

namespace Botan::TLS {

/*
* TLS Server Constructor
*/
Server::Server(Callbacks& callbacks,
               Session_Manager& session_manager,
               Credentials_Manager& creds,
               const Policy& policy,
               RandomNumberGenerator& rng,
               bool is_datagram,
               size_t io_buf_sz)
   {
   const auto max_version = policy.latest_supported_version(is_datagram);

   if(!max_version.is_pre_tls_13())
      {
#if defined(BOTAN_HAS_TLS_13)
      // TODO: Implement server version detection in the TLS 1.3 server code and
      //       switch to the TLS 1.2 implementation when requested.
      //       See the client code for inspiration.
      if(policy.acceptable_protocol_version(Protocol_Version::TLS_V12) ||
         policy.acceptable_protocol_version(Protocol_Version::DTLS_V12))
         {
         throw Not_Implemented("Protocol downgrade from a TLS 1.3 to 1.2 server "
                               "is currently not implemented. When offering a "
                               "TLS 1.3 server, one must disable TLS 1.2 in the "
                               "protocol policy.");
         }

      m_impl = std::make_unique<Server_Impl_13>(
         callbacks, session_manager, creds, policy, rng);
#else
      throw Not_Implemented("TLS 1.3 server is not available in this build");
#endif
      }
   else
      {
      m_impl = std::make_unique<Server_Impl_12>(
         callbacks, session_manager, creds, policy, rng, is_datagram, io_buf_sz);
      }
   }

Server::~Server() = default;

size_t Server::received_data(const uint8_t buf[], size_t buf_size)
   {
   return m_impl->received_data(buf, buf_size);
   }

bool Server::is_active() const
   {
   return m_impl->is_active();
   }

bool Server::is_closed() const
   {
   return m_impl->is_closed();
   }

std::vector<X509_Certificate> Server::peer_cert_chain() const
   {
   return m_impl->peer_cert_chain();
   }

SymmetricKey Server::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   return m_impl->key_material_export(label, context, length);
   }

void Server::renegotiate(bool force_full_renegotiation)
   {
   m_impl->renegotiate(force_full_renegotiation);
   }

void Server::update_traffic_keys(bool request_peer_update)
   {
   m_impl->update_traffic_keys(request_peer_update);
   }

bool Server::secure_renegotiation_supported() const
   {
   return m_impl->secure_renegotiation_supported();
   }

void Server::send(const uint8_t buf[], size_t buf_size)
   {
   m_impl->send(buf, buf_size);
   }

void Server::send_alert(const Alert& alert)
   {
   m_impl->send_alert(alert);
   }

void Server::send_warning_alert(Alert::Type type)
   {
   m_impl->send_warning_alert(type);
   }

void Server::send_fatal_alert(Alert::Type type)
   {
   m_impl->send_fatal_alert(type);
   }

void Server::close()
   {
   m_impl->close();
   }

bool Server::timeout_check()
   {
   return m_impl->timeout_check();
   }

std::string Server::application_protocol() const
   {
   return m_impl->application_protocol();
   }
}
