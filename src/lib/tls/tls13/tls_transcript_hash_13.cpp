/*
* TLS transcript hash implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_transcript_hash_13.h>

#include <botan/hash.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/tls_reader.h>

#include <utility>

namespace Botan::TLS {

Transcript_Hash_State::Transcript_Hash_State(TLS_Flavor flavor) : m_flavor(flavor) {}

Transcript_Hash_State::Transcript_Hash_State(TLS_Flavor flavor, std::string_view algo_spec) :
      Transcript_Hash_State(flavor) {
   set_algorithm(algo_spec);
}

Transcript_Hash_State::~Transcript_Hash_State() = default;

Transcript_Hash_State::Transcript_Hash_State(Transcript_Hash_State&& other) noexcept = default;
Transcript_Hash_State& Transcript_Hash_State::operator=(Transcript_Hash_State&& other) noexcept = default;

Transcript_Hash_State::Transcript_Hash_State(const Transcript_Hash_State& other) :
      m_flavor(other.m_flavor),
      m_hash((other.m_hash != nullptr) ? other.m_hash->copy_state() : nullptr),
      m_unprocessed_transcript(other.m_unprocessed_transcript),
      m_current(other.m_current),
      m_previous(other.m_previous),
      m_truncated(other.m_truncated) {}

std::unique_ptr<Transcript_Hash_State> Transcript_Hash_State::recreate_after_hello_retry_request(
   std::string_view algo_spec, const Transcript_Hash_State& prev_transcript_hash_state) {
   // make sure that we have seen exactly 'client_hello' and 'hello_retry_request'
   // before re-creating the transcript hash state
   BOTAN_STATE_CHECK(prev_transcript_hash_state.m_hash == nullptr);
   BOTAN_STATE_CHECK(prev_transcript_hash_state.m_unprocessed_transcript.size() == 2);

   auto transcript_hash = std::make_unique<Transcript_Hash_State>(prev_transcript_hash_state.m_flavor, algo_spec);

   const auto& client_hello_1 = prev_transcript_hash_state.m_unprocessed_transcript.front();
   const auto& hello_retry_request = prev_transcript_hash_state.m_unprocessed_transcript.back();

   const auto hash_length = transcript_hash->m_hash->output_length();
   BOTAN_ASSERT_NOMSG(hash_length < 256);
   const auto hash_length_32 = static_cast<uint32_t>(hash_length);

   // RFC 8446 4.4.1
   //    [...], when the server responds to a ClientHello with a HelloRetryRequest,
   //    the value of ClientHello1 is replaced with a special synthetic handshake
   //    message of handshake type "message_hash" [(0xFE)] containing:
   const auto message_hash_header = std::array{
      uint8_t(0xFE), /* message type 'message_hash' RFC 8446 4. */
      get_byte<1>(hash_length_32),
      get_byte<2>(hash_length_32),
      get_byte<3>(hash_length_32),
   };

   transcript_hash->update(message_hash_header, transcript_hash->m_hash->process(client_hello_1));
   transcript_hash->update(hello_retry_request);

   return transcript_hash;
}

namespace {

// TODO: This is a massive code duplication of the client hello parsing code,
//       as well as basic parsing of extensions. We should resolve this.
//
// Ad-hoc idea: When parsing the production objects, we could keep markers into
//              the original buffer. E.g. the PSK extensions would keep its off-
//              set into the entire client hello buffer. Using that offset we
//              could quickly identify the offset of the binders list slice the
//              buffer without re-parsing it.
//
// Finds the truncation offset in a serialization of Client Hello as defined in
// RFC 8446 4.2.11.2 used for the calculation of PSK binder MACs.
size_t find_client_hello_truncation_mark(std::span<const uint8_t> client_hello, TLS_Flavor flavor) {
   TLS_Data_Reader reader("Client Hello Truncation", client_hello);

   // legacy version
   reader.discard_next(2);

   // random
   reader.discard_next(32);

   // session ID
   const auto session_id_length = reader.get_byte();
   reader.discard_next(session_id_length);

   // Cookie (only for DTLS)
   if(flavor == TLS_Flavor::DTLS) {
      // RFC 9147 5.3
      //    A DTLS 1.3-only client MUST set the legacy_cookie field to zero
      //    length. If a DTLS 1.3 ClientHello is received with any other value
      //    in this field, the server MUST abort the handshake with an
      //    "illegal_parameter" alert.
      const auto cookie_length = reader.get_byte();
      if(cookie_length != 0) {
         throw TLS_Exception(Alert::IllegalParameter, "DTLS 1.3 Client Hello has non-empty cookie");
      }
   }

   // cipher suites
   const auto ciphersuites_length = reader.get_uint16_t();
   reader.discard_next(ciphersuites_length);

   // compression methods
   const auto compression_methods_length = reader.get_byte();
   reader.discard_next(compression_methods_length);

   // extensions
   const auto extensions_length = reader.get_uint16_t();
   const auto extensions_offset = reader.read_so_far();
   while(reader.has_remaining() && reader.read_so_far() - extensions_offset < extensions_length) {
      const auto ext_type = static_cast<Extension_Code>(reader.get_uint16_t());
      const auto ext_length = reader.get_uint16_t();

      // skip over all extensions, finding the PSK extension to be truncated
      if(ext_type != Extension_Code::PresharedKey) {
         reader.discard_next(ext_length);
         continue;
      }

      // PSK identities list
      const auto identities_length = reader.get_uint16_t();
      reader.discard_next(identities_length);

      // check that only the binders are left in the buffer...
      const auto binders_length = reader.peek_uint16_t();
      if(binders_length != reader.remaining_bytes() - 2 /* binders_length */) {
         throw TLS_Exception(Alert::IllegalParameter,
                             "Failed to truncate Client Hello that doesn't end on the PSK binders list");
      }

      // the reader now points to the truncation point
      break;
   }

   // if no PSK extension was found, this will point to the end of the buffer
   return reader.read_so_far();
}

std::vector<uint8_t> read_hash_state(std::unique_ptr<HashFunction>& hash) {
   // Botan does not support finalizing a HashFunction without resetting
   // the internal state of the hash. Hence we first copy the internal
   // state and then finalize the transient HashFunction.
   return hash->copy_state()->final_stdvec();
}

}  // namespace

void Transcript_Hash_State::update(std::span<const uint8_t, TLS_HANDSHAKE_HEADER_LENGTH> tls_message_header,
                                   std::span<const uint8_t> serialized_message_s) {
   const auto message_type = static_cast<Handshake_Type>(tls_message_header[0]);
   const auto* serialized_message = serialized_message_s.data();
   auto serialized_message_length = serialized_message_s.size();
   if(m_hash != nullptr) {
      auto truncation_mark = serialized_message_length;

      // Check whether we should generate a truncated hash for supporting PSK
      // binder calculation or verification. See RFC 8446 4.2.11.2.
      if(serialized_message_length > 0 && message_type == Handshake_Type::ClientHello) {
         truncation_mark = find_client_hello_truncation_mark(serialized_message_s, m_flavor);
      }

      m_hash->update(tls_message_header);
      if(truncation_mark < serialized_message_length) {
         m_hash->update(serialized_message, truncation_mark);
         m_truncated = read_hash_state(m_hash);
         m_hash->update(serialized_message + truncation_mark, serialized_message_length - truncation_mark);
      } else {
         m_truncated.clear();
         m_hash->update(serialized_message, serialized_message_length);
      }

      m_previous = std::exchange(m_current, read_hash_state(m_hash));
   } else {
      m_unprocessed_transcript.push_back(concat<std::vector<uint8_t>>(tls_message_header, serialized_message_s));
   }
}

void Transcript_Hash_State::update(std::span<const uint8_t> tls_message_header_and_serialized_message) {
   BOTAN_ASSERT(tls_message_header_and_serialized_message.size() >= TLS_HANDSHAKE_HEADER_LENGTH,
                "Message is at least as long as the Handshake Layer's header");
   update(tls_message_header_and_serialized_message.first<TLS_HANDSHAKE_HEADER_LENGTH>(),
          tls_message_header_and_serialized_message.subspan(TLS_HANDSHAKE_HEADER_LENGTH));
}

const Transcript_Hash& Transcript_Hash_State::current() const {
   BOTAN_STATE_CHECK(!m_current.empty());
   return m_current;
}

const Transcript_Hash& Transcript_Hash_State::previous() const {
   BOTAN_STATE_CHECK(!m_previous.empty());
   return m_previous;
}

const Transcript_Hash& Transcript_Hash_State::truncated() const {
   BOTAN_STATE_CHECK(!m_truncated.empty());
   return m_truncated;
}

void Transcript_Hash_State::set_algorithm(std::string_view algo_spec) {
   BOTAN_STATE_CHECK(m_hash == nullptr || m_hash->name() == algo_spec);
   if(m_hash != nullptr) {
      return;
   }

   m_hash = HashFunction::create_or_throw(algo_spec);
   for(const auto& msg : m_unprocessed_transcript) {
      update(msg);
   }
   m_unprocessed_transcript.clear();
}

Transcript_Hash_State Transcript_Hash_State::clone() const {
   return *this;
}

}  // namespace Botan::TLS
