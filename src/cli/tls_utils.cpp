/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_TLS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

#include <botan/tls_policy.h>
#include <botan/tls_version.h>
#include <botan/tls_messages.h>
#include <botan/internal/loadstor.h>
#include <botan/hex.h>
#include <sstream>

#include "tls_helpers.h"

namespace Botan_CLI {

class TLS_Ciphersuites final : public Command
   {
   public:
      TLS_Ciphersuites()
         : Command("tls_ciphers --policy=default --version=tls1.2") {}

      static Botan::TLS::Protocol_Version::Version_Code tls_version_from_str(const std::string& str)
         {
         if(str == "tls1.2" || str == "TLS1.2" || str == "TLS-1.2")
            {
            return Botan::TLS::Protocol_Version::TLS_V12;
            }
         if(str == "dtls1.2" || str == "DTLS1.2" || str == "DTLS-1.2")
            {
            return Botan::TLS::Protocol_Version::DTLS_V12;
            }
         else
            {
            throw CLI_Error("Unknown TLS version '" + str + "'");
            }
         }

      std::string group() const override
         {
         return "tls";
         }

      std::string description() const override
         {
         return "Lists all ciphersuites for a policy and TLS version";
         }

      void go() override
         {
         const std::string policy_type = get_arg("policy");
         const Botan::TLS::Protocol_Version version(tls_version_from_str(get_arg("version")));

         auto policy = load_tls_policy(policy_type);

         if(policy->acceptable_protocol_version(version) == false)
            {
            error_output() << "Error: the policy specified does not allow the given TLS version\n";
            return;
            }

         for(uint16_t suite_id : policy->ciphersuite_list(version))
            {
            const auto s = Botan::TLS::Ciphersuite::by_id(suite_id);
            output() << ((s) ? s->to_string() : "unknown cipher suite") << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("tls_ciphers", TLS_Ciphersuites);

#if defined(BOTAN_HAS_TLS_13)

class TLS_Client_Hello_Reader final : public Command
   {
   public:
      TLS_Client_Hello_Reader()
         : Command("tls_client_hello --hex input") {}

      std::string group() const override
         {
         return "tls";
         }

      std::string description() const override
         {
         return "Parse a TLS client hello message";
         }

      void go() override
         {
         const std::string input_file = get_arg("input");
         std::vector<uint8_t> input;

         if(flag_set("hex"))
            {
            input = Botan::hex_decode(slurp_file_as_str(input_file));
            }
         else
            {
            input = slurp_file(input_file);
            }

         if(input.size() < 45)
            {
            error_output() << "Input too short to be valid\n";
            return;
            }

         // Input also contains the record layer header, strip it
         if(input[0] == 22)
            {
            const size_t len = Botan::make_uint16(input[3], input[4]);

            if(input.size() != len + 5)
               {
               error_output() << "Record layer length invalid\n";
               return;
               }

            input = std::vector<uint8_t>(input.begin() + 5, input.end());
            }

         // Assume the handshake header is there, strip it
         if(input[0] == 1)
            {
            const size_t hs_len = Botan::make_uint32(0, input[1], input[2], input[3]);

            if(input.size() != hs_len + 4)
               {
               error_output() << "Handshake layer length invalid\n";
               return;
               }

            input = std::vector<uint8_t>(input.begin() + 4, input.end());
            }

         try
            {
            auto hello = Botan::TLS::Client_Hello_13::parse(input);

            std::visit([=](const auto& client_hello) { output() << format_hello(client_hello); }, hello);
            }
         catch(std::exception& e)
            {
            error_output() << "Parsing client hello failed: " << e.what() << "\n";
            }
         }

   private:
      static void format_generic_hello(std::ostringstream& oss, const Botan::TLS::Client_Hello& hello, const Botan::TLS::Protocol_Version& version)
         {
         oss << "Version: " << version.to_string() << "\n"
             << "Random: " << Botan::hex_encode(hello.random()) << "\n";

         if(!hello.session_id().empty())
            oss << "SessionID: " << Botan::hex_encode(hello.session_id()) << "\n";
         for(uint16_t csuite_id : hello.ciphersuites())
            {
            const auto csuite = Botan::TLS::Ciphersuite::by_id(csuite_id);
            if(csuite && csuite->valid())
               oss << "Cipher: " << csuite->to_string()  << "\n";
            else if(csuite_id == 0x00FF)
               oss << "Cipher: EMPTY_RENEGOTIATION_INFO_SCSV\n";
            else
               oss << "Cipher: Unknown (" << std::hex << csuite_id << ")\n";
            }

         oss << "Supported signature schemes: ";

         if(!hello.sent_signature_algorithms())
            {
            oss << "Did not send signature_algorithms extension\n";
            }
         else
            {
            for(Botan::TLS::Signature_Scheme scheme : hello.signature_schemes())
               {
               try
                  {
                  auto s = scheme.to_string();
                  oss << s << " ";
                  }
               catch(...)
                  {
                  oss << "(" << std::hex << static_cast<unsigned int>(scheme.wire_code()) << ") ";
                  }
               }
            oss << "\n";
            }

         std::map<std::string, bool> hello_flags;
         hello_flags["ALPN"] = hello.supports_alpn();

         for(auto&& i : hello_flags)
            oss << "Supports " << i.first << "? " << (i.second ? "yes" : "no") << "\n";
         }

      static std::string format_hello(const Botan::TLS::Client_Hello_12& hello)
         {
         std::ostringstream oss;

         format_generic_hello(oss, hello, hello.legacy_version());

         std::map<std::string, bool> hello_flags;
         hello_flags["Encrypt Then Mac"] = hello.supports_encrypt_then_mac();
         hello_flags["Extended Master Secret"] = hello.supports_extended_master_secret();
         hello_flags["Session Ticket"] = hello.supports_session_ticket();

         for(auto&& i : hello_flags)
            oss << "Supports " << i.first << "? " << (i.second ? "yes" : "no") << "\n";

         return oss.str();
         }

      static std::string format_hello(const Botan::TLS::Client_Hello_13& hello)
         {
         std::ostringstream oss;

         format_generic_hello(oss, hello, Botan::TLS::Protocol_Version::TLS_V13);

         std::map<std::string, bool> hello_flags;
         hello_flags["Middlebox Compatibility Mode"] = !hello.session_id().empty();

         for(auto&& i : hello_flags)
            oss << "Supports " << i.first << "? " << (i.second ? "yes" : "no") << "\n";

         const auto& exts = hello.extensions();

         oss << "Supported TLS versions: ";
         for(auto version : exts.get<Botan::TLS::Supported_Versions>()->versions())
            {
            oss << version.to_string() << " ";
            }
         oss << "\n";

         oss << "Supported Key Exchange Groups:\n";
         if(exts.has<Botan::TLS::Supported_Groups>())
            {
            for(auto group : exts.get<Botan::TLS::Supported_Groups>()->groups())
               {
               oss << "Group: " << group_to_string(group) << "\n";
               }
            }
         else
            {
            oss << "no such extension sent\n";
            }

         oss << "Pre-offered Key Exchange Groups:\n";
         if(exts.has<Botan::TLS::Key_Share>())
            {
            for(auto group : exts.get<Botan::TLS::Key_Share>()->offered_groups())
               {
               oss << "Offered Group: " << group_to_string(group) << "\n";
               }
            }
         else
            {
            oss << "no such extension sent\n";
            }

         if(exts.has<Botan::TLS::Record_Size_Limit>())
            {
            oss << "Record Size Limit: " << exts.get<Botan::TLS::Record_Size_Limit>()->limit() << "\n";
            }

         return oss.str();
         }

      static std::string group_to_string(const Botan::TLS::Group_Params& group)
         {
         std::ostringstream oss;

         const auto group_name = Botan::TLS::group_param_to_string(group);
         if(group_name.empty())
            {
            oss << "unknown group (" << static_cast<uint16_t>(group) << ")";
            }
         else
            {
            oss << group_name;
            }

         return oss.str();
         }
   };

BOTAN_REGISTER_COMMAND("tls_client_hello", TLS_Client_Hello_Reader);

#endif

}

#endif
