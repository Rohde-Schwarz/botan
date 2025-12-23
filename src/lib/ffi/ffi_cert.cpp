/*
* (C) 2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_pkey.h>
#include <botan/internal/ffi_util.h>
#include <memory>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/data_src.h>
   #include <botan/der_enc.h>
   #include <botan/x509_crl.h>
   #include <botan/x509_ext.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/parsing.h>
   #include <botan/internal/stl_util.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cert_struct, Botan::X509_Certificate, 0x8F628937);
BOTAN_FFI_DECLARE_STRUCT(botan_x509_alt_names_struct, Botan::AlternativeName, 0xBD9144C5);

#endif

int botan_x509_cert_load_file(botan_x509_cert_t* cert_obj, const char* cert_path) {
   if(cert_obj == nullptr || cert_path == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_Certificate>(cert_path);
      return ffi_new_object(cert_obj, std::move(c));
   });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_dup(botan_x509_cert_t* cert_obj, botan_x509_cert_t cert) {
   if(cert_obj == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_Certificate>(safe_get(cert));
      return ffi_new_object(cert_obj, std::move(c));
   });

#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_load(botan_x509_cert_t* cert_obj, const uint8_t cert_bits[], size_t cert_bits_len) {
   if(cert_obj == nullptr || cert_bits == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(cert_bits, cert_bits_len);
      auto c = std::make_unique<Botan::X509_Certificate>(bits);
      return ffi_new_object(cert_obj, std::move(c));
   });
#else
   BOTAN_UNUSED(cert_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

namespace {

int botan_x509_object_view_binary_values(const Botan::X509_Object& object,
                                         botan_x509_value_type value_type,
                                         botan_view_ctx ctx,
                                         botan_view_bin_fn view_fn) {
   auto view = [=](std::span<const uint8_t> value) { return invoke_view_callback(view_fn, ctx, value); };

   switch(value_type) {
      case BOTAN_X509_TBS_DATA_BITS:
         return view(object.tbs_data());
      case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         return view(object.signature_algorithm().BER_encode());
      case BOTAN_X509_SIGNATURE_BITS:
         return view(object.signature());
      case BOTAN_X509_DER_ENCODING:
         return view(object.BER_encode());
      default:
         return BOTAN_FFI_ERROR_INTERNAL_ERROR; /* called with unexpected (non-generic) value_type */
   }
}

}  // namespace

extern "C" {

int botan_x509_cert_view_binary_values(botan_x509_cert_t cert,
                                       botan_x509_value_type value_type,
                                       size_t index,
                                       botan_view_ctx ctx,
                                       botan_view_bin_fn view_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(index != 0) {
      // As of now there are no multi-value binary entries.
      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   }

   auto view = [=](std::span<const uint8_t> value) { return invoke_view_callback(view_fn, ctx, value); };

   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) -> int {
      switch(value_type) {
         case BOTAN_X509_SERIAL_NUMBER:
            return view(c.serial_number());
         case BOTAN_X509_SUBJECT_DN_BITS:
            return view(c.raw_subject_dn());
         case BOTAN_X509_ISSUER_DN_BITS:
            return view(c.raw_issuer_dn());
         case BOTAN_X509_SUBJECT_KEY_IDENTIFIER:
            return c.subject_key_id().empty() ? BOTAN_FFI_ERROR_NO_VALUE : view(c.subject_key_id());
         case BOTAN_X509_AUTHORITY_KEY_IDENTIFIER:
            return c.authority_key_id().empty() ? BOTAN_FFI_ERROR_NO_VALUE : view(c.authority_key_id());
         case BOTAN_X509_PUBLIC_KEY_PKCS8_BITS:
            return view(c.subject_public_key_info());

         case BOTAN_X509_TBS_DATA_BITS:
         case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         case BOTAN_X509_SIGNATURE_BITS:
         case BOTAN_X509_DER_ENCODING:
            return botan_x509_object_view_binary_values(c, value_type, ctx, view_fn);

         case BOTAN_X509_CRL_DISTRIBUTION_URLS:
         case BOTAN_X509_OCSP_RESPONDER_URLS:
         case BOTAN_X509_CA_ISSUERS_URLS:
            return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
#else
   BOTAN_UNUSED(cert, value_type, index, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_view_string_values(botan_x509_cert_t cert,
                                       botan_x509_value_type value_type,
                                       size_t index,
                                       botan_view_ctx ctx,
                                       botan_view_str_fn view_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   auto enumerate = [view_fn, ctx](auto values, size_t idx) -> int {
      if(idx >= values.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      } else {
         return invoke_view_callback(view_fn, ctx, values[idx]);
      }
   };

   auto enumerate_crl_distribution_points = [view_fn, ctx](const Botan::X509_Certificate& c, size_t idx) -> int {
      const auto* crl_dp_ext =
         c.v3_extensions().get_extension_object_as<Botan::Cert_Extension::CRL_Distribution_Points>();
      if(crl_dp_ext == nullptr) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;  // essentially an empty list
      }

      const auto& dps = crl_dp_ext->distribution_points();
      for(size_t i = idx; const auto& dp : dps) {
         const auto& uris = dp.point().uris();
         if(i >= uris.size()) {
            i -= uris.size();
            continue;
         }

         auto itr = uris.begin();
         std::advance(itr, i);
         return invoke_view_callback(view_fn, ctx, *itr);
      }

      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   };

   auto wrap_or_empty = [](std::string str) -> std::vector<std::string> {
      if(str.empty()) {
         return {};
      } else {
         return {std::move(str)};
      }
   };

   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) -> int {
      switch(value_type) {
         case BOTAN_X509_CRL_DISTRIBUTION_URLS:
            return enumerate_crl_distribution_points(c, index);
         case BOTAN_X509_OCSP_RESPONDER_URLS:
            return enumerate(wrap_or_empty(c.ocsp_responder()), index);
         case BOTAN_X509_CA_ISSUERS_URLS:
            return enumerate(c.ca_issuers(), index);

         case BOTAN_X509_SERIAL_NUMBER:
         case BOTAN_X509_SUBJECT_DN_BITS:
         case BOTAN_X509_ISSUER_DN_BITS:
         case BOTAN_X509_SUBJECT_KEY_IDENTIFIER:
         case BOTAN_X509_AUTHORITY_KEY_IDENTIFIER:
         case BOTAN_X509_PUBLIC_KEY_PKCS8_BITS:
         case BOTAN_X509_TBS_DATA_BITS:
         case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         case BOTAN_X509_SIGNATURE_BITS:
         case BOTAN_X509_DER_ENCODING:
            return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
#else
   BOTAN_UNUSED(cert, value_type, index, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_is_ca(botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return c.is_CA_cert() ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_path_length_constraint(botan_x509_cert_t cert, size_t* path_limit) {
   if(path_limit == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      if(const auto path_len = c.path_length_constraint()) {
         *path_limit = path_len.value();
         return BOTAN_FFI_SUCCESS;
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(cert, path_limit);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_public_key(botan_x509_cert_t cert, botan_pubkey_t* key) {
   if(key == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   *key = nullptr;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto public_key = safe_get(cert).subject_public_key();
      return ffi_new_object(key, std::move(public_key));
   });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_issuer_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      auto issuer_info = c.issuer_info(key);
      if(index < issuer_info.size()) {
         // TODO(Botan4) change the type of out and remove this cast
         return write_str_output(reinterpret_cast<char*>(out), out_len, c.issuer_info(key).at(index));
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_dn(
   botan_x509_cert_t cert, const char* key, size_t index, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      auto subject_info = c.subject_info(key);
      if(index < subject_info.size()) {
         // TODO(Botan4) change the type of out and remove this cast
         return write_str_output(reinterpret_cast<char*>(out), out_len, c.subject_info(key).at(index));
      } else {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
   });
#else
   BOTAN_UNUSED(cert, key, index, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_to_string(botan_x509_cert_t cert, char out[], size_t* out_len) {
   return copy_view_str(reinterpret_cast<uint8_t*>(out), out_len, botan_x509_cert_view_as_string, cert);
}

int botan_x509_cert_view_as_string(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return invoke_view_callback(view, ctx, c.to_string()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_allowed_usage(botan_x509_cert_t cert, unsigned int key_usage) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int {
      const Botan::Key_Constraints k = static_cast<Botan::Key_Constraints>(key_usage);
      if(c.allowed_usage(k)) {
         return BOTAN_FFI_SUCCESS;
      }
      return 1;
   });
#else
   BOTAN_UNUSED(cert, key_usage);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_has_ex_constraint(botan_x509_cert_t cert, const char* oid) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) -> int { return c.has_ex_constraint(oid) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert, oid);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_destroy(botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(cert);
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_time_starts(botan_x509_cert_t cert, char out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.not_before().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_time_expires(botan_x509_cert_t cert, char out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return write_str_output(out, out_len, c.not_after().to_string()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_not_before(botan_x509_cert_t cert, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *time_since_epoch = c.not_before().time_since_epoch(); });
#else
   BOTAN_UNUSED(cert, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_not_after(botan_x509_cert_t cert, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { *time_since_epoch = c.not_after().time_since_epoch(); });
#else
   BOTAN_UNUSED(cert, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_serial_number(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.serial_number()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_fingerprint(botan_x509_cert_t cert, const char* hash, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   // TODO(Botan4) change the type of out and remove this cast

   return BOTAN_FFI_VISIT(cert, [=](const auto& c) {
      return write_str_output(reinterpret_cast<char*>(out), out_len, c.fingerprint(hash));
   });
#else
   BOTAN_UNUSED(cert, hash, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_authority_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.authority_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_subject_key_id(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return write_vec_output(out, out_len, c.subject_key_id()); });
#else
   BOTAN_UNUSED(cert, out, out_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_get_public_key_bits(botan_x509_cert_t cert, uint8_t out[], size_t* out_len) {
   return copy_view_bin(out, out_len, botan_x509_cert_view_public_key_bits, cert);
}

int botan_x509_cert_view_public_key_bits(botan_x509_cert_t cert, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert,
                          [=](const auto& c) { return invoke_view_callback(view, ctx, c.subject_public_key_bits()); });
#else
   BOTAN_UNUSED(cert, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_subject_alternative_names(botan_x509_cert_t cert, botan_x509_alt_names_t* alt_names) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) {
      if(Botan::any_null_pointers(alt_names)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      const auto& san = c.subject_alt_name();
      if(!san.has_items()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return ffi_new_object(alt_names, std::make_unique<Botan::AlternativeName>(san));
   });
#else
   BOTAN_UNUSED(cert, alt_names);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_issuer_alternative_names(botan_x509_cert_t cert, botan_x509_alt_names_t* alt_names) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const Botan::X509_Certificate& c) {
      if(Botan::any_null_pointers(alt_names)) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }

      const auto& ian = c.issuer_alt_name();
      if(!ian.has_items()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return ffi_new_object(alt_names, std::make_unique<Botan::AlternativeName>(ian));
   });
#else
   BOTAN_UNUSED(cert, alt_names);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alternative_names_destroy(botan_x509_alt_names_t alt_names) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(alt_names);
#else
   BOTAN_UNUSED(alt_names);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}

namespace {

using altname_dataset_variant = std::variant<std::reference_wrapper<const std::set<std::string>>,
                                             std::reference_wrapper<const std::set<uint32_t>>,
                                             std::reference_wrapper<const std::set<Botan::X509_DN>>>;

altname_dataset_variant get_alternative_name_set(const Botan::AlternativeName& alt_names, unsigned int type) {
   switch(static_cast<botan_x509_alternative_name_types>(type)) {
      case ALTNAME_EMAIL:
         return alt_names.email();
      case ALTNAME_DNS:
         return alt_names.dns();
      case ALTNAME_DIRNAME:
         return alt_names.directory_names();
      case ALTNAME_URI:
         return alt_names.uris();
      case ALTNAME_IP4_ADDRESS:
         return alt_names.ipv4_address();
   }

   BOTAN_ASSERT_UNREACHABLE();
}

template <typename ViewFnT, typename EncoderFnT>
   requires std::same_as<botan_view_bin_fn, ViewFnT> || std::same_as<botan_view_str_fn, ViewFnT>
int select_and_encode_value_then_invoke_view_callback(
   size_t index, botan_view_ctx ctx, ViewFnT view_fn, altname_dataset_variant set, EncoderFnT encoder_fn) {
   return std::visit(
      [=](const auto& items) -> int {
         if(items.get().size() <= index) {
            return BOTAN_FFI_ERROR_OUT_OF_RANGE;
         }

         auto item = items.get().begin();
         std::advance(item, index);

         if constexpr(std::invocable<decltype(encoder_fn), decltype(*item)>) {
            return invoke_view_callback(view_fn, ctx, encoder_fn(*item));
         } else {
            return BOTAN_FFI_ERROR_NO_VALUE;
         }
      },
      set);
}

}  // namespace

extern "C" {

int botan_x509_alternative_names_items_of(botan_x509_alt_names_t alt_names, unsigned int type, size_t* count) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_names, [=](const Botan::AlternativeName& an) {
      std::visit([=](const auto& items) { *count = items.get().size(); }, get_alternative_name_set(an, type));
   });
#else
   BOTAN_UNUSED(alt_names, type, count);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alternative_names_view_str_item_at(
   botan_x509_alt_names_t alt_names, unsigned int type, size_t index, botan_view_ctx ctx, botan_view_str_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_names, [=](const Botan::AlternativeName& an) {
      return select_and_encode_value_then_invoke_view_callback(
         index,
         ctx,
         view,
         get_alternative_name_set(an, type),
         Botan::overloaded{
            [](std::string str) { return str; },
            [](uint32_t ip4addr) { return Botan::ipv4_to_string(ip4addr); },
         });
   });
#else
   BOTAN_UNUSED(alt_names, type, index, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_alternative_names_view_bin_item_at(
   botan_x509_alt_names_t alt_names, unsigned int type, size_t index, botan_view_ctx ctx, botan_view_bin_fn view) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(alt_names, [=](const Botan::AlternativeName& an) {
      return select_and_encode_value_then_invoke_view_callback(
         index,
         ctx,
         view,
         get_alternative_name_set(an, type),
         Botan::overloaded{
            [](const Botan::X509_DN& dn) {
               std::vector<uint8_t> dn_bytes;
               auto der = Botan::DER_Encoder(dn_bytes);
               dn.encode_into(der);
               return dn_bytes;
            },
            [](uint32_t ipaddr) { return Botan::store_be(ipaddr); },
         });
   });
#else
   BOTAN_UNUSED(alt_names, type, index, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_hostname_match(botan_x509_cert_t cert, const char* hostname) {
   if(hostname == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(cert, [=](const auto& c) { return c.matches_dns_name(hostname) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_verify(int* result_code,
                           botan_x509_cert_t cert,
                           const botan_x509_cert_t* intermediates,
                           size_t intermediates_len,
                           const botan_x509_cert_t* trusted,
                           size_t trusted_len,
                           const char* trusted_path,
                           size_t required_strength,
                           const char* hostname_cstr,
                           uint64_t reference_time) {
   if(required_strength == 0) {
      required_strength = 110;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string hostname((hostname_cstr == nullptr) ? "" : hostname_cstr);
      const Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;
      const auto validation_time = reference_time == 0
                                      ? std::chrono::system_clock::now()
                                      : std::chrono::system_clock::from_time_t(static_cast<time_t>(reference_time));

      std::vector<Botan::X509_Certificate> end_certs;
      end_certs.push_back(safe_get(cert));
      for(size_t i = 0; i != intermediates_len; ++i) {
         end_certs.push_back(safe_get(intermediates[i]));
      }

      std::unique_ptr<Botan::Certificate_Store> trusted_from_path;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_extra;
      std::vector<Botan::Certificate_Store*> trusted_roots;

      if(trusted_path != nullptr && *trusted_path != 0) {
         trusted_from_path = std::make_unique<Botan::Certificate_Store_In_Memory>(trusted_path);
         trusted_roots.push_back(trusted_from_path.get());
      }

      if(trusted_len > 0) {
         trusted_extra = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != trusted_len; ++i) {
            trusted_extra->add_certificate(safe_get(trusted[i]));
         }
         trusted_roots.push_back(trusted_extra.get());
      }

      const Botan::Path_Validation_Restrictions restrictions(false, required_strength);

      auto validation_result =
         Botan::x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, validation_time);

      if(result_code != nullptr) {
         *result_code = static_cast<int>(validation_result.result());
      }

      if(validation_result.successful_validation()) {
         return 0;
      } else {
         return 1;
      }
   });
#else
   BOTAN_UNUSED(result_code, cert, intermediates, intermediates_len, trusted);
   BOTAN_UNUSED(trusted_len, trusted_path, hostname_cstr, reference_time);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

const char* botan_x509_cert_validation_status(int code) {
   if(code < 0) {
      return nullptr;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   const Botan::Certificate_Status_Code sc = static_cast<Botan::Certificate_Status_Code>(code);
   return Botan::to_string(sc);
#else
   return nullptr;
#endif
}

#if defined(BOTAN_HAS_X509_CERTIFICATES)

BOTAN_FFI_DECLARE_STRUCT(botan_x509_crl_struct, Botan::X509_CRL, 0x2C628910);

#endif

int botan_x509_crl_load_file(botan_x509_crl_t* crl_obj, const char* crl_path) {
   if(crl_obj == nullptr || crl_path == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   return ffi_guard_thunk(__func__, [=]() -> int {
      auto c = std::make_unique<Botan::X509_CRL>(crl_path);
      return ffi_new_object(crl_obj, std::move(c));
   });

#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_load(botan_x509_crl_t* crl_obj, const uint8_t crl_bits[], size_t crl_bits_len) {
   if(crl_obj == nullptr || crl_bits == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      Botan::DataSource_Memory bits(crl_bits, crl_bits_len);
      auto c = std::make_unique<Botan::X509_CRL>(bits);
      return ffi_new_object(crl_obj, std::move(c));
   });
#else
   BOTAN_UNUSED(crl_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_this_update(botan_x509_crl_t crl, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) { *time_since_epoch = c.this_update().time_since_epoch(); });
#else
   BOTAN_UNUSED(crl, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_next_update(botan_x509_crl_t crl, uint64_t* time_since_epoch) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) {
      const auto time = c.next_update();
      if(!time.time_is_set()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      *time_since_epoch = c.next_update().time_since_epoch();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(crl, time_since_epoch);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_destroy(botan_x509_crl_t crl) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(crl);
#else
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_view_binary_values(botan_x509_crl_t crl_obj,
                                      botan_x509_value_type value_type,
                                      size_t index,
                                      botan_view_ctx ctx,
                                      botan_view_bin_fn view_fn) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(index != 0) {
      // As of now there are no multi-value binary entries.
      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   }

   auto view = [=](std::span<const uint8_t> value) { return invoke_view_callback(view_fn, ctx, value); };

   return BOTAN_FFI_VISIT(crl_obj, [=](const Botan::X509_CRL& crl) -> int {
      switch(value_type) {
         case BOTAN_X509_SERIAL_NUMBER:
            return view(Botan::store_be(crl.crl_number()));
         case BOTAN_X509_ISSUER_DN_BITS:
            return view(Botan::ASN1::put_in_sequence(crl.issuer_dn().get_bits()));
         case BOTAN_X509_AUTHORITY_KEY_IDENTIFIER:
            return crl.authority_key_id().empty() ? BOTAN_FFI_ERROR_NO_VALUE : view(crl.authority_key_id());

         case BOTAN_X509_TBS_DATA_BITS:
         case BOTAN_X509_SIGNATURE_SCHEME_BITS:
         case BOTAN_X509_SIGNATURE_BITS:
         case BOTAN_X509_DER_ENCODING:
            return botan_x509_object_view_binary_values(crl, value_type, ctx, view_fn);

         case BOTAN_X509_SUBJECT_DN_BITS:
         case BOTAN_X509_SUBJECT_KEY_IDENTIFIER:
         case BOTAN_X509_PUBLIC_KEY_PKCS8_BITS:
         case BOTAN_X509_CRL_DISTRIBUTION_URLS:
         case BOTAN_X509_OCSP_RESPONDER_URLS:
         case BOTAN_X509_CA_ISSUERS_URLS:
            return BOTAN_FFI_ERROR_NO_VALUE;
      }

      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   });
#else
   BOTAN_UNUSED(crl_obj, value_type, index, ctx, view);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_is_revoked(botan_x509_crl_t crl, botan_x509_cert_t cert) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const auto& c) { return c.is_revoked(safe_get(cert)) ? 0 : -1; });
#else
   BOTAN_UNUSED(cert);
   BOTAN_UNUSED(crl);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_crl_get_entry(botan_x509_crl_t crl,
                             size_t index,
                             uint64_t* expire_time_seconds_since_epoch,
                             uint8_t* reason,
                             uint8_t serial_bits[],
                             size_t* serial_bits_len) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_VISIT(crl, [=](const Botan::X509_CRL& c) -> int {
      const auto& entries = c.get_revoked();
      if(index >= entries.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      }

      const auto& entry = entries[index];

      if(serial_bits_len) {
         const auto rc = write_vec_output(serial_bits, serial_bits_len, entry.serial_number());
         if(rc != BOTAN_FFI_SUCCESS) {
            return rc;
         }
      }

      if(expire_time_seconds_since_epoch) {
         *expire_time_seconds_since_epoch = entry.expire_time().time_since_epoch();
      }

      if(reason) {
         *reason = static_cast<uint8_t>(entry.reason_code());
      }

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(crl, index, expire_time_seconds_since_epoch, reason, searial_bits, serial_bits_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_cert_verify_with_crl(int* result_code,
                                    botan_x509_cert_t cert,
                                    const botan_x509_cert_t* intermediates,
                                    size_t intermediates_len,
                                    const botan_x509_cert_t* trusted,
                                    size_t trusted_len,
                                    const botan_x509_crl_t* crls,
                                    size_t crls_len,
                                    const char* trusted_path,
                                    size_t required_strength,
                                    const char* hostname_cstr,
                                    uint64_t reference_time) {
   if(required_strength == 0) {
      required_strength = 110;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const std::string hostname((hostname_cstr == nullptr) ? "" : hostname_cstr);
      const Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;
      const auto validation_time = reference_time == 0
                                      ? std::chrono::system_clock::now()
                                      : std::chrono::system_clock::from_time_t(static_cast<time_t>(reference_time));

      std::vector<Botan::X509_Certificate> end_certs;
      end_certs.push_back(safe_get(cert));
      for(size_t i = 0; i != intermediates_len; ++i) {
         end_certs.push_back(safe_get(intermediates[i]));
      }

      std::unique_ptr<Botan::Certificate_Store> trusted_from_path;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_extra;
      std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_crls;
      std::vector<Botan::Certificate_Store*> trusted_roots;

      if(trusted_path != nullptr && *trusted_path != 0) {
         trusted_from_path = std::make_unique<Botan::Certificate_Store_In_Memory>(trusted_path);
         trusted_roots.push_back(trusted_from_path.get());
      }

      if(trusted_len > 0) {
         trusted_extra = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != trusted_len; ++i) {
            trusted_extra->add_certificate(safe_get(trusted[i]));
         }
         trusted_roots.push_back(trusted_extra.get());
      }

      if(crls_len > 0) {
         trusted_crls = std::make_unique<Botan::Certificate_Store_In_Memory>();
         for(size_t i = 0; i != crls_len; ++i) {
            trusted_crls->add_crl(safe_get(crls[i]));
         }
         trusted_roots.push_back(trusted_crls.get());
      }

      const Botan::Path_Validation_Restrictions restrictions(false, required_strength);

      auto validation_result =
         Botan::x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, validation_time);

      if(result_code != nullptr) {
         *result_code = static_cast<int>(validation_result.result());
      }

      if(validation_result.successful_validation()) {
         return 0;
      } else {
         return 1;
      }
   });
#else
   BOTAN_UNUSED(result_code, cert, intermediates, intermediates_len, trusted);
   BOTAN_UNUSED(trusted_len, trusted_path, hostname_cstr, reference_time, crls, crls_len);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
