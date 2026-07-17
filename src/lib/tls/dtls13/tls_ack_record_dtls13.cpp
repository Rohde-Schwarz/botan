/*
* DTLS 1.3 Acknowledgement message
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_ack_record_dtls13.h>

#include <botan/tls_exceptn.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <algorithm>

namespace Botan::TLS {

namespace {

constexpr size_t length_field_size = sizeof(uint16_t);
constexpr size_t record_number_size = sizeof(uint64_t) * 2;  // epoch + sequence number

}  // namespace

ACKs::ACKs(std::vector<RecordNumber> record_numbers) : m_record_numbers(std::move(record_numbers)) {
   // RFC 9147 Section 7
   //    record_numbers: A list of the records containing handshake
   //    messages in the current flight which the endpoint has received
   //    and either processed or buffered, in numerically increasing order.
   std::sort(m_record_numbers.begin(), m_record_numbers.end());
}

ACKs::ACKs(std::span<const uint8_t> ack_record) {
   BufferSlicer bs(ack_record);

   if(bs.remaining() < length_field_size) {
      throw TLS_Exception(AlertType::DecodeError, "ACK record too short to contain length field");
   }

   const auto length = load_be(bs.take<length_field_size>());
   if(bs.remaining() != length) {
      throw TLS_Exception(AlertType::DecodeError, "ACK record length field does not match actual length");
   }

   if(bs.remaining() % record_number_size != 0) {
      throw TLS_Exception(AlertType::DecodeError, "ACK record length not a multiple of 16 bytes");
   }

   m_record_numbers.reserve(bs.remaining() / record_number_size);
   while(!bs.empty()) {
      m_record_numbers.push_back(RecordNumber{
         .epoch = load_be<Epoch_Number>(bs.take<sizeof(uint64_t)>()),
         .sequence_number = load_be(bs.take<sizeof(uint64_t)>()),
      });
   }
   BOTAN_ASSERT_NOMSG(m_record_numbers.size() == length / record_number_size);
}

std::vector<uint8_t> ACKs::serialize() const {
   std::vector<uint8_t> result;

   const auto ack_bytes = m_record_numbers.size() * record_number_size;
   result.reserve(sizeof(uint16_t) /* length */ + ack_bytes);

   const auto length = store_be(checked_cast_to<uint16_t>(ack_bytes));
   result.insert(result.end(), length.begin(), length.end());
   for(const auto& record_number : m_record_numbers) {
      auto one_ack = concat(store_be(record_number.epoch),  //
                            store_be(record_number.sequence_number));
      result.insert(result.end(), one_ack.begin(), one_ack.end());
   }

   return result;
}

}  // namespace Botan::TLS
