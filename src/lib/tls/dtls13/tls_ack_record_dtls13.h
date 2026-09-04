/*
* DTLS 1.3 Acknowledgement message
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_DTLS_ACK_H_
#define BOTAN_TLS_DTLS_ACK_H_

#include <botan/internal/tls_record_13.h>

namespace Botan::TLS {

class ACKs {
   public:
      explicit ACKs(std::vector<RecordNumber> record_numbers);
      explicit ACKs(std::span<const uint8_t> ack_record);

      std::vector<uint8_t> serialize(size_t max_plaintext_length) const;

      const std::vector<RecordNumber>& record_numbers() const { return m_record_numbers; }

   private:
      std::vector<RecordNumber> m_record_numbers;
};

}  // namespace Botan::TLS

#endif
