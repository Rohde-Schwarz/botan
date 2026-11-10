/*
* DTLS utilities
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_UTILS_DTLS_13_H_
#define BOTAN_TLS_UTILS_DTLS_13_H_

#include <botan/internal/tls_types_dtls13.h>
#include <chrono>
#include <optional>

namespace Botan::TLS {

/**
 * RFC 9147 4.2.2
 *    [I]mplementations SHOULD reconstruct the sequence number by computing
 *    the full sequence number which is numerically closest to one plus the
 *    sequence number of the highest successfully deprotected record in the
 *    current epoch.
 *
 * The wire carries only the low 8 or 16 bits of the sequence number, so the
 * full value is ambiguous modulo 2^bits (the "window"). We resolve the
 * ambiguity by picking the value within the window that is closest to the
 * expected next sequence number. This tolerates reordering and loss of up to
 * half a window in either direction and ties at exactly half a window resolve
 * to the higher value.
 */
constexpr uint64_t reconstruct_full_sequence_number(uint64_t highest_seen_seqno, SequenceNumberHint record_seqno_hint) {
   return std::visit(
      [&]<std::unsigned_integral T>(T hint) {
         constexpr size_t bits = sizeof(T) * 8;
         constexpr uint64_t window = uint64_t{1} << bits;
         constexpr uint64_t half_window = window / 2;

         const uint64_t expected = highest_seen_seqno + 1;

         // First guess: keep the high bits of the expected next sequence
         // number and replace the low bits with the transmitted hint. This
         // yields the unique value congruent to the hint modulo the window
         // that differs from `expected` by less than a full window.
         const uint64_t candidate = (expected & ~(window - 1)) | uint64_t(hint);

         // The first guess may still be up to a full window off. Shifting it
         // by exactly one window preserves congruence with the hint, so pick
         // whichever shift lands closest to `expected`.
         if(candidate + half_window <= expected) {
            return candidate + window;
         } else if(candidate > expected + half_window &&
                   candidate >= window /* prevent underflow at the start of an epoch */) {
            return candidate - window;
         } else {
            return candidate;
         }
      },
      record_seqno_hint);
}

class Replay_Window_13 {
   private:
      using window_type = uint64_t;

   public:
      constexpr static size_t window_size = sizeof(window_type) * 8;

   public:
      /**
       * Adds the given sequence number to the replay window. Note that the
       * reconstructed sequence number of an already authenticated record
       * must be provided.
       *
       * RFC 9147 Section 4.5.1
       *    The window MUST NOT be updated due to a received record until that
       *    record has been deprotected successfully.
       *
       * @returns false if the sequence number has already been seen or falls
       *          outside the window, true otherwise.
       */
      constexpr bool accept(uint64_t sequence_number) {
         // RFC 9147 Section 4.5.1
         //     If the received record [...] is to the right of the window,
         //     then the record is new.
         if(sequence_number > highest_sequence_number) {
            const uint64_t offset = sequence_number - highest_sequence_number;
            if(offset >= window_size) {
               window = 0;
            } else {
               window <<= offset;
            }

            highest_sequence_number = sequence_number;
            window |= 1;  // set bit for new highest sequence number
            return true;
         }

         const uint64_t offset = highest_sequence_number - sequence_number;

         // RFC 9147 Section 4.5.1
         //   Records that contain sequence numbers lower than the "left" edge
         //   of the window are rejected.
         if(offset >= window_size) {
            return false;  // too old
         }

         // RFC 9147 Section 4.5.1
         //    Records falling within the window are checked against a list of
         //    received records within the window.
         const bool is_duplicate = ((window >> offset) & 1) == 1;

         // RFC 9147 Section 4.5.1
         //    Duplicates are rejected [...].
         if(is_duplicate) {
            return false;
         }

         // RFC 9147 Section 4.5.1
         //    If the received record falls within the window and is new,
         //    [...] then the record is new.
         window |= (static_cast<uint64_t>(1) << offset);
         return true;
      }

   private:
      uint64_t highest_sequence_number = 0;
      uint64_t window = 0;
};

}  // namespace Botan::TLS

#endif
