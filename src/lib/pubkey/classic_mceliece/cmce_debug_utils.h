/// Delete me on release

#ifndef BOTAN_CMCE_DEBUG_H_
#define BOTAN_CMCE_DEBUG_H_

#include <bitset>
#include <chrono>
#include <iostream>

namespace Botan {

class Stopwatch {
   public:
      Stopwatch() : start_time_(std::chrono::high_resolution_clock::now()) {}

      void reset() { start_time_ = std::chrono::high_resolution_clock::now(); }

      double elapsed_time() const {
         auto end_time = std::chrono::high_resolution_clock::now();
         return std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time_).count();
      }

      void log_with_time(std::string_view str) const {
         double time = elapsed_time();
         std::cout << "[" << time << " ms] " << str << std::endl;
      }

      void log_and_reset(std::string_view str) {
         log_with_time(str);
         reset();
      }

   private:
      std::chrono::time_point<std::chrono::high_resolution_clock> start_time_;
};

template <typename T>
T reverse_bits(T in) {
   constexpr size_t bit_size = sizeof(T) * 8;
   std::bitset<bit_size> bits(in);
   std::bitset<bit_size> reversed_bits;

   for(int i = 0; i < bit_size; ++i) {
      reversed_bits[i] = bits[bit_size - 1 - i];
   }

   return T(reversed_bits.to_ulong());
}

}  // namespace Botan
#endif
