/*
* Lightweight wrappers for SIMD operations
* (C) 2009,2011,2016,2017,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_32_H_
#define BOTAN_SIMD_32_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <botan/internal/target_info.h>
#include <span>

#if defined(BOTAN_TARGET_CPU_SUPPORTS_SSE2)
   #include <emmintrin.h>
   #define BOTAN_SIMD_USE_SSE2

#elif defined(BOTAN_TARGET_CPU_SUPPORTS_ALTIVEC)
   #include <botan/internal/loadstor.h>
   #include <altivec.h>
   #undef vector
   #undef bool
   #define BOTAN_SIMD_USE_ALTIVEC
   #ifdef __VSX__
      #define BOTAN_SIMD_USE_VSX
   #endif

#elif defined(BOTAN_TARGET_CPU_SUPPORTS_NEON)
   #include <arm_neon.h>
   #include <bit>
   #define BOTAN_SIMD_USE_NEON

#else
   #error "No SIMD instruction set enabled"
#endif

#if defined(BOTAN_SIMD_USE_SSE2)
   #define BOTAN_SIMD_ISA "sse2"
   #define BOTAN_VPERM_ISA "ssse3"
   #define BOTAN_CLMUL_ISA "pclmul"
#elif defined(BOTAN_SIMD_USE_NEON)
   #if defined(BOTAN_TARGET_ARCH_IS_ARM64)
      #define BOTAN_SIMD_ISA "+simd"
      #define BOTAN_CLMUL_ISA "+crypto+aes"
   #else
      #define BOTAN_SIMD_ISA "fpu=neon"
   #endif
   #define BOTAN_VPERM_ISA BOTAN_SIMD_ISA
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
   #define BOTAN_SIMD_ISA "altivec"
   #define BOTAN_VPERM_ISA "altivec"
   #define BOTAN_CLMUL_ISA "crypto"
#endif

namespace Botan {

#if defined(BOTAN_SIMD_USE_SSE2)
using native_simd_type = __m128i;
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
using native_simd_type = __vector unsigned int;
#elif defined(BOTAN_SIMD_USE_NEON)
using native_simd_type = uint32x4_t;
#endif

/**
* 4x32 bit SIMD register
*
* This class is not a general purpose SIMD type, and only offers
* instructions needed for evaluation of specific crypto primitives.
* For example it does not currently have equality operators of any
* kind.
*
* Implemented for SSE2, VMX (Altivec), and NEON.
*/
class SIMD_4x32 final {
   public:
      SIMD_4x32& operator=(const SIMD_4x32& other) = default;
      SIMD_4x32(const SIMD_4x32& other) = default;

      SIMD_4x32& operator=(SIMD_4x32&& other) = default;
      SIMD_4x32(SIMD_4x32&& other) = default;

      ~SIMD_4x32() = default;

      /**
      * Zero initialize SIMD register with 4 32-bit elements
      */
      SIMD_4x32() noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         m_simd = _mm_setzero_si128();
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_splat_u32(0);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vdupq_n_u32(0);
#endif
      }

      /**
      * Load SIMD register with 4 32-bit elements
      */
      SIMD_4x32(uint32_t B0, uint32_t B1, uint32_t B2, uint32_t B3) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         m_simd = _mm_set_epi32(B3, B2, B1, B0);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         __vector unsigned int val = {B0, B1, B2, B3};
         m_simd = val;
#elif defined(BOTAN_SIMD_USE_NEON)
         // Better way to do this?
         const uint32_t B[4] = {B0, B1, B2, B3};
         m_simd = vld1q_u32(B);
#endif
      }

      /**
      * Load SIMD register with one 32-bit element repeated
      */
      static SIMD_4x32 splat(uint32_t B) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_set1_epi32(B));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vdupq_n_u32(B));
#else
         return SIMD_4x32(B, B, B, B);
#endif
      }

      /**
      * Load SIMD register with one 8-bit element repeated
      */
      static SIMD_4x32 splat_u8(uint8_t B) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_set1_epi8(B));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vreinterpretq_u32_u8(vdupq_n_u8(B)));
#else
         const uint32_t B4 = make_uint32(B, B, B, B);
         return SIMD_4x32(B4, B4, B4, B4);
#endif
      }

      /**
      * Load a SIMD register with little-endian convention
      */
      static SIMD_4x32 load_le(const void* in) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         uint32_t R[4];
         Botan::load_le(R, static_cast<const uint8_t*>(in), 4);
         __vector unsigned int val = {R[0], R[1], R[2], R[3]};
         return SIMD_4x32(val);
#elif defined(BOTAN_SIMD_USE_NEON)
         SIMD_4x32 l(vld1q_u32(static_cast<const uint32_t*>(in)));
         if constexpr(std::endian::native == std::endian::big) {
            return l.bswap();
         } else {
            return l;
         }
#endif
      }

      /**
      * Load a SIMD register with big-endian convention
      */
      static SIMD_4x32 load_be(const void* in) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         return load_le(in).bswap();

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         uint32_t R[4];
         Botan::load_be(R, static_cast<const uint8_t*>(in), 4);
         __vector unsigned int val = {R[0], R[1], R[2], R[3]};
         return SIMD_4x32(val);

#elif defined(BOTAN_SIMD_USE_NEON)
         SIMD_4x32 l(vld1q_u32(static_cast<const uint32_t*>(in)));
         if constexpr(std::endian::native == std::endian::little) {
            return l.bswap();
         } else {
            return l;
         }
#endif
      }

      static SIMD_4x32 load_le(std::span<const uint8_t, 16> in) { return SIMD_4x32::load_le(in.data()); }

      static SIMD_4x32 load_be(std::span<const uint8_t, 16> in) { return SIMD_4x32::load_be(in.data()); }

      void store_le(uint32_t out[4]) const noexcept { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      void store_be(uint32_t out[4]) const noexcept { this->store_be(reinterpret_cast<uint8_t*>(out)); }

      void store_le(uint64_t out[2]) const noexcept { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      /**
      * Load a SIMD register with little-endian convention
      */
      void store_le(uint8_t out[]) const noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)

         _mm_storeu_si128(reinterpret_cast<__m128i*>(out), raw());

#elif defined(BOTAN_SIMD_USE_ALTIVEC)

         union {
               __vector unsigned int V;
               uint32_t R[4];
         } vec;

         vec.V = raw();
         Botan::store_le(out, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);

#elif defined(BOTAN_SIMD_USE_NEON)
         if constexpr(std::endian::native == std::endian::little) {
            vst1q_u8(out, vreinterpretq_u8_u32(m_simd));
         } else {
            vst1q_u8(out, vreinterpretq_u8_u32(bswap().m_simd));
         }
#endif
      }

      /**
      * Load a SIMD register with big-endian convention
      */
      void store_be(uint8_t out[]) const noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)

         bswap().store_le(out);

#elif defined(BOTAN_SIMD_USE_ALTIVEC)

         union {
               __vector unsigned int V;
               uint32_t R[4];
         } vec;

         vec.V = m_simd;
         Botan::store_be(out, vec.R[0], vec.R[1], vec.R[2], vec.R[3]);

#elif defined(BOTAN_SIMD_USE_NEON)
         if constexpr(std::endian::native == std::endian::little) {
            vst1q_u8(out, vreinterpretq_u8_u32(bswap().m_simd));
         } else {
            vst1q_u8(out, vreinterpretq_u8_u32(m_simd));
         }
#endif
      }

      void store_be(std::span<uint8_t, 16> out) const { this->store_be(out.data()); }

      void store_le(std::span<uint8_t, 16> out) const { this->store_le(out.data()); }

      /*
      * This is used for SHA-2/SHACAL2
      */
      SIMD_4x32 sigma0() const noexcept {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_crypto_vshasigmaw) && defined(_ARCH_PWR8)
         return SIMD_4x32(__builtin_crypto_vshasigmaw(raw(), 1, 0));
#else
         const SIMD_4x32 rot1 = this->rotr<2>();
         const SIMD_4x32 rot2 = this->rotr<13>();
         const SIMD_4x32 rot3 = this->rotr<22>();
         return (rot1 ^ rot2 ^ rot3);
#endif
      }

      /*
      * This is used for SHA-2/SHACAL2
      */
      SIMD_4x32 sigma1() const noexcept {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_crypto_vshasigmaw) && defined(_ARCH_PWR8)
         return SIMD_4x32(__builtin_crypto_vshasigmaw(raw(), 1, 0xF));
#else
         const SIMD_4x32 rot1 = this->rotr<6>();
         const SIMD_4x32 rot2 = this->rotr<11>();
         const SIMD_4x32 rot3 = this->rotr<25>();
         return (rot1 ^ rot2 ^ rot3);
#endif
      }

      /**
      * Left rotation by a compile time constant
      */
      template <size_t ROT>
      SIMD_4x32 rotl() const noexcept
         requires(ROT > 0 && ROT < 32)
      {
#if defined(BOTAN_SIMD_USE_SSE2)

         return SIMD_4x32(_mm_or_si128(_mm_slli_epi32(m_simd, static_cast<int>(ROT)),
                                       _mm_srli_epi32(m_simd, static_cast<int>(32 - ROT))));

#elif defined(BOTAN_SIMD_USE_ALTIVEC)

         const unsigned int r = static_cast<unsigned int>(ROT);
         __vector unsigned int rot = {r, r, r, r};
         return SIMD_4x32(vec_rl(m_simd, rot));

#elif defined(BOTAN_SIMD_USE_NEON)

   #if defined(BOTAN_TARGET_ARCH_IS_ARM64)

         if constexpr(ROT == 8) {
            const uint8_t maskb[16] = {3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14};
            const uint8x16_t mask = vld1q_u8(maskb);
            return SIMD_4x32(vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(m_simd), mask)));
         } else if constexpr(ROT == 16) {
            return SIMD_4x32(vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(m_simd))));
         }
   #endif
         return SIMD_4x32(
            vorrq_u32(vshlq_n_u32(m_simd, static_cast<int>(ROT)), vshrq_n_u32(m_simd, static_cast<int>(32 - ROT))));
#endif
      }

      /**
      * Right rotation by a compile time constant
      */
      template <size_t ROT>
      SIMD_4x32 rotr() const noexcept {
         return this->rotl<32 - ROT>();
      }

      /**
      * Add elements of a SIMD vector
      */
      SIMD_4x32 operator+(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval += other;
         return retval;
      }

      /**
      * Subtract elements of a SIMD vector
      */
      SIMD_4x32 operator-(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval -= other;
         return retval;
      }

      /**
      * XOR elements of a SIMD vector
      */
      SIMD_4x32 operator^(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval ^= other;
         return retval;
      }

      /**
      * Binary OR elements of a SIMD vector
      */
      SIMD_4x32 operator|(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval |= other;
         return retval;
      }

      /**
      * Binary AND elements of a SIMD vector
      */
      SIMD_4x32 operator&(const SIMD_4x32& other) const noexcept {
         SIMD_4x32 retval(*this);
         retval &= other;
         return retval;
      }

      void operator+=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         m_simd = _mm_add_epi32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_add(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vaddq_u32(m_simd, other.m_simd);
#endif
      }

      void operator-=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         m_simd = _mm_sub_epi32(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_sub(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vsubq_u32(m_simd, other.m_simd);
#endif
      }

      void operator^=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         m_simd = _mm_xor_si128(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_xor(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = veorq_u32(m_simd, other.m_simd);
#endif
      }

      void operator^=(uint32_t other) noexcept { *this ^= SIMD_4x32::splat(other); }

      void operator|=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         m_simd = _mm_or_si128(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_or(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vorrq_u32(m_simd, other.m_simd);
#endif
      }

      void operator&=(const SIMD_4x32& other) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         m_simd = _mm_and_si128(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         m_simd = vec_and(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_NEON)
         m_simd = vandq_u32(m_simd, other.m_simd);
#endif
      }

      template <int SHIFT>
      SIMD_4x32 shl() const noexcept
         requires(SHIFT > 0 && SHIFT < 32)
      {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_slli_epi32(m_simd, SHIFT));

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const unsigned int s = static_cast<unsigned int>(SHIFT);
         const __vector unsigned int shifts = {s, s, s, s};
         return SIMD_4x32(vec_sl(m_simd, shifts));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vshlq_n_u32(m_simd, SHIFT));
#endif
      }

      template <int SHIFT>
      SIMD_4x32 shr() const noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_srli_epi32(m_simd, SHIFT));

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const unsigned int s = static_cast<unsigned int>(SHIFT);
         const __vector unsigned int shifts = {s, s, s, s};
         return SIMD_4x32(vec_sr(m_simd, shifts));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vshrq_n_u32(m_simd, SHIFT));
#endif
      }

      SIMD_4x32 operator~() const noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_xor_si128(m_simd, _mm_set1_epi32(0xFFFFFFFF)));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         return SIMD_4x32(vec_nor(m_simd, m_simd));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vmvnq_u32(m_simd));
#endif
      }

      // (~reg) & other
      SIMD_4x32 andc(const SIMD_4x32& other) const noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_andnot_si128(m_simd, other.m_simd));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         /*
         AltiVec does arg1 & ~arg2 rather than SSE's ~arg1 & arg2
         so swap the arguments
         */
         return SIMD_4x32(vec_andc(other.m_simd, m_simd));
#elif defined(BOTAN_SIMD_USE_NEON)
         // NEON is also a & ~b
         return SIMD_4x32(vbicq_u32(other.m_simd, m_simd));
#endif
      }

      /**
      * Return copy *this with each word byte swapped
      */
      SIMD_4x32 bswap() const noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)

         __m128i T = m_simd;
         T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
         T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
         return SIMD_4x32(_mm_or_si128(_mm_srli_epi16(T, 8), _mm_slli_epi16(T, 8)));

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
   #ifdef BOTAN_SIMD_USE_VSX
         return SIMD_4x32(vec_revb(m_simd));
   #else
         const __vector unsigned char rev[1] = {
            {3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12},
         };

         return SIMD_4x32(vec_perm(m_simd, m_simd, rev[0]));
   #endif

#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(m_simd))));
#endif
      }

      template <size_t I>
      SIMD_4x32 shift_elems_left() const noexcept
         requires(I <= 3)
      {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_slli_si128(raw(), 4 * I));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vextq_u32(vdupq_n_u32(0), raw(), 4 - I));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned int zero = vec_splat_u32(0);

         const __vector unsigned char shuf[3] = {
            {16, 17, 18, 19, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
            {16, 17, 18, 19, 20, 21, 22, 23, 0, 1, 2, 3, 4, 5, 6, 7},
            {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 0, 1, 2, 3},
         };

         return SIMD_4x32(vec_perm(raw(), zero, shuf[I - 1]));
#endif
      }

      template <size_t I>
      SIMD_4x32 shift_elems_right() const noexcept
         requires(I <= 3)
      {
#if defined(BOTAN_SIMD_USE_SSE2)
         return SIMD_4x32(_mm_srli_si128(raw(), 4 * I));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vextq_u32(raw(), vdupq_n_u32(0), I));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned int zero = vec_splat_u32(0);

         const __vector unsigned char shuf[3] = {
            {4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
            {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
            {12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27},
         };

         return SIMD_4x32(vec_perm(raw(), zero, shuf[I - 1]));
#endif
      }

      /**
      * 4x4 Transposition on SIMD registers
      */
      static void transpose(SIMD_4x32& B0, SIMD_4x32& B1, SIMD_4x32& B2, SIMD_4x32& B3) noexcept {
#if defined(BOTAN_SIMD_USE_SSE2)
         const __m128i T0 = _mm_unpacklo_epi32(B0.m_simd, B1.m_simd);
         const __m128i T1 = _mm_unpacklo_epi32(B2.m_simd, B3.m_simd);
         const __m128i T2 = _mm_unpackhi_epi32(B0.m_simd, B1.m_simd);
         const __m128i T3 = _mm_unpackhi_epi32(B2.m_simd, B3.m_simd);

         B0.m_simd = _mm_unpacklo_epi64(T0, T1);
         B1.m_simd = _mm_unpackhi_epi64(T0, T1);
         B2.m_simd = _mm_unpacklo_epi64(T2, T3);
         B3.m_simd = _mm_unpackhi_epi64(T2, T3);
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
         const __vector unsigned int T0 = vec_mergeh(B0.m_simd, B2.m_simd);
         const __vector unsigned int T1 = vec_mergeh(B1.m_simd, B3.m_simd);
         const __vector unsigned int T2 = vec_mergel(B0.m_simd, B2.m_simd);
         const __vector unsigned int T3 = vec_mergel(B1.m_simd, B3.m_simd);

         B0.m_simd = vec_mergeh(T0, T1);
         B1.m_simd = vec_mergel(T0, T1);
         B2.m_simd = vec_mergeh(T2, T3);
         B3.m_simd = vec_mergel(T2, T3);

#elif defined(BOTAN_SIMD_USE_NEON) && defined(BOTAN_TARGET_ARCH_IS_ARM32)
         const uint32x4x2_t T0 = vzipq_u32(B0.m_simd, B2.m_simd);
         const uint32x4x2_t T1 = vzipq_u32(B1.m_simd, B3.m_simd);
         const uint32x4x2_t O0 = vzipq_u32(T0.val[0], T1.val[0]);
         const uint32x4x2_t O1 = vzipq_u32(T0.val[1], T1.val[1]);

         B0.m_simd = O0.val[0];
         B1.m_simd = O0.val[1];
         B2.m_simd = O1.val[0];
         B3.m_simd = O1.val[1];

#elif defined(BOTAN_SIMD_USE_NEON) && defined(BOTAN_TARGET_ARCH_IS_ARM64)
         const uint32x4_t T0 = vzip1q_u32(B0.m_simd, B2.m_simd);
         const uint32x4_t T2 = vzip2q_u32(B0.m_simd, B2.m_simd);
         const uint32x4_t T1 = vzip1q_u32(B1.m_simd, B3.m_simd);
         const uint32x4_t T3 = vzip2q_u32(B1.m_simd, B3.m_simd);

         B0.m_simd = vzip1q_u32(T0, T1);
         B1.m_simd = vzip2q_u32(T0, T1);
         B2.m_simd = vzip1q_u32(T2, T3);
         B3.m_simd = vzip2q_u32(T2, T3);
#endif
      }

      static inline SIMD_4x32 choose(const SIMD_4x32& mask, const SIMD_4x32& a, const SIMD_4x32& b) noexcept {
#if defined(BOTAN_SIMD_USE_ALTIVEC)
         return SIMD_4x32(vec_sel(b.raw(), a.raw(), mask.raw()));
#elif defined(BOTAN_SIMD_USE_NEON)
         return SIMD_4x32(vbslq_u32(mask.raw(), a.raw(), b.raw()));
#else
         return (mask & a) ^ mask.andc(b);
#endif
      }

      static inline SIMD_4x32 majority(const SIMD_4x32& x, const SIMD_4x32& y, const SIMD_4x32& z) noexcept {
         return SIMD_4x32::choose(x ^ y, z, y);
      }

      native_simd_type raw() const noexcept { return m_simd; }

      explicit SIMD_4x32(native_simd_type x) noexcept : m_simd(x) {}

   private:
      native_simd_type m_simd;
};

template <size_t R>
inline SIMD_4x32 rotl(SIMD_4x32 input) {
   return input.rotl<R>();
}

template <size_t R>
inline SIMD_4x32 rotr(SIMD_4x32 input) {
   return input.rotr<R>();
}

// For Serpent:
template <size_t S>
inline SIMD_4x32 shl(SIMD_4x32 input) {
   return input.shl<S>();
}

}  // namespace Botan

#endif
