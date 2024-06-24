/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_nist.h>
#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

template <typename Params>
class Secp256r1Rep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      // Adds 4 * P-256 to prevent underflow
      static constexpr auto P256_4 =
         hex_to_words<uint32_t>("0x3fffffffc00000004000000000000000000000003fffffffffffffffffffffffc");

      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         const auto X = into_32bit_words<16>(z);
         auto [r, S] =
            accumulate_with_carry<W, N>({P256_4[0] + X[0] + X[8] + X[9] - (X[11] + X[12] + X[13] + X[14]),
                                         P256_4[1] + X[1] + X[9] + X[10] - (X[12] + X[13] + X[14] + X[15]),
                                         P256_4[2] + X[2] + X[10] + X[11] - (X[13] + X[14] + X[15]),
                                         P256_4[3] + X[3] + 2 * (X[11] + X[12]) + X[13] - (X[15] + X[8] + X[9]),
                                         P256_4[4] + X[4] + 2 * (X[12] + X[13]) + X[14] - (X[9] + X[10]),
                                         P256_4[5] + X[5] + 2 * (X[13] + X[14]) + X[15] - (X[10] + X[11]),
                                         P256_4[6] + X[6] + X[13] + X[14] * 3 + X[15] * 2 - (X[8] + X[9]),
                                         P256_4[7] + X[7] + X[15] * 3 + X[8] - (X[10] + X[11] + X[12] + X[13]),
                                         P256_4[8]});

         CT::unpoison(S);
         BOTAN_ASSERT(S <= 8, "Expected overflow");

         const auto correction = p256_mul_mod_256(S);
         W borrow = bigint_sub2(r.data(), N, correction.data(), N);

         bigint_cnd_add(borrow, r.data(), N, P.data(), N);

         return r;
      }

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }

   private:
      // Return (i*P-256) % 2**256
      //
      // Assumes i is small
      constexpr static std::array<W, N> p256_mul_mod_256(W i) {
         static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

         // For small i, multiples of P-256 have a simple structure so it's faster to
         // compute the value directly vs a (constant time) table lookup

         auto r = P;
         if constexpr(WordInfo<W>::bits == 32) {
            r[7] -= i;
            r[6] += i;
            r[3] += i;
            r[0] -= i;
         } else {
            const uint64_t i32 = static_cast<uint64_t>(i) << 32;
            r[3] -= i32;
            r[3] += i;
            r[1] += i32;
            r[0] -= i;
         }
         return r;
      }
};

namespace secp256r1 {

// clang-format off
class Params final : public EllipticCurveParameters<
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
   "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
   "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
   "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
   "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
   -10> {
};

// clang-format on

#if BOTAN_MP_WORD_BITS == 32
// Secp256r1Rep works for 64 bit also, but is at best marginally faster at least
// on compilers/CPUs tested so far
class Curve final : public EllipticCurve<Params, Secp256r1Rep> {};
#else
class Curve final : public EllipticCurve<Params> {};
#endif

}  // namespace secp256r1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp256r1() {
   return PrimeOrderCurveImpl<secp256r1::Curve>::instance();
}

}  // namespace Botan::PCurve
