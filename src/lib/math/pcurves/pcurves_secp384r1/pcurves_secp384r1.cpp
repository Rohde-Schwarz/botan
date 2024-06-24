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
class Secp384r1Rep final {
   public:
      static constexpr auto P = Params::P;
      static constexpr size_t N = Params::N;
      typedef typename Params::W W;

      constexpr static std::array<W, N> redc(const std::array<W, 2 * N>& z) {
         const auto X = into_32bit_words<24>(z);
         const auto P384 = into_32bit_words<12>(Params::P);

         // One copy of P-384 is added to prevent underflow
         auto [r, S] = accumulate_with_carry<W, N>(
            {P384[0] + X[0] + X[12] + X[20] + X[21] - X[23],
             P384[1] + X[1] + X[13] + X[22] + X[23] - X[12] - X[20],
             P384[2] + X[2] + X[14] + X[23] - X[13] - X[21],
             P384[3] + X[3] + X[12] + X[15] + X[20] + X[21] - X[14] - X[22] - X[23],
             P384[4] + X[4] + X[12] + X[13] + X[16] + X[20] + X[21] * 2 + X[22] - X[15] - X[23] * 2,
             P384[5] + X[5] + X[13] + X[14] + X[17] + X[21] + X[22] * 2 + X[23] - X[16],
             P384[6] + X[6] + X[14] + X[15] + X[18] + X[22] + X[23] * 2 - X[17],
             P384[7] + X[7] + X[15] + X[16] + X[19] + X[23] - X[18],
             P384[8] + X[8] + X[16] + X[17] + X[20] - X[19],
             P384[9] + X[9] + X[17] + X[18] + X[21] - X[20],
             P384[10] + X[10] + X[18] + X[19] + X[22] - X[21],
             P384[11] + X[11] + X[19] + X[20] + X[23] - X[22],
             0});

         CT::unpoison(S);
         BOTAN_ASSERT(S <= 4, "Expected overflow");

         const auto correction = p384_mul_mod_384(S);
         W borrow = bigint_sub2(r.data(), N, correction.data(), N);

         bigint_cnd_add(borrow, r.data(), N, P.data(), N);

         return r;
      }

      constexpr static std::array<W, N> one() { return std::array<W, N>{1}; }

      constexpr static std::array<W, N> to_rep(const std::array<W, N>& x) { return x; }

      constexpr static std::array<W, N> wide_to_rep(const std::array<W, 2 * N>& x) { return redc(x); }

      constexpr static std::array<W, N> from_rep(const std::array<W, N>& z) { return z; }

   private:
      // Return (i*P-384) % 2**384
      //
      // Assumes i is small
      constexpr static std::array<W, N> p384_mul_mod_384(W i) {
         static_assert(WordInfo<W>::bits == 32 || WordInfo<W>::bits == 64);

         // For small i, multiples of P-384 have a simple structure so it's faster to
         // compute the value directly vs a (constant time) table lookup

         auto r = P;
         if constexpr(WordInfo<W>::bits == 32) {
            r[4] -= i;
            r[3] -= i;
            r[1] += i;
            r[0] -= i;
         } else {
            const uint64_t i32 = static_cast<uint64_t>(i) << 32;
            r[2] -= i;
            r[1] -= i32;
            r[0] += i32;
            r[0] -= i;
         }
         return r;
      }
};

// clang-format off
namespace secp384r1 {

class Params final : public EllipticCurveParameters<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
   "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
   "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
   "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
   -12> {
};

class Curve final : public EllipticCurve<Params, Secp384r1Rep> {};

}

// clang-format on

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp384r1() {
   return PrimeOrderCurveImpl<secp384r1::Curve>::instance();
}

}  // namespace Botan::PCurve
