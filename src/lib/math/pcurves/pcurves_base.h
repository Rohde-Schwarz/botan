/*
* (C) 2024,2025 Jack Lloyd
* (C) 2025 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_BASE_H_
#define BOTAN_PCURVES_BASE_H_

#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>

#include <span>

namespace Botan {

namespace detail {

struct MaybeDynamicExtent {
      size_t x;

      consteval MaybeDynamicExtent operator+(MaybeDynamicExtent o) const {
         return {(x == std::dynamic_extent || o == std::dynamic_extent) ? std::dynamic_extent : (o + x)};
      }

      consteval MaybeDynamicExtent operator*(MaybeDynamicExtent o) const {
         return {(x == std::dynamic_extent || o == std::dynamic_extent) ? std::dynamic_extent : (o * x)};
      }

      consteval operator size_t() const { return x; }
};

}  // namespace detail

consteval detail::MaybeDynamicExtent operator""_dynext(unsigned long long int x) {
   return {static_cast<size_t>(x)};
}

template <typename AffinePointT, typename FieldElementT, detail::MaybeDynamicExtent fe_bytes>
class AffineBaseCurvePoint {
   public:
      static constexpr size_t COMPRESSED_BYTES = 1_dynext + fe_bytes;
      static constexpr size_t BYTES = 1_dynext + 2_dynext * fe_bytes;

   public:
      ~AffineBaseCurvePoint() = default;
      AffineBaseCurvePoint(const AffineBaseCurvePoint& other) = default;
      AffineBaseCurvePoint(AffineBaseCurvePoint&& other) = default;
      AffineBaseCurvePoint& operator=(const AffineBaseCurvePoint& other) = default;
      AffineBaseCurvePoint& operator=(AffineBaseCurvePoint&& other) = default;

      constexpr AffineBaseCurvePoint(const FieldElementT& x, const FieldElementT& y) : m_x(x), m_y(y) {}

      constexpr CT::Choice is_identity() const { return x().is_zero() && y().is_zero(); }

      constexpr AffinePointT negate() const { return AffinePointT(x(), y().negate()); }

      /**
      * Serialize the point in uncompressed format
      */
      constexpr void serialize_to(std::span<uint8_t, BYTES> bytes) const {
         BOTAN_ARG_CHECK(bytes.size() == 1 + x().bytes() + y().bytes(), "Buffer size incorrect");
         BOTAN_STATE_CHECK(this->is_identity().as_bool() == false);
         BufferStuffer pack(bytes);
         pack.append(0x04);
         this->x().serialize_to(pack.next<fe_bytes>(x().bytes()));
         this->y().serialize_to(pack.next<fe_bytes>(y().bytes()));
         BOTAN_DEBUG_ASSERT(pack.full());
      }

      /**
      * Serialize the point in compressed format
      */
      constexpr void serialize_compressed_to(std::span<uint8_t, COMPRESSED_BYTES> bytes) const {
         BOTAN_ARG_CHECK(bytes.size() == 1 + x().bytes(), "Buffer size incorrect");
         BOTAN_STATE_CHECK(this->is_identity().as_bool() == false);
         const uint8_t hdr = CT::Mask<uint8_t>::from_choice(this->y().is_even()).select(0x02, 0x03);

         BufferStuffer pack(bytes);
         pack.append(hdr);
         this->x().serialize_to(pack.next<fe_bytes>(x().bytes()));
         BOTAN_DEBUG_ASSERT(pack.full());
      }

      /**
      * Serialize the affine x coordinate only
      */
      constexpr void serialize_x_to(std::span<uint8_t, fe_bytes> bytes) const {
         BOTAN_STATE_CHECK(this->is_identity().as_bool() == false);
         x().serialize_to(bytes);
      }

      constexpr const FieldElementT& x() const { return m_x; }

      constexpr const FieldElementT& y() const { return m_y; }

      void conditional_assign(CT::Choice cond, const AffinePointT& pt) {
         FieldElementT::conditional_assign(m_x, m_y, cond, pt.x(), pt.y());
      }

      constexpr void _const_time_poison() const { CT::poison_all(m_x, m_y); }

      constexpr void _const_time_unpoison() const { CT::unpoison_all(m_x, m_y); }

   protected:
      /**
      * If idx is zero then return the identity element. Otherwise return pts[idx - 1]
      *
      * Returns the identity element also if idx is out of range
      */
      static auto ct_select_impl(AffinePointT identity, std::span<const AffinePointT> pts, size_t idx) {
         BOTAN_ARG_CHECK(!pts.empty(), "Cannot select from an empty set");
         auto& result = identity;

         // Intentionally wrapping; set to maximum size_t if idx == 0
         const size_t idx1 = static_cast<size_t>(idx - 1);
         for(size_t i = 0; i != pts.size(); ++i) {
            const auto found = CT::Mask<size_t>::is_equal(idx1, i).as_choice();
            result.conditional_assign(found, pts[i]);
         }

         return result;
      }

      /**
      * Point deserialization
      *
      * This accepts compressed or uncompressed formats.
      *
      * It also currently accepts the deprecated hybrid format.
      * TODO(Botan4): remove support for decoding hybrid points
      */
      template <std::invocable<> IdFn, std::invocable<std::span<const uint8_t>> ReadFn>
         requires(std::same_as<std::invoke_result_t<IdFn>, AffinePointT> &&
                  std::same_as<std::invoke_result_t<ReadFn, std::span<const uint8_t>>, std::optional<FieldElementT>>)
      static std::optional<AffinePointT> deserialize_impl(IdFn identity,
                                                          ReadFn deserialize_fe,
                                                          size_t dyn_fe_bytes,
                                                          std::span<const uint8_t> bytes) {
         if(bytes.empty()) {
            return {};
         }

         BufferSlicer slicer(bytes);
         const auto hdr = slicer.take_byte();

         if(slicer.remaining() == 2 * dyn_fe_bytes) {
            if(hdr == 0x04) {
               auto x = deserialize_fe(slicer.take(dyn_fe_bytes));
               auto y = deserialize_fe(slicer.take(dyn_fe_bytes));

               if(x && y) {
                  const auto lhs = (*y).square();
                  const auto rhs = AffinePointT::x3_ax_b(*x);
                  if((lhs == rhs).as_bool()) {
                     return AffinePointT(*x, *y);
                  }
               }
            } else if(hdr == 0x06 || hdr == 0x07) {
               // Deprecated "hybrid" encoding
               const CT::Choice y_is_even = CT::Mask<uint8_t>::is_equal(hdr, 0x06).as_choice();
               auto x = deserialize_fe(slicer.take(dyn_fe_bytes));
               auto y = deserialize_fe(slicer.take(dyn_fe_bytes));

               if(x && y && (y_is_even == y->is_even()).as_bool()) {
                  const auto lhs = (*y).square();
                  const auto rhs = AffinePointT::x3_ax_b(*x);
                  if((lhs == rhs).as_bool()) {
                     return AffinePointT(*x, *y);
                  }
               }
            }
         } else if(slicer.remaining() == dyn_fe_bytes) {
            if(hdr == 0x02 || hdr == 0x03) {
               const CT::Choice y_is_even = CT::Mask<uint8_t>::is_equal(hdr, 0x02).as_choice();

               if(auto x = deserialize_fe(slicer.take(dyn_fe_bytes))) {
                  auto [y, is_square] = AffinePointT::x3_ax_b(*x).sqrt();

                  if(is_square.as_bool()) {
                     const auto flip_y = y_is_even != y.is_even();
                     FieldElementT::conditional_assign(y, flip_y, y.negate());
                     return AffinePointT(*x, y);
                  }
               }
            }
         } else if(hdr == 0x00 && slicer.empty()) {
            // See SEC1 section 2.3.4
            return identity();
         }

         return {};
      }

   private:
      FieldElementT m_x;
      FieldElementT m_y;
};

}  // namespace Botan

#endif
