/*
 * An abstraction for an arbitrarily large bitvector that can
 * optionally use the secure_allocator.
 *
 * (C) 2023 Jack Lloyd
 * (C) 2023 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_BIT_VECTOR_H_
#define BOTAN_BIT_VECTOR_H_

#include <botan/concepts.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/secmem.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>

#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Botan {

namespace detail {

template <typename OutT, typename>
using as = OutT;

template <typename FnT, typename BlockT, typename... ParamTs>
concept blockwise_processing_callback_return_type =
   std::unsigned_integral<BlockT> && (std::same_as<BlockT, std::invoke_result_t<FnT, as<BlockT, ParamTs>...>> ||
                                      std::same_as<bool, std::invoke_result_t<FnT, as<BlockT, ParamTs>...>> ||
                                      std::same_as<void, std::invoke_result_t<FnT, as<BlockT, ParamTs>...>>);

template <typename FnT, typename... ParamTs>
concept blockwise_processing_callback_without_mask =
   blockwise_processing_callback_return_type<FnT, uint8_t, ParamTs...> &&
   blockwise_processing_callback_return_type<FnT, uint16_t, ParamTs...> &&
   blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs...> &&
   blockwise_processing_callback_return_type<FnT, uint64_t, ParamTs...>;

template <typename FnT, typename... ParamTs>
concept blockwise_processing_callback_with_mask =
   blockwise_processing_callback_return_type<FnT, uint8_t, ParamTs..., uint8_t /* mask */> &&
   blockwise_processing_callback_return_type<FnT, uint16_t, ParamTs..., uint16_t /* mask */> &&
   blockwise_processing_callback_return_type<FnT, uint32_t, ParamTs..., uint32_t /* mask */> &&
   blockwise_processing_callback_return_type<FnT, uint64_t, ParamTs..., uint64_t /* mask */>;

/**
 * Defines the callback constraints for the BitRangeOperator. For further
 * details, see bitvector_base::range_operation().
 */
template <typename FnT, typename... ParamTs>
concept blockwise_processing_callback = blockwise_processing_callback_with_mask<FnT, ParamTs...> ||
                                        blockwise_processing_callback_without_mask<FnT, ParamTs...>;

}  // namespace detail

/**
 * An arbitrarily large bitvector with typical bit manipulation and convenient
 * bitwise access methods. Don't use `bitvector_base` directly, but the type
 * aliases::
 *
 *    * bitvector         - with a standard allocator
 *    * secure_bitvector  - with a secure allocator that auto-scrubs the memory
 */
template <template <typename> typename AllocatorT>
class bitvector_base final {
   public:
      using block_type = uint8_t;
      using size_type = size_t;
      using allocator_type = AllocatorT<block_type>;

      static constexpr size_type block_size_bytes = sizeof(block_type);
      static constexpr size_type block_size_bits = block_size_bytes * 8;
      static constexpr bool uses_secure_allocator = std::is_same_v<allocator_type, secure_allocator<block_type>>;

   private:
      template <template <typename> typename FriendAllocatorT>
      friend class bitvector_base;

      static constexpr block_type one = block_type(1);

      static constexpr size_type block_offset_shift = size_type(3) + ceil_log2(block_size_bytes);
      static constexpr size_type block_index_mask = (one << block_offset_shift) - 1;

      static constexpr size_type block_index(size_type pos) { return pos >> block_offset_shift; }

      static constexpr size_type block_offset(size_type pos) { return pos & block_index_mask; }

   private:
      /**
       * Internal helper to wrap a single bit in the bitvector and provide
       * certain convenience access methods.
       */
      template <typename BlockT>
         requires std::same_as<block_type, std::remove_cv_t<BlockT>>
      class bitref_base {
         private:
            friend class bitvector_base<AllocatorT>;

            constexpr bitref_base(std::span<BlockT> blocks, size_type pos) :
                  m_block(blocks[block_index(pos)]), m_mask(one << block_offset(pos)) {}

         public:
            bitref_base() = delete;
            bitref_base(const bitref_base&) noexcept = default;
            bitref_base(bitref_base&&) noexcept = default;
            bitref_base& operator=(const bitref_base&) = delete;
            bitref_base& operator=(bitref_base&&) = delete;

            ~bitref_base() = default;

         public:
            constexpr operator bool() const noexcept { return is_set(); }

            constexpr bool is_set() const noexcept { return (m_block & m_mask) > 0; }

         protected:
            BlockT& m_block;   // NOLINT(*-non-private-member-variables-in-classes)
            size_type m_mask;  // NOLINT(*-non-private-member-variables-in-classes)
      };

   public:
      /**
       * Wraps a constant reference into the bitvector. Bit can be accessed
       * but not modified.
       */
      template <typename BlockT>
      class bitref final : public bitref_base<BlockT> {
         public:
            using bitref_base<BlockT>::bitref_base;
      };

      /**
       * Wraps a modifiable reference into the bitvector. Bit may be accessed
       * and modified (e.g. flipped or XOR'ed).
       */
      template <typename BlockT>
         requires(!std::is_const_v<BlockT>)
      class bitref<BlockT> : public bitref_base<BlockT> {
         public:
            using bitref_base<BlockT>::bitref_base;

            ~bitref() = default;
            bitref(const bitref&) noexcept = default;
            bitref(bitref&&) noexcept = default;

            constexpr bitref& set() noexcept {
               this->m_block |= this->m_mask;
               return *this;
            }

            constexpr bitref& unset() noexcept {
               this->m_block &= ~this->m_mask;
               return *this;
            }

            constexpr bitref& flip() noexcept {
               this->m_block ^= this->m_mask;
               return *this;
            }

            // NOLINTBEGIN

            constexpr bitref& operator=(bool bit) noexcept { return assign(bit); }

            constexpr bitref& operator=(const bitref& bit) noexcept { return assign(bit); }

            constexpr bitref& operator=(bitref&& bit) noexcept { return assign(bit); }

            // NOLINTEND

            constexpr bitref& operator&=(bool other) noexcept { return assign(this->is_set() && other); }

            constexpr bitref& operator|=(bool other) noexcept { return assign(this->is_set() || other); }

            constexpr bitref& operator^=(bool other) noexcept { return assign(this->is_set() ^ other); }

         private:
            constexpr bitref& assign(bool bit) noexcept { return (bit) ? set() : unset(); }
      };

   public:
      bitvector_base() : m_bits(0) {}

      bitvector_base(size_type bits) : m_bits(bits), m_blocks(ceil_toblocks(bits)) {}

      /**
       * Initialize the bitvector from a byte-array. Bits are taken byte-wise
       * from least significant to most significant. Example::
       *
       *    bitvector[0] -> LSB(Byte[0])
       *    bitvector[1] -> LSB+1(Byte[0])
       *    ...
       *    bitvector[8] -> LSB(Byte[1])
       *
       * @param bytes The byte vector to be loaded
       * @param bits  The number of bits to be loaded. This must not be more
       *              than the number of bytes in @p bytes.
       */
      bitvector_base(std::span<const uint8_t> bytes, std::optional<size_type> bits = std::nullopt) {
         from_bytes(bytes, bits);
      }

      bool empty() const { return m_bits == 0; }

      size_type size() const { return m_bits; }

      /**
       * @returns true iff the number of 1-bits in this is odd, false otherwise
       */
      bool has_odd_hamming_weight() const {
         uint64_t acc = 0;
         full_range_operation([&](std::unsigned_integral auto block) { acc ^= block; }, *this);

         for(size_t i = (sizeof(acc) * 8) >> 1; i > 0; i >>= 1) {
            acc ^= acc >> i;
         }

         acc &= one;

         return acc == 1;
      }

      /**
       * @returns a copy of this bitvector as a secure_bitvector
       */
      auto as_locked() const { return subvector<secure_allocator>(0, size()); }

      /**
       * @returns a copy of this bitvector as a standard-allocated bitvector
       */
      auto as_unlocked() const { return subvector<std::allocator>(0, size()); }

      /**
       * @returns true if @p other contains the same bit pattern as this
       */
      template <template <typename> typename OtherAllocatorT>
      bool equals(const bitvector_base<OtherAllocatorT>& other) const noexcept {
         return size() == other.size() &&
                full_range_operation(
                   []<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) { return lhs == rhs; }, *this, other);
      }

      /// @name Serialization
      /// @{

      /**
       * Re-initialize the bitvector with the given bytes. See the respective
       * constructor for details. This should be used only when trying to save
       * allocations. Otherwise, use the constructor.
       *
       * @param bytes  the byte range to load bits from
       * @param bits   (optional) if not all @p bytes should be loaded in full
       */
      void from_bytes(std::span<const uint8_t> bytes, std::optional<size_type> bits = std::nullopt) {
         m_bits = bits.value_or(bytes.size_bytes() * 8);
         BOTAN_ARG_CHECK(m_bits <= bytes.size_bytes() * 8, "not enough data to load so many bits");
         resize(m_bits);

         // load as much aligned data as possible
         const auto verbatim_blocks = m_bits / block_size_bits;
         const auto verbatim_bytes = verbatim_blocks * block_size_bytes;
         typecast_copy(std::span{m_blocks}.first(verbatim_blocks), bytes.first(verbatim_bytes));

         // load remaining unaligned data
         for(size_type i = verbatim_bytes * 8; i < m_bits; ++i) {
            ref(i) = ((bytes[i >> 3] & (uint8_t(1) << (i & 7))) != 0);
         }
      }

      /**
       * Renders the bitvector into a byte array. By default, this will use
       * `std::vector<uint8_t>` or `Botan::secure_vector<uint8_t>`, depending on
       * the allocator used by the bitvector. The rendering is compatible with
       * the bit layout explained in the respective constructor.
       */
      template <concepts::resizable_byte_buffer OutT =
                   std::conditional_t<uses_secure_allocator, secure_vector<uint8_t>, std::vector<uint8_t>>>
      OutT to_bytes() const {
         OutT out(ceil_tobytes(m_bits));
         to_bytes(out);
         return out;
      }

      /**
       * Renders the bitvector into a properly sized byte range.
       *
       * @param out  a byte range that has a length of at least `ceil_tobytes(size())`.
       */
      void to_bytes(std::span<uint8_t> out) const {
         const auto bytes_needed = ceil_tobytes(m_bits);
         BOTAN_ARG_CHECK(bytes_needed <= out.size_bytes(), "Not enough space to render bitvector");

         // copy as much aligned data as possible
         const auto verbatim_blocks = m_bits / block_size_bits;
         const auto verbatim_bytes = verbatim_blocks * block_size_bytes;
         typecast_copy(out.first(verbatim_bytes), std::span{m_blocks}.first(verbatim_blocks));

         // copy remaining unaligned data
         for(size_type i = verbatim_bytes * 8; i < m_bits; ++i) {
            out[i >> 3] |= static_cast<uint8_t>(ref(i)) << (i & 7);
         }
      }

      /**
       * Renders this bitvector into a sequence of "0"s and "1"s.
       */
      std::string to_string() const {
         // TODO: if we introduce iterators for the bitvector class
         //       we might be able to move this into a cpp file.
         std::stringstream ss;
         for(size_type i = 0; i < size(); ++i) {
            ss << ref(i);
         }
         return ss.str();
      }

      /// @}

      /// @name Capacity Accessors and Modifiers
      /// @{

      size_type capacity() const { return m_blocks.capacity() * block_size_bits; }

      void reserve(size_type bits) { m_blocks.reserve(ceil_toblocks(bits)); }

      void resize(size_type bits) {
         const auto new_number_of_blocks = ceil_toblocks(bits);
         if(new_number_of_blocks != m_blocks.size()) {
            m_blocks.resize(new_number_of_blocks);
         }

         m_bits = bits;
         zero_unused_bits();
      }

      void push_back(bool bit) {
         const auto i = size();
         resize(i + 1);
         ref(i) = bit;
      }

      void pop_back() {
         if(!empty()) {
            resize(size() - 1);
         }
      }

      /// @}

      /// @name Bitwise and Global Accessors and Modifiers
      /// @{

      auto at(size_type pos) {
         check_offset(pos);
         return ref(pos);
      }

      // TODO C++23: deducing this
      auto at(size_type pos) const {
         check_offset(pos);
         return ref(pos);
      }

      auto front() { return ref(0); }

      // TODO C++23: deducing this
      auto front() const { return ref(0); }

      auto back() { return ref(size() - 1); }

      // TODO C++23: deducing this
      auto back() const { return ref(size() - 1); }

      /**
       * Sets the bit at position @p pos.
       * @throws Botan::Invalid_Argument if @p pos is out of range
       */
      bitvector_base& set(size_type pos) {
         check_offset(pos);
         ref(pos).set();
         return *this;
      }

      /**
       * Sets all currently allocated bits.
       */
      bitvector_base& set() {
         full_range_operation([](std::unsigned_integral auto block) -> decltype(block) { return ~0; }, *this);
         zero_unused_bits();
         return *this;
      }

      /**
       * Unsets the bit at position @p pos.
       * @throws Botan::Invalid_Argument if @p pos is out of range
       */
      bitvector_base& unset(size_type pos) {
         check_offset(pos);
         ref(pos).unset();
         return *this;
      }

      /**
       * Unsets all currently allocated bits.
       */
      bitvector_base& unset() {
         full_range_operation([](std::unsigned_integral auto block) -> decltype(block) { return 0; }, *this);
         return *this;
      }

      /**
       * Flips the bit at position @p pos.
       * @throws Botan::Invalid_Argument if @p pos is out of range
       */
      bitvector_base& flip(size_type pos) {
         check_offset(pos);
         ref(pos).flip();
         return *this;
      }

      /**
       * Flips all currently allocated bits.
       */
      bitvector_base& flip() {
         full_range_operation([](std::unsigned_integral auto block) -> decltype(block) { return ~block; }, *this);
         zero_unused_bits();
         return *this;
      }

      /**
       * @returns true iff no bit is set
       */
      bool none() const {
         return full_range_operation([](std::unsigned_integral auto block) { return block == 0; }, *this);
      }

      /**
       * @returns true iff at least one bit is set
       */
      bool any() const { return !none(); }

      /**
       * @returns true iff all bits are set
       */
      bool all() const {
         return full_range_operation(
            []<std::unsigned_integral BlockT>(BlockT block, BlockT mask) { return block == mask; }, *this);
      }

      auto operator[](size_type pos) { return ref(pos); }

      // TODO C++23: deducing this
      bool operator[](size_type pos) const { return ref(pos); }

      /// @}

      /// @name Subvectors
      /// @{

      /**
       * Creates a new bitvector with a subsection of this bitvector starting at
       * @p pos copying exactly @p length bits.
       */
      template <template <typename> typename NewAllocatorT = AllocatorT>
      auto subvector(size_type pos, std::optional<size_type> length = std::nullopt) const {
         size_type bitlen = length.value_or(size() - pos);
         BOTAN_ARG_CHECK(pos + bitlen <= size(), "Not enough bits to copy");

         bitvector_base<NewAllocatorT> newvector(bitlen);

         if(bitlen > 0) {
            if(pos % 8 == 0) {
               copy_mem(
                  newvector.m_blocks,
                  std::span{m_blocks}.subspan(block_index(pos), block_index(pos + bitlen - 1) - block_index(pos) + 1));
            } else {
               BitRangeOperator<const bitvector_base<AllocatorT>, BitRangeAlignment::no_alignment> from_op(
                  *this, pos, bitlen);
               BitRangeOperator<bitvector_base<NewAllocatorT>> to_op(newvector, 0, bitlen);
               range_operation([](auto /* to */, auto from) { return from; }, to_op, from_op);
            }

            newvector.zero_unused_bits();
         }

         return newvector;
      }

      /// @}

      /// @name Operators
      ///
      /// @{

      auto operator~() {
         auto newbv = *this;
         newbv.flip();
         return newbv;
      }

      template <template <typename> typename OtherAllocatorT>
      auto& operator|=(const bitvector_base<OtherAllocatorT>& other) {
         full_range_operation(
            []<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) -> BlockT { return lhs | rhs; }, *this, other);
         return *this;
      }

      template <template <typename> typename OtherAllocatorT>
      auto& operator&=(const bitvector_base<OtherAllocatorT>& other) {
         full_range_operation(
            []<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) -> BlockT { return lhs & rhs; }, *this, other);
         return *this;
      }

      template <template <typename> typename OtherAllocatorT>
      auto& operator^=(const bitvector_base<OtherAllocatorT>& other) {
         full_range_operation(
            []<std::unsigned_integral BlockT>(BlockT lhs, BlockT rhs) -> BlockT { return lhs ^ rhs; }, *this, other);
         return *this;
      }

      /// @}

      /// @name Constant Time Operations
      ///
      /// @{

      /**
       * Implements::
       *
       *    if(condition) {
       *       *this ^= other;
       *    }
       *
       * omitting runtime dependence on any of the parameters.
       */
      template <template <typename> typename OtherAllocatorT>
      void ct_conditional_xor(bool condition, const bitvector_base<OtherAllocatorT>& other) {
         BOTAN_ASSERT_NOMSG(m_bits == other.m_bits);
         BOTAN_ASSERT_NOMSG(m_blocks.size() == other.m_blocks.size());

         // This is deliberately done without BitRangeOperator for simpler
         // reasoning about constant-time behaviour.
         const auto mask = CT::Mask<uint8_t>::expand(condition);
         for(size_type i = 0; i < m_blocks.size(); ++i) {
            m_blocks[i] ^= mask.if_set_return(other.m_blocks[i]);
         }
      }

      /// @}

   private:
      void check_offset(size_type pos) const { BOTAN_ARG_CHECK(pos < m_bits, "Out of range"); }

      void zero_unused_bits() {
         const auto first_unused_bit = size();

         // Zero out any unused bits in the last block
         if(first_unused_bit % block_size_bits != 0) {
            const block_type mask = (one << block_offset(first_unused_bit)) - one;
            m_blocks[block_index(first_unused_bit)] &= mask;
         }
      }

      static constexpr size_type ceil_toblocks(size_type bits) {
         return (bits + block_size_bits - 1) / block_size_bits;
      }

      auto ref(size_type pos) const { return bitref<const block_type>(m_blocks, pos); }

      auto ref(size_type pos) { return bitref<block_type>(m_blocks, pos); }

   private:
      enum class BitRangeAlignment { byte_aligned, no_alignment };

      /**
       * Helper construction to implement bit range operations on the bitvector.
       * It basically implements an iterator to read and write blocks of bits
       * from the underlying bitvector. Where "blocks of bits" are unsigned
       * integers of varying bit lengths.
       *
       * If the iteration starts at a byte boundary in the underlying bitvector,
       * this applies certain optimizations (i.e. loading blocks of bits straight
       * from the underlying byte buffer). The optimizations are enabled at
       * compile time (with the template parameter `alignment`).
       */
      template <typename BitvectorT, auto alignment = BitRangeAlignment::byte_aligned>
      class BitRangeOperator {
         private:
            constexpr static bool is_const() { return std::is_const_v<BitvectorT>; }

         public:
            BitRangeOperator(BitvectorT& source, size_type start_bitoffset, size_type bitlength) :
                  m_source(source),
                  m_start_bitoffset(start_bitoffset),
                  m_bitlength(bitlength),
                  m_read_bitpos(start_bitoffset),
                  m_write_bitpos(start_bitoffset) {
               BOTAN_ASSERT(is_byte_aligned() == (m_start_bitoffset % 8 == 0), "byte alignment guarantee");
               BOTAN_ASSERT(m_source.size() >= m_start_bitoffset + m_bitlength, "enough bytes in underlying source");
            }

            BitRangeOperator(BitvectorT& source) : BitRangeOperator(source, 0, source.size()) {}

            static constexpr bool is_byte_aligned() { return alignment == BitRangeAlignment::byte_aligned; }

            /**
             * @returns the overall number of bits to be iterated with this operator
             */
            size_type size() const { return m_bitlength; }

            /**
             * @returns the number of bits not yet read from this operator
             */
            size_type bits_to_read() const { return m_bitlength - m_read_bitpos + m_start_bitoffset; }

            /**
             * @returns the number of bits still to be written into this operator
             */
            size_type bits_to_write() const { return m_bitlength - m_write_bitpos + m_start_bitoffset; }

            /**
             * Loads the next block of bits from the underlying bitvector. No
             * bounds checks are performed. The caller can define the size of
             * the resulting unsigned integer block.
             */
            template <std::unsigned_integral BlockT>
            BlockT load_next() const {
               constexpr size_type block_size = sizeof(BlockT);
               const size_type byte_pos = m_read_bitpos / 8;
               BlockT result_block = 0;

               if constexpr(is_byte_aligned()) {
                  result_block = load_le(std::span{m_source.m_blocks}.subspan(byte_pos).template first<block_size>());
               } else {
                  constexpr size_type block_bits = block_size * 8;
                  const size_type bits_to_ignore_in_carry = m_start_bitoffset % 8;
                  const size_type bits_in_carry = 8 - bits_to_ignore_in_carry;
                  const size_type bits_to_collect =
                     std::min(block_bits, m_start_bitoffset + m_bitlength - m_read_bitpos);

                  const uint8_t carry = m_source.m_blocks[byte_pos];

                  // Initialize the left-most bits with the carry.
                  result_block = BlockT(carry) >> bits_to_ignore_in_carry;

                  // If more bits are needed, we pull them from the remaining bytes.
                  if(bits_in_carry < bits_to_collect) {
                     const BlockT block =
                        load_le(std::span{m_source.m_blocks}.subspan(byte_pos + 1).template first<block_size>());
                     result_block |= block << bits_in_carry;
                  }
               }

               m_read_bitpos += std::min(block_size * 8, bits_to_read());
               return result_block;
            }

            /**
             * Stores the next block of bits into the underlying bitvector.
             * No bounds checks are performed. Storing bit blocks that are not
             * aligned at a byte-boundary in the underlying bitvector is
             * currently not implemented.
             */
            template <std::unsigned_integral BlockT>
               requires(!is_const())
            void store_next(BlockT block) {
               constexpr size_type block_size = sizeof(BlockT);

               if constexpr(is_byte_aligned()) {
                  auto sink = std::span{m_source.m_blocks}.subspan(m_write_bitpos / 8).template first<block_size>();
                  store_le(sink, block);
               } else {
                  throw Not_Implemented("Storing out-of-alignment blocks is NYI");
               }

               m_write_bitpos += std::min(block_size * 8, bits_to_write());
            }

         private:
            BitvectorT& m_source;
            size_type m_start_bitoffset;
            size_type m_bitlength;

            mutable size_type m_read_bitpos;
            mutable size_type m_write_bitpos;
      };

      /**
       * Helper function of `full_range_operation` and `range_operation` that
       * calls @p fn on a given unsigned integer block size as long as the
       * underlying bit range contains enough bits to fill the block.
       */
      template <std::unsigned_integral BlockT,
                typename FnT,
                typename BitRangeOperatorT0,
                typename... BitRangeOperatorTs>
         requires(detail::blockwise_processing_callback<FnT, BitRangeOperatorT0, BitRangeOperatorTs...>)
      static bool _process_in_blocks_of(FnT fn, BitRangeOperatorT0& first_op, const BitRangeOperatorTs&... ops) {
         auto process_block = [&](size_type bits) {
            if constexpr(detail::
                            blockwise_processing_callback_with_mask<FnT, BitRangeOperatorT0, BitRangeOperatorTs...>) {
               return fn(
                  first_op.template load_next<BlockT>(), ops.template load_next<BlockT>()..., make_mask<BlockT>(bits));
            } else {
               return fn(first_op.template load_next<BlockT>(), ops.template load_next<BlockT>()...);
            }
         };

         auto block_applies = [](const auto& op) {
            if constexpr(sizeof(BlockT) == 1) {
               return op.bits_to_read() > 0;
            } else {
               return op.bits_to_read() >= sizeof(BlockT) * 8;
            }
         };

         using block_result_t = decltype(process_block(std::declval<BlockT>()));

         while(block_applies(first_op)) {
            const auto bits = first_op.bits_to_read();
            if constexpr(std::same_as<BlockT, block_result_t>) {
               first_op.template store_next(process_block(bits));
            } else if constexpr(std::same_as<bool, block_result_t>) {
               if(!process_block(bits)) {
                  return false;
               }
            } else {
               process_block(bits);
            }
         }

         return true;
      }

      /**
       * Apply @p fn to all bits in the ranges defined by @p ops. If more than
       * one range operator is passed to @p ops, @p fn receives corresponding
       * blocks of bits from each operator. Therefore, all @p ops have to define
       * the exact same length of their underlying ranges.
       *
       * @p fn may return a bit block that will be stored into the _first_ bit
       * range passed into @p ops. If @p fn returns a boolean, and its value is
       * `false`, the range operation is cancelled and `false` is returned.
       *
       * The implementation ensures to pull bits in the largest bit blocks
       * possible and reverts to smaller bit blocks only when needed.
       */
      template <typename FnT, typename... BitRangeOperatorTs>
         requires(detail::blockwise_processing_callback<FnT, BitRangeOperatorTs...>)
      static bool range_operation(FnT fn, BitRangeOperatorTs... ops) {
         BOTAN_ASSERT(has_equal_lengths(ops...), "all BitRangeOperators have the same length");
         return _process_in_blocks_of<uint64_t>(fn, ops...) && _process_in_blocks_of<uint32_t>(fn, ops...) &&
                _process_in_blocks_of<uint16_t>(fn, ops...) && _process_in_blocks_of<uint8_t>(fn, ops...);
      }

      /**
       * Apply @p fn to all bit blocks in the bitvector(s).
       */
      template <typename FnT, typename... BitvectorTs>
         requires(detail::blockwise_processing_callback<FnT, BitvectorTs...>)
      static bool full_range_operation(FnT&& fn, BitvectorTs&... bitvecs) {
         BOTAN_ASSERT(has_equal_lengths(bitvecs...), "all bitvectors have the same length");
         return range_operation(std::forward<FnT>(fn), BitRangeOperator<BitvectorTs>(bitvecs)...);
      }

      template <typename SomeT>
      static bool has_equal_lengths(const SomeT&) {
         return true;
      }

      template <typename SomeT, typename... SomeTs>
      static bool has_equal_lengths(const SomeT& v, const SomeTs&... vs) {
         return ((v.size() == vs.size()) && ...);
      }

      template <std::unsigned_integral T>
      static T make_mask(size_type bits) {
         const bool max = bits >= sizeof(T) * 8;
         bits &= T(max - 1);
         return (T(!max) << bits) - 1;
      }

   private:
      size_type m_bits;
      std::vector<block_type, allocator_type> m_blocks;
};

using secure_bitvector = bitvector_base<secure_allocator>;
using bitvector = bitvector_base<std::allocator>;

namespace detail {

/**
 * If one of the allocators is a Botan::secure_allocator, this will always
 * prefer it. Otherwise, the allocator of @p lhs will be used as a default.
 */
template <template <typename> typename AllocatorT1, template <typename> typename AllocatorT2>
constexpr auto copy_lhs_allocator_aware(const bitvector_base<AllocatorT1>& lhs,
                                        const bitvector_base<AllocatorT2>& rhs) {
   constexpr bool needs_secure_allocator = std::remove_cvref_t<decltype(lhs)>::uses_secure_allocator ||
                                           std::remove_cvref_t<decltype(rhs)>::uses_secure_allocator;

   if constexpr(needs_secure_allocator) {
      return lhs.as_locked();
   } else {
      return lhs;
   }
}

}  // namespace detail

template <template <typename> typename AllocatorT1, template <typename> typename AllocatorT2>
auto operator|(const bitvector_base<AllocatorT1>& lhs, const bitvector_base<AllocatorT2>& rhs) {
   auto res = detail::copy_lhs_allocator_aware(lhs, rhs);
   res |= rhs;
   return res;
}

template <template <typename> typename AllocatorT1, template <typename> typename AllocatorT2>
auto operator&(const bitvector_base<AllocatorT1>& lhs, const bitvector_base<AllocatorT2>& rhs) {
   auto res = detail::copy_lhs_allocator_aware(lhs, rhs);
   res &= rhs;
   return res;
}

template <template <typename> typename AllocatorT1, template <typename> typename AllocatorT2>
auto operator^(const bitvector_base<AllocatorT1>& lhs, const bitvector_base<AllocatorT2>& rhs) {
   auto res = detail::copy_lhs_allocator_aware(lhs, rhs);
   res ^= rhs;
   return res;
}

template <template <typename> typename AllocatorT1, template <typename> typename AllocatorT2>
bool operator==(const bitvector_base<AllocatorT1>& lhs, const bitvector_base<AllocatorT2>& rhs) {
   return lhs.equals(rhs);
}

template <template <typename> typename AllocatorT1, template <typename> typename AllocatorT2>
bool operator!=(const bitvector_base<AllocatorT1>& lhs, const bitvector_base<AllocatorT2>& rhs) {
   return lhs.equals(rhs);
}

}  // namespace Botan

#endif
