/*
* Classic McEliece Matrix Logic
*
* People who took the red pill:
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/cmce_debug_utils.h>
#include <botan/internal/cmce_matrix.h>

namespace {
using word_t = uint64_t;

}  // Anonymous namespace

// TODO: Refactoring potential (after semi-systematic form is implemented)
namespace Botan {
namespace {

//Remove me
std::optional<std::pair<Classic_McEliece_Matrix, std::array<uint8_t, Classic_McEliece_Parameters::nu() / 8>>>
old_create_matrix(const Classic_McEliece_Parameters& params,
                  Classic_McEliece_Field_Ordering& field_ordering,
                  const Classic_McEliece_Minimal_Polynomial& g);

size_t count_lsb_zeros(secure_bitvector n) {
   size_t res = 0;
   Botan::CT::Mask<size_t> found_only_zeros = Botan::CT::Mask<size_t>::set();
   for(size_t bit_pos = 0; bit_pos < n.size(); ++bit_pos) {
      auto bit_set_mask = Botan::CT::Mask<size_t>::expand(n.at(bit_pos));
      found_only_zeros &= ~bit_set_mask;
      res += found_only_zeros.if_set_return(size_t(1));
   }

   return res;
}

std::vector<secure_bitvector> init_matrix_with_alphas(const Classic_McEliece_Parameters& params,
                                                      Classic_McEliece_Field_Ordering& field_ordering,
                                                      const Classic_McEliece_Minimal_Polynomial& g) {
   auto all_alphas = field_ordering.alphas();
   BOTAN_ASSERT_NOMSG(params.n() <= all_alphas.size());
   // TODO: In own function
   std::vector<Classic_McEliece_GF> alphas(all_alphas.begin(), all_alphas.begin() + params.n());
   std::vector<Classic_McEliece_GF> inv_g_of_alpha;
   inv_g_of_alpha.reserve(params.n());
   for(auto& alpha : alphas) {
      inv_g_of_alpha.push_back(g(alpha).inv());
   }
   std::vector<secure_bitvector> mat(params.pk_no_rows(), secure_bitvector(params.n()));

   for(size_t i = 0; i < params.t(); ++i) {
      for(size_t j = 0; j < params.n(); ++j) {
         for(size_t alpha_i_j_bit = 0; alpha_i_j_bit < params.m(); ++alpha_i_j_bit) {
            mat.at(i * params.m() + alpha_i_j_bit).at(j) = (1 << alpha_i_j_bit) & inv_g_of_alpha.at(j).elem();
         }
      }
      // Update for the next i so that:
      // inv_g_of_alpha[j] = h_i_j = alpha_j^i/g(alpha_j)
      for(size_t j = 0; j < params.n(); ++j) {
         inv_g_of_alpha.at(j) *= alphas.at(j);
      }
   }

   return mat;
}

std::optional<secure_bitvector> move_columns(std::vector<secure_bitvector>& mat,
                                             Classic_McEliece_Field_Ordering& field_ordering,
                                             const Classic_McEliece_Parameters& params) {
   // TODO refactor w/ new bitvector
   static_assert(Classic_McEliece_Parameters::nu() == 64,
                 "nu needs to be 64");  // Since we use uint64_t to represent tows in the mu x nu sub-matrix
   // A 32x64 sub-matrix of mat containing the elements mat[m*t-32][m*t-32] at the top left
   std::vector<secure_bitvector> sub_mat(Classic_McEliece_Parameters::mu(), secure_bitvector());

   size_t pos_offset = params.pk_no_rows() - Classic_McEliece_Parameters::mu();

   // Extract the bottom mu x nu matrix at offset row_offset
   for(size_t i = 0; i < 32; i++) {
      sub_mat.at(i) = mat.at(pos_offset + i).subvector(pos_offset, Classic_McEliece_Parameters::nu());
   }

   secure_bitvector pivots(Classic_McEliece_Parameters::nu());
   std::array<size_t, Classic_McEliece_Parameters::mu()> pivot_indices = {0};  // ctz_list

   // Identify the pivot indices, i.e. the indices of the leading ones for all rows
   // when transforming the matrix into semi-systematic form. This algorithm is a modified
   // gauss algorithm.
   for(size_t row_idx = 0; row_idx < 32; ++row_idx) {
      // Identify pivots (index of first 1) by OR-ing all subsequent rows into row_acc
      auto row_acc = sub_mat.at(row_idx);
      for(size_t next_row = row_idx + 1; next_row < 32; ++next_row) {
         row_acc |= sub_mat.at(next_row);
      }

      if(row_acc.none()) {
         // If the current row and all subsequent rows are zero
         // we cannot create a semi-systematic matrix
         return std::nullopt;
      }

      // Using the row accumulator we can predict the index of the pivot
      // bit for the current row, i.e. the first index where we can set
      // the bit to one rowby adding any subsequent row
      pivot_indices.at(row_idx) = count_lsb_zeros(row_acc);
      pivots.at(pivot_indices.at(row_idx)).set();

      // Add subsequent rows to the current row, until the pivot
      // bit is set.
      for(size_t next_row = row_idx + 1; next_row < Classic_McEliece_Parameters::mu(); ++next_row) {
         sub_mat.at(row_idx).ct_conditional_xor(!sub_mat.at(row_idx).at(pivot_indices.at(row_idx)),
                                                sub_mat.at(next_row));
      }

      // Add the (new) current row to all subsequent rows, where the leading
      // bit of the current bit is one. Therefore, the column of the leading
      // bit becomes zero.
      // Note: In normal gauss, we would also add the current row to rows
      //       above the current one. However, here we only need to identify
      //       the columns to swap. Therefore, we can ignore the upper rows.
      for(size_t next_row = row_idx + 1; next_row < Classic_McEliece_Parameters::mu(); ++next_row) {
         sub_mat.at(next_row).ct_conditional_xor(sub_mat.at(next_row).at(pivot_indices.at(row_idx)),
                                                 sub_mat.at(row_idx));
      }
   }

   // Update pi (i.e., update field ordering reference) by swapping values
   //TODO: Separate function using pivots/c?
   auto& pi_ref = field_ordering.pi_ref();
   for(size_t j = 0; j < 32; ++j) {
      for(size_t k = j + 1; k < 64; ++k) {
         // If k == pivot_indices[j], swap pi[row_offset + j] and pi[row_offset + k]
         // Use 64-bit mask since pivot_indices is 64 bit. TODO: Do we really need 64 bit?
         auto mask = CT::Mask<uint16_t>::is_equal(k, pivot_indices.at(j));
         mask.conditional_swap(pi_ref.at(pos_offset + j), pi_ref.at(pos_offset + k));
      }
   }

   // Update matrix by swapping columns
   for(size_t mat_row = 0; mat_row < params.pk_no_rows(); ++mat_row) {
      for(size_t j = 0; j < Classic_McEliece_Parameters::mu(); ++j) {
         // Swap bit j with bit pivot_indices[j]
         size_t col_j = pos_offset + j;
         size_t col_pivot_j = pos_offset + pivot_indices.at(j);
         bool sum = mat.at(mat_row).at(col_j) ^ mat.at(mat_row).at(col_pivot_j);
         mat.at(mat_row).at(col_j) = mat.at(mat_row).at(col_j) ^ sum;
         mat.at(mat_row).at(col_pivot_j) = mat.at(mat_row).at(col_pivot_j) ^ sum;
      }
   }

   return pivots;
}

std::optional<secure_bitvector> apply_gauss(const Classic_McEliece_Parameters& params,
                                            Classic_McEliece_Field_Ordering& field_ordering,
                                            std::vector<secure_bitvector>& mat) {
   // Initialized for systematic form instances
   // Is overridden for semi systematic instances
   auto pivots = secure_bitvector(std::vector<uint8_t>({0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0}), 64);

   // Gaussian Elimination
   for(size_t diag_pos = 0; diag_pos < params.pk_no_rows(); ++diag_pos) {
      if(params.is_f() && diag_pos == params.pk_no_rows() - params.mu()) {
         auto ret_pivots = move_columns(mat, field_ordering, params);
         if(!ret_pivots) {
            return std::nullopt;
         } else {
            pivots = std::move(ret_pivots.value());
         }
      }

      // Iterates over all rows k under r. If the bit at column
      // word_bits*i+j differs between row r and k, row k is added to row r.
      // This achieves that the respective bit at the diagonal becomes 1
      // (if mat is systematic)
      for(size_t next_row = diag_pos + 1; next_row < params.pk_no_rows(); ++next_row) {
         mat.at(diag_pos).ct_conditional_xor(!mat.at(diag_pos).at(diag_pos), mat.at(next_row));
      }

      // If the current bit on the diagonal is not set at this point
      // the matrix is not systematic. We abort the computation in this case.
      if(!mat.at(diag_pos).at(diag_pos)) {
         return std::nullopt;
      }

      // Now the new row is added to all other rows, where the
      // bit in the column of the current postion on the diagonal
      // is still one
      for(size_t row = 0; row < params.pk_no_rows(); ++row) {
         if(row != diag_pos) {
            mat.at(row).ct_conditional_xor(mat.at(row).at(diag_pos), mat.at(diag_pos));
         }
      }
   }

   return pivots;
}

std::vector<uint8_t> extract_pk_bytes_from_matrix(const Classic_McEliece_Parameters& params,
                                                  const std::vector<secure_bitvector>& mat) {
   // Store T of the matrix (I_mt|T) as a linear vector to represent the
   // public key as defined in McEliece ISO 9.2.7
   std::vector<uint8_t> big_t(params.pk_size_bytes());
   auto big_t_stuffer = BufferStuffer(big_t);

   for(size_t row = 0; row < params.pk_no_rows(); ++row) {
      auto pk_row_bits = mat.at(row).subvector(params.pk_no_rows());
      auto row_bytes = pk_row_bits.to_bytes();

      big_t_stuffer.append(row_bytes);
   }

   BOTAN_ASSERT_NOMSG(big_t_stuffer.full());

   return big_t;
}

}  // namespace

std::optional<std::pair<Classic_McEliece_Matrix, secure_bitvector>> Classic_McEliece_Matrix::create_matrix(
   const Classic_McEliece_Parameters& params,
   Classic_McEliece_Field_Ordering& field_ordering,
   const Classic_McEliece_Minimal_Polynomial& g) {
   Stopwatch watch;
   //watch.reset();
   auto old = old_create_matrix(params, field_ordering, g);
   //watch.log_and_reset("Old time");
   //BOTAN_ASSERT_NOMSG(!old.has_value());

   auto mat = init_matrix_with_alphas(params, field_ordering, g);
   watch.reset();
   auto pivots = apply_gauss(params, field_ordering, mat);
   watch.log_and_reset("New gauss");

   auto pk_mat_bytes = extract_pk_bytes_from_matrix(params, mat);

   if(!pivots) {  //TODO: Copy before byte extraction
      return std::nullopt;
   }
   watch.log_and_reset("New time");
   BOTAN_ASSERT_NOMSG(old.has_value());
   return std::make_pair(Classic_McEliece_Matrix(std::move(pk_mat_bytes /*std::get<0>(*old)*/)), pivots.value());
}

bitvector Classic_McEliece_Matrix::mul(const Classic_McEliece_Parameters& params, const secure_bitvector& e) const {
   auto s = e.subvector(0, params.pk_no_rows());
   auto e_T = e.subvector(params.pk_no_rows());
   auto pk_slicer = BufferSlicer(m_mat_bytes);

   for(size_t i = 0; i < params.pk_no_rows(); ++i) {
      auto pk_current_bytes = pk_slicer.take(params.pk_row_size_bytes());
      auto row = secure_bitvector(pk_current_bytes, params.n() - params.pk_no_rows());
      row &= e_T;
      s.at(i) = s.at(i) ^ row.has_odd_hamming_weight();
   }

   BOTAN_ASSERT_NOMSG(pk_slicer.empty());
   return s.as_unlocked();
}

namespace {

std::optional<uint64_t> old_move_columns(std::vector<std::vector<word_t>>& mat,
                                         Classic_McEliece_Field_Ordering& field_ordering,
                                         const Classic_McEliece_Parameters& params) {
   // TODO refactor w/ new bitvector
   static_assert(Classic_McEliece_Parameters::nu() == 64,
                 "nu needs to be 64");  // Since we use uint64_t to represent tows in the mu x nu sub-matrix
   std::array<uint64_t, Classic_McEliece_Parameters::mu()> buf;

   size_t row_offset = params.pk_no_rows() - Classic_McEliece_Parameters::mu();
   BOTAN_ASSERT(row_offset % (sizeof(word_t) * 8) == 0,
                "Not yet supported. Help us, René-Wan Kenobi! You're our only hope!");
   size_t col_word_offset = row_offset / (sizeof(word_t) * 8);

   // TODO: Generalize (René \o/)
   auto combine_uint32_le = [](uint32_t a, uint32_t b) {
      std::array<uint8_t, sizeof(uint64_t)> tmp;
      store_le(a, tmp.data() + 0 * (sizeof(uint64_t) / 2));
      store_le(b, tmp.data() + 1 * (sizeof(uint64_t) / 2));
      return load_le<uint64_t>(tmp.data(), 0);
   };

   // Extract the bottom mu x nu matrix at offset row_offset
   for(size_t i = 0; i < 32; i++) {
      buf.at(i) = combine_uint32_le(mat.at(row_offset + i).at(col_word_offset + 0),
                                    mat.at(row_offset + i).at(col_word_offset + 1));
   }

   uint64_t pivots = 0;
   std::array<uint64_t, Classic_McEliece_Parameters::mu()> pivot_indices = {0};  // ctz_list

   // Identify the pivot indices, i.e. the indices of the leading ones for all rows
   // when transforming the matrix into semi-systematic form. This algorithm is a modified
   // gauss algorithm.
   for(size_t row_idx = 0; row_idx < 32; ++row_idx) {
      // Identify pivots (index of first 1) by OR-ing all subsequent rows into row_acc
      uint64_t row_acc = buf.at(row_idx);
      for(size_t next_row = row_idx + 1; next_row < 32; ++next_row) {
         row_acc |= buf[next_row];
      }

      if(row_acc == 0) {
         // If the current row and all subsequent rows are zero
         // we cannot create a semi-systematic matrix
         return std::nullopt;
      }

      // Using the row accumulator we can predict the index of the pivot
      // bit for the current row, i.e. the first index where we can set
      // the bit to one rowby adding any subsequent row
      pivot_indices.at(row_idx) = count_lsb_zeros(row_acc);
      pivots |= uint64_t(1) << pivot_indices.at(row_idx);

      // Add subsequent rows to the current row, until the pivot
      // bit is set.
      for(size_t j = row_idx + 1; j < Classic_McEliece_Parameters::mu(); ++j) {
         auto mask = CT::Mask<uint64_t>::expand_on_bit(buf[row_idx], pivot_indices.at(row_idx));

         buf[row_idx] ^= mask.if_not_set_return(buf[j]);
      }

      // Add the (new) current row to all subsequent rows, where the leading
      // bit of the current bit is one. Therefore, the column of the leading
      // bit becomes zero.
      // Note: In normal gauss, we would also add the current row to rows
      //       above the current one. However, here we only need to identify
      //       the columns to swap. Therefore, we can ignore the upper rows.
      for(size_t j = row_idx + 1; j < Classic_McEliece_Parameters::mu(); ++j) {
         auto mask = CT::Mask<uint64_t>::expand_on_bit(buf[j], pivot_indices.at(row_idx));

         buf[j] ^= mask.if_set_return(buf[row_idx]);
      }
   }

   // Update pi (i.e., update field ordering reference) by swapping values
   //TODO: Separate function using pivots/c?
   auto& pi_ref = field_ordering.pi_ref();
   for(size_t j = 0; j < 32; ++j) {
      for(size_t k = j + 1; k < 64; ++k) {
         // If k == pivot_indices[j], swap pi[row_offset + j] and pi[row_offset + k]
         // Use 64-bit mask since pivot_indices is 64 bit. TODO: Do we really need 64 bit?
         auto mask = CT::Mask<uint64_t>::is_equal(k, pivot_indices.at(j));
         mask.conditional_swap(pi_ref.at(row_offset + j), pi_ref.at(row_offset + k));
         //TODO: Possibly do a direct implementation of cond_swap using XOR trick like in Ref Implementation
      }
   }

   // Update matrix by swapping columns
   for(size_t i = 0; i < params.pk_no_rows(); ++i) {
      uint64_t block = combine_uint32_le(mat.at(i).at(col_word_offset + 0), mat.at(i).at(col_word_offset + 1));

      for(size_t col = 0; col < Classic_McEliece_Parameters::mu(); ++col) {
         // TODO: Beautify this with René's bitvector
         uint64_t d = block >> col;            // mat[i][j]
         d ^= block >> pivot_indices.at(col);  // mat[i][ctz[j]]
         d &= 1;                               // d = mat[i][j] ^ mat[i][ctz[j]]

         block ^= d << pivot_indices.at(col);  // mat[i][ctz[j]] ^= mat[i][j] ^ mat[i][ctz[j]]
         block ^= d << col;                    // mat[i][j] ^= mat[i][j] ^ mat[i][ctz[j]]
         // => swap bit j and ctz[j]
      }

      // TODO: Generalize, only works for word_t = uint32_t
      std::array<uint8_t, sizeof(uint64_t)> tmp;
      store_le(block, tmp.data());
      mat.at(i).at(col_word_offset + 0) = load_le<uint32_t>(tmp.data(), 0);
      mat.at(i).at(col_word_offset + 1) = load_le<uint32_t>(tmp.data(), 1);
   }

   return pivots;
}

std::optional<std::pair<Classic_McEliece_Matrix, std::array<uint8_t, Classic_McEliece_Parameters::nu() / 8>>>
old_create_matrix(const Classic_McEliece_Parameters& params,
                  Classic_McEliece_Field_Ordering& field_ordering,
                  const Classic_McEliece_Minimal_Polynomial& g) {
   constexpr size_t word_bits = sizeof(word_t) * 8;

   // Precompute g(alpha_j) for j=0,...,n-1
   auto all_alphas = field_ordering.alphas();
   BOTAN_ASSERT_NOMSG(params.n() <= all_alphas.size());
   std::vector<Classic_McEliece_GF> alphas(all_alphas.begin(), all_alphas.begin() + params.n());
   std::vector<Classic_McEliece_GF> inv_g_of_alpha;
   inv_g_of_alpha.reserve(params.n());
   for(auto& alpha : alphas) {
      inv_g_of_alpha.push_back(g(alpha).inv());
   }
   const size_t col_words = ceil_div(params.n(), word_bits);
   std::vector<std::vector<word_t>> mat(params.pk_no_rows(), std::vector<word_t>(col_words, 0));

   for(size_t i = 0; i < params.t(); ++i) {
      // Compute the column representation of h_i,j = alpha_j^i/g(alpha_j) [i fixed]
      // 1 row of word_bits adjacent columns is represented as one word of mat.
      for(size_t j = 0; j < params.n(); j += word_bits) {
         for(size_t k = 0; k < params.m(); ++k) {
            /// Number of signification bits in this word. Relevant if n % sizeof(word_t) != 0.
            size_t sig_bits = std::min(params.n() - j, word_bits);
            auto b = (word_t(inv_g_of_alpha.at(j + sig_bits - 1).elem()) >> k) & 1;
            for(int16_t bit_off = sig_bits - 2; bit_off >= 0; --bit_off) {
               b <<= 1;
               b |= (word_t(inv_g_of_alpha.at(j + bit_off).elem()) >> k) & 1;
            }

            mat.at(i * params.m() + k).at(j / word_bits) = b;
         }
      }

      // Update for the next i so that:
      // inv_g_of_alpha[j] = h_i_j = alpha_j^i/g(alpha_j)
      for(size_t j = 0; j < params.n(); ++j) {
         inv_g_of_alpha.at(j) *= alphas.at(j);
      }
   }

   // Initialized for systematic form instances
   // Is overridden for semi systematic instances
   uint64_t pivots = 0xFFFFFFFF;
   Stopwatch watch;
   // Gaussian Elimination
   for(size_t i = 0; i < (params.pk_no_rows() + word_bits - 1) / word_bits; ++i) {
      for(size_t j = 0; j < word_bits; j++) {
         // We iterate the matrix diagonally. In this step
         // the (i*word_bits+j)th bit row and column is processed
         auto row = i * word_bits + j;

         if(row >= params.pk_no_rows()) {
            break;
         }

         // TODO: Insert semi systematic logic
         if(params.is_f() && row == params.pk_no_rows() - params.mu()) {
            auto ret_pivots = old_move_columns(mat, field_ordering, params);
            if(!ret_pivots) {
               return std::nullopt;
            } else {
               pivots = ret_pivots.value();
            }
         }

         // Iterates over all rows k under r. If the bit at column
         // word_bits*i+j differs between row r and k, row k is added to row r.
         // This achieves that the respective bit at the diagonal becomes 1
         // (if mat is systematic)
         for(size_t k = row + 1; k < params.pk_no_rows(); ++k) {
            auto mask = CT::Mask<uint64_t>::expand_on_bit(mat.at(row).at(i) ^ mat.at(k).at(i), j);

            // We do not use mat.at(x).at(y) because we are in the bottleneck.
            // Instead we do the following check covering the entire loop.
            BOTAN_ASSERT_NOMSG(col_words <= mat.at(0).size() && params.pk_no_rows() <= mat.size() && row < mat.size());
            for(size_t c = 0; c < col_words; ++c) {
               mat[row][c] ^= mask.if_set_return(mat[k][c]);
            }
         }

         // If the current bit on the diagonal is not set at this point
         // the matrix is not systematic. We abort the computation in this case.
         if(((mat.at(row).at(i) >> j) & 1) == 0) {
            return std::nullopt;
         }

         // Now the new row is added to all other rows, where the
         // bit in the column of the current postion on the diagonal
         // is still one
         for(size_t k = 0; k < params.pk_no_rows(); ++k) {
            if(k != row) {
               auto mask = CT::Mask<uint64_t>::expand_on_bit(mat.at(k).at(i), j);

               // We do not use mat.at(x).at(y) because we are in the bottleneck.
               // Instead we do the following check covering the entire loop.
               BOTAN_ASSERT_NOMSG(col_words <= mat.at(0).size() && params.pk_no_rows() <= mat.size() &&
                                  row < mat.size());
               for(size_t c = 0; c < col_words; ++c) {
                  mat[k][c] ^= mask.if_set_return(mat[row][c]);
               }
            }
         }
      }
   }
   watch.log_and_reset("Old gauss");

   // Store T of the matrix (I_mt|T) as a linear vector to represent the
   // public key as defined in McEliece ISO 9.2.7
   std::vector<uint8_t> big_t(params.pk_size_bytes());
   auto big_t_stuffer = BufferStuffer(big_t);

   auto tail = params.pk_no_rows() % word_bits;
   const size_t offset = params.pk_no_rows() / word_bits;

   // Implements the following: (mat.at(row).at(col) >> tail) | (mat.at(row).at(col + 1) << (sizeof(word_t) * 8 - tail));
   // However, this is UB for tail == 0, in which case we just use mat.at(row).at(col).
   auto reassemble = [tail](std::vector<std::vector<word_t>>& mat_in, size_t row, size_t col) {
      if(tail == 0) {
         return mat_in.at(row).at(col);
      } else {
         // This is only defined behavior for 0 < tail < sizeof(word_t) * 8 <=> tail != 0
         return (mat_in.at(row).at(col) >> tail) | (mat_in.at(row).at(col + 1) << (sizeof(word_t) * 8 - tail));
      }
   };

   for(size_t i = 0; i < params.pk_no_rows(); ++i) {
      // For each column, store the bytes in big_t.
      // Since mat is uint64_t, we need to start within the values with offset tail
      for(size_t j = offset; j < col_words - 1; ++j) {
         word_t temp = reassemble(mat, i, j);
         store_le(temp, big_t_stuffer.next(sizeof(temp)).data());
      }

      uint64_t temp2 = mat.at(i).at(col_words - 1) >> tail;

      std::vector<uint8_t> remaining_bytes(sizeof(word_t));
      store_le(temp2, remaining_bytes.data());

      size_t already_written = (col_words - 1 - offset) * sizeof(word_t);
      size_t to_write = ceil_div(params.pk_no_cols(), 8);

      big_t_stuffer.append(std::span<uint8_t>(remaining_bytes).subspan(0, to_write - already_written));
   }

   BOTAN_ASSERT_NOMSG(big_t_stuffer.full());

   std::array<uint8_t, (Classic_McEliece_Parameters::nu() / 8)> pivots_array;
   store_le(pivots, pivots_array.data());

   return std::make_pair(Classic_McEliece_Matrix(std::move(big_t)), pivots_array);
}
}  // namespace

}  // namespace Botan
