/*
* Classic McEliece Matrix Logic
*
* People who took the red pill:
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
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
                                                      const Classic_McEliece_Field_Ordering& field_ordering,
                                                      const Classic_McEliece_Minimal_Polynomial& g) {
   auto all_alphas = field_ordering.alphas();
   BOTAN_ASSERT_NOMSG(params.n() <= all_alphas.size());
   // TODO: In own function
   std::vector<Classic_McEliece_GF> alphas(all_alphas.begin(), all_alphas.begin() + params.n());
   std::vector<Classic_McEliece_GF> inv_g_of_alpha;
   inv_g_of_alpha.reserve(params.n());
   for(const auto& alpha : alphas) {
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
                                             const Classic_McEliece_Parameters& params) {
   static_assert(Classic_McEliece_Parameters::nu() == 64,
                 "nu needs to be 64");  // Since we use uint64_t to represent tows in the mu x nu sub-matrix
   // A 32x64 sub-matrix of mat containing the elements mat[m*t-32][m*t-32] at the top left
   std::vector<secure_bitvector> sub_mat(Classic_McEliece_Parameters::mu(), secure_bitvector());

   size_t pos_offset = params.pk_no_rows() - Classic_McEliece_Parameters::mu();

   // Extract the bottom mu x nu matrix at offset row_offset
   for(size_t i = 0; i < 32; i++) {
      sub_mat.at(i) = mat.at(pos_offset + i).subvector(pos_offset, Classic_McEliece_Parameters::nu());
   }

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

   // Create pivot bitvector from the pivot index vector
   secure_bitvector pivots(Classic_McEliece_Parameters::nu());
   for(auto pivot_idx : pivot_indices) {
      for(size_t i = 0; i < Classic_McEliece_Parameters::nu(); ++i) {
         auto mask_is_at_current_idx = Botan::CT::Mask<size_t>::is_equal(i, pivot_idx);
         pivots.at(i) = mask_is_at_current_idx.select(1, pivots.at(i));
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
                                            std::vector<secure_bitvector>& mat) {
   // Initialized for systematic form instances
   // Is overridden for semi systematic instances
   auto pivots = secure_bitvector(std::vector<uint8_t>({0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0}), 64);

   // Gaussian Elimination
   for(size_t diag_pos = 0; diag_pos < params.pk_no_rows(); ++diag_pos) {
      if(params.is_f() && diag_pos == params.pk_no_rows() - params.mu()) {
         auto ret_pivots = move_columns(mat, params);
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
   const Classic_McEliece_Field_Ordering& field_ordering,
   const Classic_McEliece_Minimal_Polynomial& g) {
   auto mat = init_matrix_with_alphas(params, field_ordering, g);
   auto pivots = apply_gauss(params, mat);

   if(!pivots) {
      return std::nullopt;
   }

   auto pk_mat_bytes = extract_pk_bytes_from_matrix(params, mat);
   return std::make_pair(Classic_McEliece_Matrix(std::move(pk_mat_bytes)), pivots.value());
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
}  // namespace Botan
