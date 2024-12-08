// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin units library
//!
//! This library provides basic types used by the Rust Bitcoin ecosystem.

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
//
#![warn(clippy::assigning_clones)] // Complete list of pedantic lints. See comments for those not set to `warn`.
#![warn(clippy::bool_to_int_with_if)]
#![warn(clippy::borrow_as_ptr)]
#![warn(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::cast_lossless)] // TODO: Still needs considering.
#![allow(clippy::cast_possible_truncation)] // TODO: Still needs considering.
#![allow(clippy::cast_possible_wrap)] // TODO: Still needs considering.
#![warn(clippy::cast_precision_loss)]
#![warn(clippy::cast_ptr_alignment)]
#![allow(clippy::cast_sign_loss)] // TODO: Still needs considering.
#![warn(clippy::checked_conversions)]
#![allow(clippy::cloned_instead_of_copied)] // TODO: Still needs considering.
#![warn(clippy::copy_iterator)]
#![warn(clippy::default_trait_access)]
#![warn(clippy::doc_link_with_quotes)]
#![warn(clippy::doc_markdown)]
#![warn(clippy::empty_enum)]
#![allow(clippy::enum_glob_use)] // TODO: Still needs considering.
#![warn(clippy::expl_impl_clone_on_copy)]
#![warn(clippy::explicit_deref_methods)]
#![warn(clippy::explicit_into_iter_loop)]
#![allow(clippy::explicit_iter_loop)] // TODO: Still needs considering.
#![warn(clippy::filter_map_next)]
#![warn(clippy::flat_map_option)]
#![allow(clippy::float_cmp)] // TODO: Still needs considering.
#![warn(clippy::fn_params_excessive_bools)]
#![warn(clippy::from_iter_instead_of_collect)]
#![warn(clippy::if_not_else)]
#![warn(clippy::ignored_unit_patterns)]
#![warn(clippy::implicit_clone)]
#![warn(clippy::implicit_hasher)]
#![warn(clippy::inconsistent_struct_constructor)]
#![warn(clippy::index_refutable_slice)]
#![warn(clippy::inefficient_to_string)]
#![warn(clippy::inline_always)]
#![warn(clippy::into_iter_without_iter)]
#![warn(clippy::invalid_upcast_comparisons)]
#![allow(clippy::items_after_statements)] // TODO: Still needs considering.
#![warn(clippy::iter_filter_is_ok)]
#![warn(clippy::iter_filter_is_some)]
#![warn(clippy::iter_not_returning_iterator)]
#![warn(clippy::iter_without_into_iter)]
#![warn(clippy::large_digit_groups)]
#![warn(clippy::large_futures)]
#![warn(clippy::large_stack_arrays)]
#![warn(clippy::large_types_passed_by_value)]
#![warn(clippy::linkedlist)]
#![warn(clippy::macro_use_imports)]
#![warn(clippy::manual_assert)]
#![warn(clippy::manual_instant_elapsed)]
#![warn(clippy::manual_is_power_of_two)]
#![warn(clippy::manual_is_variant_and)]
#![warn(clippy::manual_let_else)]
#![warn(clippy::manual_ok_or)]
#![warn(clippy::manual_string_new)]
#![warn(clippy::many_single_char_names)]
#![warn(clippy::map_unwrap_or)]
#![allow(clippy::match_bool)] // ALLOW: Adds extra indentation and LOC.
#![warn(clippy::match_on_vec_items)]
#![allow(clippy::match_same_arms)] // ALLOW: Collapses things that are conceptually unrelated to each other.
#![warn(clippy::match_wild_err_arm)]
#![warn(clippy::match_wildcard_for_single_variants)]
#![warn(clippy::maybe_infinite_iter)]
#![warn(clippy::mismatching_type_param_order)]
#![allow(clippy::missing_errors_doc)] // TODO: Still needs considering.
#![warn(clippy::missing_fields_in_debug)]
#![allow(clippy::missing_panics_doc)] // TODO: Still needs considering.
#![allow(clippy::must_use_candidate)] // ALLOW: Useful for audit but many false positives.
#![warn(clippy::mut_mut)]
#![warn(clippy::naive_bytecount)]
#![warn(clippy::needless_bitwise_bool)]
#![warn(clippy::needless_continue)]
#![warn(clippy::needless_for_each)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::needless_raw_string_hashes)]
#![warn(clippy::no_effect_underscore_binding)]
#![warn(clippy::no_mangle_with_rust_abi)]
#![warn(clippy::option_as_ref_cloned)]
#![warn(clippy::option_option)]
#![warn(clippy::ptr_as_ptr)]
#![warn(clippy::ptr_cast_constness)]
#![warn(clippy::pub_underscore_fields)]
#![warn(clippy::range_minus_one)]
#![warn(clippy::range_plus_one)]
#![warn(clippy::redundant_closure_for_method_calls)]
#![warn(clippy::redundant_else)]
#![warn(clippy::ref_as_ptr)]
#![warn(clippy::ref_binding_to_reference)]
#![warn(clippy::ref_option)]
#![warn(clippy::ref_option_ref)]
#![warn(clippy::return_self_not_must_use)]
#![warn(clippy::same_functions_in_if_condition)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::should_panic_without_expect)] // TODO: Still needs considering.
#![allow(clippy::similar_names)] // TODO: Still needs considering.
#![warn(clippy::single_char_pattern)]
#![warn(clippy::single_match_else)]
#![warn(clippy::stable_sort_primitive)]
#![warn(clippy::str_split_at_newline)]
#![warn(clippy::string_add_assign)]
#![warn(clippy::struct_excessive_bools)]
#![warn(clippy::struct_field_names)]
#![warn(clippy::too_many_lines)]
#![warn(clippy::transmute_ptr_to_ptr)]
#![warn(clippy::trivially_copy_pass_by_ref)]
#![warn(clippy::unchecked_duration_subtraction)]
#![warn(clippy::unicode_not_nfc)]
#![allow(clippy::uninlined_format_args)] // TODO: Still needs considering.
#![warn(clippy::unnecessary_box_returns)]
#![warn(clippy::unnecessary_join)]
#![warn(clippy::unnecessary_literal_bound)]
#![warn(clippy::unnecessary_wraps)]
#![warn(clippy::unnested_or_patterns)]
#![allow(clippy::unreadable_literal)] // TODO: Still needs considering.
#![warn(clippy::unsafe_derive_deserialize)]
#![warn(clippy::unused_async)]
#![warn(clippy::unused_self)]
#![warn(clippy::used_underscore_binding)]
#![warn(clippy::used_underscore_items)]
#![warn(clippy::verbose_bit_mask)]
#![warn(clippy::wildcard_imports)]
#![warn(clippy::zero_sized_map_values)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod amount;
pub mod block;
pub mod fee_rate;
pub mod locktime;
pub mod parse;
pub mod weight;

#[doc(inline)]
#[rustfmt::skip]
pub use self::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockInterval},
    fee_rate::FeeRate,
    weight::Weight
};
