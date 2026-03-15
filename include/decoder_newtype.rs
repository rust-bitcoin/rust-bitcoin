// SPDX-License-Identifier: CC0-1.0

/// Constructs a newtype wrapper around an inner [`Decoder`] type.
///
/// The generated struct wraps an inner decoder and implements [`Decoder`] by delegating
/// `push_bytes` and `read_limit` to the inner decoder, then transforming the output in `end`.
///
/// # Required items
///
/// * **Struct definition** - declares the newtype with its inner decoder type.
/// * `fn end` - transforms the inner decoder's output into the final output type. This is
///   called after the inner decoder finishes and must return a `Result`.
///
/// # Optional items
///
/// * `fn new` - a custom constructor. If provided, this macro also generates a [`Default`]
///   impl that calls through to `new()`. You may specify any visibility and/or make the function
///   const. If omitted, the resulting type will not have a new function or a [`Default`] impl.
/// * `fn on_err` - a custom error mapping function. When provided, this controls how the
///   inner decoder's error type is converted into the newtype's error type. When omitted, the
///   macro assumes the error type is a single value newtype that directly wraps the inner error.
///
/// Both `fn new` and `fn on_err` are independently optional, giving four possible forms.
/// Due to limitations in macro technology, the order must be `new`, `on_err`, then `end`.
///
/// # Attributes
///
/// You can add arbitrary doc comments or attributes to the struct definition and the new function.
/// Note that the new function always has #[inline].
///
/// # Examples
///
/// Minimal form (no `new`, no `on_err`):
///
/// ```ignore
/// decoder_newtype! {
///     /// The decoder for the [`Block`] type.
///     pub struct BlockDecoder(BlockInnerDecoder);
///
///     fn end(value: (Header, Vec<Transaction>)) -> Result<Block, BlockDecoderError> {
///         let (header, transactions) = value;
///         Ok(Block::new_unchecked(header, transactions))
///     }
/// }
/// ```
///
/// With a custom constructor:
///
/// ```ignore
/// decoder_newtype! {
///     /// The decoder for the [`BlockHeight`] type.
///     pub struct BlockHeightDecoder(encoding::ArrayDecoder<4>);
///
///     /// Constructs a new [`BlockHeight`] decoder.
///     pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
///
///     fn end(value: [u8; 4]) -> Result<BlockHeight, BlockHeightDecoderError> {
///         let n = u32::from_le_bytes(value);
///         Ok(BlockHeight::from_u32(n))
///     }
/// }
/// ```
///
/// With a custom error mapping:
///
/// ```ignore
/// decoder_newtype! {
///     /// The decoder for the [`Header`] type.
///     pub struct HeaderDecoder(HeaderInnerDecoder);
///
///     fn on_err(err: <HeaderInnerDecoder as Decoder>::Error) -> HeaderDecoderError {
///         Self::from_inner(err)
///     }
///
///     fn end(value: <HeaderInnerDecoder as Decoder>::Output) -> Result<Header, HeaderDecoderError> {
///         let (version, prev_blockhash, merkle_root, time, bits, nonce) = value;
///         let nonce = u32::from_le_bytes(nonce);
///         Ok(Header { version, prev_blockhash, merkle_root, time, bits, nonce })
///     }
/// }
/// ```
///
/// [`Decoder`]: encoding::Decoder
macro_rules! decoder_newtype {
    // Arm 1: without new, without on_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        fn end($value_name:ident: $inner_decoder_out:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            (err: <$decoder as encoding::Decoder>::Error) -> $err { $err(err) }
            ($value_name: $inner_decoder_out) -> Result<$output, $err> $end_impl
        }
    };
    // Arm 2: with new, without on_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        $(#[$($new_attr:tt)*])*
        $new_vis:vis $(const $($const:block)?)? fn new() -> Self $new_impl:block

        fn end($value_name:ident: $inner_decoder_out:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            (err: <$decoder as encoding::Decoder>::Error) -> $err { $err(err) }
            ($value_name: $inner_decoder_out) -> Result<$output, $err> $end_impl

            $(#[$($new_attr)*])*
            $new_vis $(const $($const)?)? fn new() -> Self $new_impl
        }
    };
    // Arm 3: without new, with on_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        fn on_err($err_var:ident: $inner_err:ty) -> $err_name:ident $on_err_impl:block
        fn end($value_name:ident: $inner_decoder_out:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            ($err_var: $inner_err) -> $err_name $on_err_impl
            ($value_name: $inner_decoder_out) -> Result<$output, $err> $end_impl
        }
    };
    // Arm 4: with new, with on_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        $(#[$($new_attr:tt)*])*
        $new_vis:vis $(const $($const:block)?)? fn new() -> Self $new_impl:block

        fn on_err($err_var:ident: $inner_err:ty) -> $err_name:ident $on_err_impl:block
        fn end($value_name:ident: $inner_decoder_out:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            ($err_var: $inner_err) -> $err_name $on_err_impl
            ($value_name: $inner_decoder_out) -> Result<$output, $err> $end_impl

            $(#[$($new_attr)*])*
            $new_vis $(const $($const)?)? fn new() -> Self $new_impl
        }
    };
}
pub(crate) use decoder_newtype;

// Due to macro ambiguity, the new needs to go at the end.
macro_rules! _decoder_newtype_internal {
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        ($err_var:ident: $inner_err:ty) -> $err_name:ident $on_err_impl:block
        ($value_name:ident: $inner_decoder_out:ty) -> Result<$output:ty, $err:ident> $end_impl:block

        $(
            $(#[$($new_attr:tt)*])*
            $new_vis:vis $(const $($const:block)?)? fn new() -> Self $new_impl:block
        )?
    ) => {
        $(#[$($struct_attr)*])*
        $vis struct $name($decoder);

        $(
            impl Default for $name {
                #[inline]
                fn default() -> Self { Self::new() }
            }

            impl $name {
                $(#[$($new_attr)*])*
                #[inline]
                $new_vis $(const $($const)?)? fn new() -> Self $new_impl
            }
        )?

        impl $name {
            /// INTERNAL ONLY: Converts an inner decoder error into the correct error type.
            /// Needed because we don't want to have a From impl in the public API just for this.
            fn map_err($err_var: $inner_err) -> $err $on_err_impl
        }

        impl encoding::Decoder for $name {
            type Output = $output;
            type Error = $err;

            #[inline]
            fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
                self.0.push_bytes(bytes).map_err(Self::map_err)
            }

            #[inline]
            fn end(self) -> Result<Self::Output, Self::Error> {
                let end = |$value_name: $inner_decoder_out| $end_impl;
                end(self.0.end().map_err(Self::map_err)?)
            }

            #[inline]
            fn read_limit(&self) -> usize { self.0.read_limit() }
        }
    };
}
pub(crate) use _decoder_newtype_internal;
