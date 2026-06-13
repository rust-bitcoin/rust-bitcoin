// SPDX-License-Identifier: CC0-1.0

/// Constructs a newtype wrapper around an inner [`encoding::Decoder`] type.
///
/// The generated struct wraps an inner decoder and implements [`encoding::Decoder`] by delegating
/// `push_bytes` and `read_limit` to the inner decoder, then transforming the result in `end`.
///
/// ## Required items
///
/// * **Struct definition** - declares the newtype with its inner decoder type.
/// * `fn end` - receives the `Result` returned by the inner decoder's `end` method (i.e.
///   `Result<InnerOutput, InnerError>`) and must return a `Result<Output, Error>` for the
///   newtype decoder.
///
/// ## Optional items
///
/// * `fn new` - a custom constructor. If provided, this macro also generates a [`Default`]
///   impl that calls through to `new()`. You may specify any visibility and/or make the function
///   const. If omitted, the resulting type will not have a new function or a [`Default`] impl.
/// * `fn map_push_bytes_err` - a custom error mapping function to tranform any error from the inner
///   decoder's `push_bytes` to the wrapper decoder's error type. If omitted, the macro assumes
///   the error type is a single value newtype that directly wraps the inner error.
///
/// Both `fn new` and `fn map_push_bytes_err` are independently optional, giving four possible forms.
/// Due to limitations in macros, the order must be `new`, `push_bytes_err`, then `end`.
///
/// ## Attributes
///
/// You can add arbitrary doc comments or attributes to the struct definition and the new function.
/// Note that the new function always has #[inline].
///
/// # Examples
///
/// Minimal form (no `new`, no `push_bytes_err`):
///
/// ```ignore
/// decoder_newtype! {
///     /// The decoder for the [`Block`] type.
///     pub struct BlockDecoder(BlockInnerDecoder);
///
///     fn end(
///         result: Result<(Header, Vec<Transaction>), <BlockInnerDecoder as Decoder>::Error>
///     ) -> Result<Block, BlockDecoderError> {
///         let (header, transactions) = result.map_err(BlockDecoderError)?;
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
///     fn end(result: Result<[u8; 4], encoding::UnexpectedEofError>) -> Result<BlockHeight, BlockHeightDecoderError> {
///         let value = result.map_err(BlockHeightDecoderError)?;
///         let n = u32::from_le_bytes(value);
///         Ok(BlockHeight::from_u32(n))
///     }
/// }
/// ```
///
/// With a custom `push_bytes` error mapping:
///
/// ```ignore
/// decoder_newtype! {
///     /// The decoder for the [`Header`] type.
///     pub struct HeaderDecoder(HeaderInnerDecoder);
///
///     fn map_push_bytes_err(err: <HeaderInnerDecoder as Decoder>::Error) -> HeaderDecoderError {
///         Self::from_inner(err)
///     }
///
///     fn end(
///         result: Result<<HeaderInnerDecoder as Decoder>::Output, <HeaderInnerDecoder as Decoder>::Error>
///     ) -> Result<Header, HeaderDecoderError> {
///         let (version, prev_blockhash, merkle_root, time, bits, nonce) = result.map_err(Self::from_inner)?;
///         let nonce = u32::from_le_bytes(nonce);
///         Ok(Header { version, prev_blockhash, merkle_root, time, bits, nonce })
///     }
/// }
/// ```
macro_rules! decoder_newtype {
    // Arm 1: without new, without push_bytes_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        fn end($result_name:ident: $result_ty:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            (err: <$decoder as encoding::Decoder>::Error) -> $err { $err(err) }
            ($result_name: $result_ty) -> Result<$output, $err> $end_impl
        }
    };
    // Arm 2: with new, without push_bytes_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        $(#[$($new_attr:tt)*])*
        $new_vis:vis $(const $($const:block)?)? fn new() -> Self $new_impl:block

        fn end($result_name:ident: $result_ty:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            (err: <$decoder as encoding::Decoder>::Error) -> $err { $err(err) }
            ($result_name: $result_ty) -> Result<$output, $err> $end_impl

            $(#[$($new_attr)*])*
            $new_vis $(const $($const)?)? fn new() -> Self $new_impl
        }
    };
    // Arm 3: without new, with push_bytes_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        fn map_push_bytes_err($err_var:ident: $inner_err:ty) -> $err_name:ident $on_err_impl:block
        fn end($result_name:ident: $result_ty:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            ($err_var: $inner_err) -> $err_name $on_err_impl
            ($result_name: $result_ty) -> Result<$output, $err> $end_impl
        }
    };
    // Arm 4: with new, with push_bytes_err
    (
        $(#[$($struct_attr:tt)*])*
        $vis:vis struct $name:ident($decoder:ty);

        $(#[$($new_attr:tt)*])*
        $new_vis:vis $(const $($const:block)?)? fn new() -> Self $new_impl:block

        fn map_push_bytes_err($err_var:ident: $inner_err:ty) -> $err_name:ident $on_err_impl:block
        fn end($result_name:ident: $result_ty:ty) -> Result<$output:ty, $err:ident> $end_impl:block
    ) => {
        crate::_decoder_newtype_internal! {
            $(#[$($struct_attr)*])*
            $vis struct $name($decoder);

            ($err_var: $inner_err) -> $err_name $on_err_impl
            ($result_name: $result_ty) -> Result<$output, $err> $end_impl

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
        ($result_name:ident: $result_ty:ty) -> Result<$output:ty, $err:ident> $end_impl:block

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
            /// Only used by the `push_bytes` method.
            #[inline]
            fn push_bytes_map_err($err_var: $inner_err) -> $err $on_err_impl
        }

        impl encoding::Decoder for $name {
            type Output = $output;
            type Error = $err;

            #[inline]
            fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
                self.0.push_bytes(bytes).map_err(Self::push_bytes_map_err)
            }

            #[inline]
            fn end(self) -> Result<Self::Output, Self::Error> {
                let end = |$result_name: $result_ty| $end_impl;
                end(self.0.end())
            }

            #[inline]
            fn read_limit(&self) -> usize { self.0.read_limit() }
        }
    };
}
pub(crate) use _decoder_newtype_internal;
