use super::{Encoder, VarIntEncoder, BufWrite};

pub trait EncodeTc<'a> {
    type Encoder: Encoder;
}

pub trait Encode: for<'a> EncodeTc<'a> {
    /// Minimum number of bytes needed to encode this value.
    const MIN_ENCODED_LEN: usize;
    /// True if the encoded length is known, false if not.
    const IS_KNOWN_LEN: bool;

    /// Creates an encoder producing conensus-encoded `Self`.
    fn encoder(&self) -> <Self as EncodeTc<'_>>::Encoder;

    fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize);

    fn reserve_suggestion(&self, max_steps: usize) -> (usize, usize) {
        if Self::IS_KNOWN_LEN {
            debug_assert_eq!(self.dyn_encoded_len(usize::MAX).0, 0);
            (Self::MIN_ENCODED_LEN, max_steps)
        } else {
            let (len, max_steps) = self.dyn_encoded_len(max_steps);
            (Self::MIN_ENCODED_LEN + len, max_steps)
        }
    }

    fn count_consensus_bytes(&self) -> usize {
        if Self::IS_KNOWN_LEN {
            Self::MIN_ENCODED_LEN
        } else {
            let mut encoder = self.encoder();
            let mut total = 0;
            while !encoder.encoded_chunk().is_empty() {
                total += encoder.encoded_chunk().len();
                if !encoder.next() {
                    break;
                }
            }
            total
        }
    }

    /// Consensus-encodes the value and stores the bytes in a vec.
    #[cfg(feature = "alloc")]
    fn consensus_encode_to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::with_capacity(self.reserve_suggestion(20).0);
        self.encoder().write_to_vec(&mut buf);
        buf
    }

    /// Consensus-encodes the value and writes it into a buffered `std` writer.
    ///
    /// # Errors
    ///
    /// This only returns errors originating from the passed-in `writer`.
    #[cfg(feature = "std")]
    fn consensus_encode<W: std::io::Write + BufWrite>(&self, writer: &mut W) -> std::io::Result<()> {
        self.encoder().write_all_sync(writer)
    }

    /// Feeds the consensus-encoded data into the hash engine.
    #[cfg(feature = "hashes")]
    fn consensus_encode_to_hash_engine<E: hashes::HashEngine>(&self, engine: &mut E) {
        self.encoder().hash_to_engine(engine)
    }

    /// Returns the hash of consensus data.
    #[cfg(feature = "hashes")]
    fn hash_consensus_encoded<H: hashes::GeneralHash>(&self) -> H {
        self.encoder().hash()
    }
}

pub trait EncoderExt: Encoder {
    #[cfg(feature = "hashes")]
    fn hash<H: hashes::GeneralHash>(self) -> H {
        let mut engine = H::engine();
        self.hash_to_engine(&mut engine);
        H::from_engine(engine)
    }

    #[cfg(feature = "hashes")]
    fn hash_to_engine<E: hashes::HashEngine>(mut self, engine: &mut E) {
        while !self.encoded_chunk().is_empty() {
            engine.input(self.encoded_chunk());
            if !self.next() {
                break;
            }
        }
    }
}

impl<T: Encoder> EncoderExt for T {}

#[macro_export]
macro_rules! gat_like {
    (impl$(<$($bounded_gen:tt)*>)? Encode for $value:ty { type Encoder<$lifetime:lifetime> = $encoder:ty $(where Self: $bound_lifetime:lifetime)?; const MIN_ENCODED_LEN: usize = $min_len:expr; const IS_KNOWN_LEN: bool = $is_known_len:expr; $(#[$($constructor_attr:tt)*])* fn encoder(&$self:ident) -> Self::Encoder<'_> { $($encoder_constructor:tt)* } $($remaining:tt)* }) => {
        $(
            // Idea copied from the static-cond crate.
            macro_rules! __bitcoin_consensus_encoding_check_lifetimes {
                ($lifetime, $lifetime) => {};
                ($lifetime, $bound_lifetime) => { compile_error!("The lifetime in the `where Self: '` bound doesn't match the one in \"GAT\""); };
            }

            __bitcoin_consensus_encoding_check_lifetimes!($lifetime, $bound_lifetime);
        )?

        impl<$lifetime $(, $($bounded_gen)*)?> $crate::EncodeTc<$lifetime> for $value {
            type Encoder = $encoder;
        }

        impl$(<$($bounded_gen)*>)? $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = $min_len;
            const IS_KNOWN_LEN: bool = $is_known_len;

            $(#[$($constructor_attr)*])*
            fn encoder(&$self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                $($encoder_constructor)*
            }

            $($remaining)*
        }
    }
}

pub use push_decode::encoders::IntEncoder;

// Note: this horrible macro is required because Rust doesn't allow generating match arms directly.
// Stolen from https://users.rust-lang.org/t/how-to-generate-in-macro/56774/4
#[doc(hidden)]
#[macro_export]
macro_rules! impl_struct_encode_next {
    ($self:expr, $state:ident $(, ($field:ident, $variant:ident))*) => {
        $crate::impl_struct_encode_next!(@($self, $state $(, ($field, $variant))*))
    };
    (@($self:expr, $state:ident, ($field:ident, $variant:ident)) $($arms:tt)*) => {
        match &mut $self.state {
            $($arms)*
            $state::$variant (encoder) => encoder.next()
        }
    };
    (@($self:expr, $state:ident, ($field:ident, $variant:ident), ($next_field:ident, $next_variant:ident) $(, ($remaining_fields:ident, $remaining_variants:ident))*) $($arms:tt)*) => {
        $crate::impl_struct_encode_next! {
            @($self, $state, ($field, $next_variant) $(, ($remaining_fields, $remaining_variants))*)
                $($arms)*

                $state::$variant (encoder) => {
                    if encoder.next() {
                        true
                    } else {
                        let encoder = $crate::Encode::encoder(&$self.value.$next_field);
                        $self.state = $state::$next_variant(encoder);
                        true
                    }
                }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_struct_encode_encoder_constructor {
    ($encoder:ident, $encoder_state:ident, $variant:ident, $field:ident $(, $($whatever:tt)*)?) => {
        fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
            $encoder {
                value: self,
                state: $encoder_state::$variant(self.$field.encoder()),
            }
        }
    }
}

/// Implements [`EncodeTc`], [`Encode`] and a [`Encoder`] for given structured type.
///
/// This is for types where each field is directly encoded, in order.
///
/// WARNING: currently doens't work if any of the fields produces empty serialization.
#[macro_export]
macro_rules! impl_struct_encode {
    ($value:ty => $encoder_vis:vis struct $encoder:ident { $($(#[$($variant_attr:tt)*])* $variant:ident { $field:ident: $ty:ty }),+ $(,)? } enum $encoder_state:ident<'_> { ... }) => {

        #[doc = "Encoder of [`"]
        #[doc = stringify!($value)]
        #[doc = "`]\n"]
        #[doc = "\n"]
        #[doc = "For more information about encoders check the `Encoder` trait"]
        $encoder_vis struct $encoder<'a> {
            value: &'a $value,
            state: $encoder_state<'a>,
        }

        enum $encoder_state<'a> {
            $($variant(<$ty as $crate::EncodeTc<'a>>::Encoder),)*
        }

        impl<'a> $crate::EncodeTc<'a> for $value {
            type Encoder = $encoder<'a>;
        }

        impl $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = 0 $(+ <$ty as $crate::Encode>::MIN_ENCODED_LEN)*;
            const IS_KNOWN_LEN: bool = true $(&& <$ty as $crate::Encode>::IS_KNOWN_LEN)*;

            $crate::impl_struct_encode_encoder_constructor!($encoder, $encoder_state, $($variant, $field),*);

            fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                if Self::IS_KNOWN_LEN {
                    (0, max_steps)
                } else {
                    if max_steps == 0 {
                        return (0, 0);
                    }

                    let mut total = 0;
                    $(
                        // This avoids reliance on inlining to optimize-out calls to
                        // dyn_encoded_len for known-len types.
                        let max_steps = if <$ty as $crate::Encode>::IS_KNOWN_LEN {
                            max_steps
                        } else {
                            let (len, max_steps) = $crate::Encode::dyn_encoded_len(&self.$field, max_steps - 1);
                            total += len;
                            if max_steps == 0 {
                                return (total, 0);
                            }
                            max_steps
                        };
                    )+
                    (total, max_steps)
                }
            }
        }

        impl $crate::Encoder for $encoder<'_> {
            fn encoded_chunk(&self) -> &[u8] {
                match &self.state {
                    $(
                        $encoder_state::$variant(state) => $crate::Encoder::encoded_chunk(state),
                    )*
                }
            }

            fn next(&mut self) -> bool {
                $crate::impl_struct_encode_next!(self, $encoder_state $(, ($field, $variant))*)
            }
        }
    }
}

/// Creates a newtype for an encoder.
///
/// Has three levels:
///
/// * Just the encoders struct (without specifying `$value`)
/// * The encoder struct and `EncodeTc` (without `map ...`)
/// * Full implementation - uses conversion to an intermediate type
#[macro_export]
macro_rules! encoder_newtype {
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident<$lifetime:lifetime>($inner:ty);) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`]\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $vis struct $encoder<$lifetime>($inner);
        }

        impl<$lifetime> $crate::EncodeTc<$lifetime> for $value {
            type Encoder = $encoder<$lifetime>;
        }
    };
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident($inner:ty);) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`]\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $vis struct $encoder($inner);
        }

        impl<'a> $crate::EncodeTc<'a> for $value {
            type Encoder = $encoder;
        }
    };
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident<$lifetime:lifetime>($inner:ty) map $intermediate:ty as $fun:expr;) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`].\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $value => $vis struct $encoder<$lifetime>($inner);
        }

        impl $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = <$intermediate as $crate::Encode>::MIN_ENCODED_LEN;
            const IS_KNOWN_LEN: bool = <$intermediate as $crate::Encode>::IS_KNOWN_LEN;

            fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                $encoder($crate::Encode::encoder(&($fun)(self)))
            }

            fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                $crate::Encode::dyn_encoded_len((&$fun)(self), max_steps)
            }
        }
    };
    ($(#[$($attr:tt)*])* $value:ty => $vis:vis struct $encoder:ident($inner:ty) map $intermediate:ty as $fun:expr;) => {
        $crate::encoder_newtype! {
            #[doc = "Encoder of [`"]
            #[doc = stringify!($value)]
            #[doc = "`].\n"]
            #[doc = "\n"]
            #[doc = "For more information about encoders check the `Encoder` trait"]
            $(#[$($attr)*])*
            $value => $vis struct $encoder($inner);
        }

        impl $crate::Encode for $value {
            const MIN_ENCODED_LEN: usize = <$intermediate as $crate::Encode>::MIN_ENCODED_LEN;
            const IS_KNOWN_LEN: bool = <$intermediate as $crate::Encode>::IS_KNOWN_LEN;

            fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                $encoder($crate::Encode::encoder(&($fun)(self)))
            }

            fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                $crate::Encode::dyn_encoded_len(&($fun)(self), max_steps)
            }
        }
    };
    ($(#[$($attr:tt)*])* $vis:vis struct $encoder:ident<$lifetime:lifetime>($inner:ty);) => {
        $(#[$($attr)*])*
        $vis struct $encoder<$lifetime>($inner);

        impl<$lifetime> $crate::Encoder for $encoder<$lifetime> {
            fn encoded_chunk(&self) -> &[u8] {
                $crate::Encoder::encoded_chunk(&self.0)
            }

            fn next(&mut self) -> bool {
                $crate::Encoder::next(&mut self.0)
            }
        }
    };
    ($(#[$($attr:tt)*])* $vis:vis struct $encoder:ident($inner:ty);) => {
        $(#[$($attr)*])*
        $vis struct $encoder($inner);

        impl $crate::Encoder for $encoder {
            fn encoded_chunk(&self) -> &[u8] {
                $crate::Encoder::encoded_chunk(&self.0)
            }

            fn next(&mut self) -> bool {
                $crate::Encoder::next(&mut self.0)
            }
        }
    };
}

/// Implements `Encode` and a `Encoder` for given hash type.
///
/// This directly reads the appropriate amount of bytes without transformation.
#[cfg(feature = "hashes")]
#[macro_export]
macro_rules! hash_encoder {
    ($($hash_type:ty;)*) => {
        $(
            impl<'a> $crate::EncodeTc<'a> for $hash_type {
                // We intentionally use array rather than slice to get a thin pointer.
                type Encoder = $crate::push_decode::encoders::BytesEncoder<&'a <$hash_type as $crate::hashes::Hash>::Bytes>;
            }

            impl $crate::Encode for $hash_type {
                const MIN_ENCODED_LEN: usize = <Self as $crate::hashes::Hash>::LEN;
                const IS_KNOWN_LEN: bool = true;

                fn encoder(&self) -> <Self as $crate::EncodeTc<'_>>::Encoder {
                    $crate::push_decode::encoders::BytesEncoder::new(self.as_byte_array())
                }

                fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
                    (0, max_steps)
                }
            }
        )*
    }
}

pub type SliceEncoder<'a, T> = IterEncoder<'a, T, core::slice::Iter<'a, T>>;

pub struct IterEncoder<'a, T: Encode + 'a, I: Iterator<Item=&'a T> + ExactSizeIterator>(push_decode::encoders::combinators::Chain<VarIntEncoder, UnprefixedIterEncoder<'a, T, I>>);

impl<'a, T: Encode + 'a, I: Iterator<Item=&'a T> + ExactSizeIterator> IterEncoder<'a, T, I> {
    pub fn new<U: IntoIterator<IntoIter=I>>(iter: U) -> Self {
        let iter = iter.into_iter();
        let first_encoder = VarIntEncoder::new(iter.len() as u64);
        let second_encoder = UnprefixedIterEncoder::new(iter);

        IterEncoder(first_encoder.chain(second_encoder))
    }

    pub fn dyn_len(iter: impl IntoIterator<IntoIter=I>, max_steps: usize) -> (usize, usize) {
        let iter = iter.into_iter();
        let (varint_len, max_steps) = VarIntEncoder::dyn_encoded_len(iter.len() as u64, max_steps);
        if max_steps == 0 {
            return (varint_len, 0);
        }
        let (data_len, max_steps) = UnprefixedIterEncoder::dyn_len(iter, max_steps - 1);
        (data_len + varint_len, max_steps)
    }
}

pub struct UnprefixedIterEncoder<'a, T: Encode, I: Iterator<Item=&'a T>>(InnerIterEncoder<'a, T, I>);

impl<'a, T: Encode + 'a, I: Iterator<Item=&'a T> + ExactSizeIterator> UnprefixedIterEncoder<'a, T, I> {
    pub fn new<U: IntoIterator<IntoIter=I>>(iter: U) -> Self {
        let mut iter = iter.into_iter().fuse();
        // Empty elements must be skipped
        let state = loop {
            match iter.next() {
                Some(first) => {
                    let encoder = first.encoder();
                    if !encoder.encoded_chunk().is_empty() {
                        break InnerIterEncoder::Encoding { current: encoder, remaining: iter };
                    }
                },
                None => break InnerIterEncoder::Done,
            }
        };
        Self(state)
    }

    pub fn dyn_len(iter: impl IntoIterator<IntoIter=I>, mut max_steps: usize) -> (usize, usize) {
        let iter = iter.into_iter();
        if max_steps == 0 {
            return (0, 0);
        }
        let mut total = T::MIN_ENCODED_LEN * iter.len();
        max_steps -= 1;
        if !T::IS_KNOWN_LEN {
            for element in iter {
                let (len, new_max_steps) = element.dyn_encoded_len(max_steps);
                total += len;
                if new_max_steps == 0 {
                    return (total, 0);
                }
                max_steps = new_max_steps;
            }
        }
        (total, max_steps)
    }
}

impl<'a, T: Encode, I: Iterator<Item=&'a T> + ExactSizeIterator> Encoder for IterEncoder<'a, T, I> {
    fn encoded_chunk(&self) -> &[u8] {
        self.0.encoded_chunk()
    }

    fn next(&mut self) -> bool {
        self.0.next()
    }
}

enum InnerIterEncoder<'a, T: Encode + 'a, I: Iterator<Item=&'a T>> {
    Encoding { current: <T as EncodeTc<'a>>::Encoder, remaining: core::iter::Fuse<I> },
    Done,
}

impl<'a, T: Encode, I: Iterator<Item=&'a T>> Encoder for UnprefixedIterEncoder<'a, T, I> {
    fn encoded_chunk(&self) -> &[u8] {
        match &self.0 {
            InnerIterEncoder::Encoding { current, .. } => current.encoded_chunk(),
            InnerIterEncoder::Done => &[],
        }
    }

    fn next(&mut self) -> bool {
        match &mut self.0 {
            InnerIterEncoder::Encoding { current, remaining } => {
                if current.next() {
                    true
                } else {
                    loop {
                        match remaining.next() {
                            Some(next) => {
                                *current = next.encoder();
                                if !current.encoded_chunk().is_empty() {
                                    break true;
                                }
                            },
                            None => {
                                self.0 = InnerIterEncoder::Done;
                                break false;
                            }
                        }
                    }
                }
            },
            InnerIterEncoder::Done => false,
        }
    }
}

