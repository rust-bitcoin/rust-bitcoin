// SPDX-License-Identifier: CC0-1.0

/// Defines a flat, named error enum for a composite [`Decoder`](encoding::Decoder) and the
/// conversion that flattens its positional `DecoderNError` into it.
///
/// The pattern is otherwise written out by hand (see e.g. `HeaderDecoderError`): rather than
/// declaring the enum plus `From<Infallible>`, `Display`, [`std::error::Error`] and a positional
/// `match` by hand, list `field: ErrorType => Variant` entries together with the composite decoder
/// they come from.
///
/// Each entry names its error type explicitly rather than having the macro infer it as
/// `<D as Decoder>::Error`. The inferred form is shorter to write, but it is what ends up in
/// rustdoc and in the checked-in API files, where a variant is far more useful spelled
/// `Bits(CompactTargetDecoderError)` than `Bits(<CompactTargetDecoder as Decoder>::Error)`. The
/// two cannot drift: the generated code statically asserts that each named error type really is
/// the associated error type of the decoder in that position.
///
/// The generated flattening is a single exhaustive `match` over `DecoderNError`, so a dropped,
/// mistyped or duplicated field will fail to compile. It is a private constructor rather than a
/// `From` impl, so flattening an encoding-internal positional error stays an implementation
/// detail instead of becoming public API.
///
/// The generated `Display` reports the field name (``error decoding `script_sig` field``).
macro_rules! decoder_error {
    // ----- arity 2 -----
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident from Decoder2<$d0:ty, $d1:ty $(,)?> {
            $(#[$a0:meta])* $f0:ident: $e0:ty => $v0:ident,
            $(#[$a1:meta])* $f1:ident: $e1:ty => $v1:ident $(,)?
        }
    ) => {
        crate::decoder_error!(@build $(#[$attr])* $vis $name; Decoder2Error;
            (First,  [$(#[$a0])*], $f0, $v0, $d0, $e0),
            (Second, [$(#[$a1])*], $f1, $v1, $d1, $e1),
        );
    };
    // ----- arity 3 -----
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident from Decoder3<$d0:ty, $d1:ty, $d2:ty $(,)?> {
            $(#[$a0:meta])* $f0:ident: $e0:ty => $v0:ident,
            $(#[$a1:meta])* $f1:ident: $e1:ty => $v1:ident,
            $(#[$a2:meta])* $f2:ident: $e2:ty => $v2:ident $(,)?
        }
    ) => {
        crate::decoder_error!(@build $(#[$attr])* $vis $name; Decoder3Error;
            (First,  [$(#[$a0])*], $f0, $v0, $d0, $e0),
            (Second, [$(#[$a1])*], $f1, $v1, $d1, $e1),
            (Third,  [$(#[$a2])*], $f2, $v2, $d2, $e2),
        );
    };
    // ----- arity 6 -----
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident from Decoder6<$d0:ty, $d1:ty, $d2:ty, $d3:ty, $d4:ty, $d5:ty $(,)?> {
            $(#[$a0:meta])* $f0:ident: $e0:ty => $v0:ident,
            $(#[$a1:meta])* $f1:ident: $e1:ty => $v1:ident,
            $(#[$a2:meta])* $f2:ident: $e2:ty => $v2:ident,
            $(#[$a3:meta])* $f3:ident: $e3:ty => $v3:ident,
            $(#[$a4:meta])* $f4:ident: $e4:ty => $v4:ident,
            $(#[$a5:meta])* $f5:ident: $e5:ty => $v5:ident $(,)?
        }
    ) => {
        crate::decoder_error!(@build $(#[$attr])* $vis $name; Decoder6Error;
            (First,  [$(#[$a0])*], $f0, $v0, $d0, $e0),
            (Second, [$(#[$a1])*], $f1, $v1, $d1, $e1),
            (Third,  [$(#[$a2])*], $f2, $v2, $d2, $e2),
            (Fourth, [$(#[$a3])*], $f3, $v3, $d3, $e3),
            (Fifth,  [$(#[$a4])*], $f4, $v4, $d4, $e4),
            (Sixth,  [$(#[$a5])*], $f5, $v5, $d5, $e5),
        );
    };

    // ----- shared codegen -----
    (@build
        $(#[$attr:meta])* $vis:vis $name:ident; $errenum:ident;
        $( ($wrap:ident, [$(#[$fattr:meta])*], $field:ident, $variant:ident, $dec:ty, $err:ty) ),* $(,)?
    ) => {
        $(#[$attr])*
        $vis enum $name {
            $(
                $(#[$fattr])*
                $variant($err),
            )*
        }

        // Ties the spelled-out error types back to the decoders they came from: this fails to
        // compile unless each `$err` is exactly `<$dec as Decoder>::Error`. The closure is only
        // ever type checked, never called.
        const _: fn() = || {
            fn assert_decoder_error<D: encoding::Decoder<Error = E>, E>() {}
            $( assert_decoder_error::<$dec, $err>(); )*
        };

        impl $name {
            /// Flattens the positional error of the composite decoder into this named enum.
            ///
            /// Kept private: the positional `DecoderNError` types are an implementation detail of
            /// the encoding crate and we do not want to commit to converting from them.
            pub(crate) fn from_inner(e: encoding::$errenum< $($err),* >) -> Self {
                match e {
                    $( encoding::$errenum::$wrap(e) => $name::$variant(e), )*
                }
            }
        }

        impl ::core::convert::From<::core::convert::Infallible> for $name {
            fn from(never: ::core::convert::Infallible) -> Self { match never {} }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    $(
                        // This is what `internals::write_err!` does, hand-inlined: that macro
                        // needs a literal format string and `stringify!($field)` is not one.
                        // Without `std` there is no `source()`, so the source is appended here
                        // instead of being lost.
                        $name::$variant(e) => {
                            #[cfg(feature = "std")]
                            { let _ = e; write!(f, "error decoding `{}` field", stringify!($field)) }
                            #[cfg(not(feature = "std"))]
                            { write!(f, "error decoding `{}` field: {}", stringify!($field), e) }
                        }
                    )*
                }
            }
        }

        #[cfg(feature = "std")]
        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $( $name::$variant(e) => Some(e), )*
                }
            }
        }
    };
}
pub(crate) use decoder_error;
