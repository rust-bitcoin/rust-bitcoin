// SPDX-License-Identifier: CC0-1.0

/// Defines a flat, named error enum for a composite [`Decoder`](encoding::Decoder) and the
/// conversion that flattens its positional `DecoderNError` into it.
///
/// The pattern is otherwise written out by hand (see e.g. `HeaderDecoderError`): rather than
/// declaring the enum plus `From<Infallible>`, `Display`, [`std::error::Error`] and a positional
/// `match` by hand, list `field => Variant` pairs together with the composite decoder they come
/// from.
///
/// We infer the inner error type for the N variant via <D as Decoder>::Error, that way we wont have it
/// being spelled out.
///
/// A dropped, duplicated or mistyped field fails to compile, because The generated `From` is a
/// single exhaustive `match` over `DecoderNError`, so a dropped/ mistyped/duplicated field
/// will fail to complie.
/// The generated `Display` reports the field name (``error decoding `script_sig` field``).
///
macro_rules! decoder_error {
    // ----- arity 2 -----
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident from Decoder2<$d0:ty, $d1:ty $(,)?> {
            $(#[$a0:meta])* $f0:ident => $v0:ident,
            $(#[$a1:meta])* $f1:ident => $v1:ident $(,)?
        }
    ) => {
        crate::decoder_error!(@build $(#[$attr])* $vis $name; Decoder2Error;
            (First,  [$(#[$a0])*], $f0, $v0, $d0),
            (Second, [$(#[$a1])*], $f1, $v1, $d1),
        );
    };
    // ----- arity 3 -----
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident from Decoder3<$d0:ty, $d1:ty, $d2:ty $(,)?> {
            $(#[$a0:meta])* $f0:ident => $v0:ident,
            $(#[$a1:meta])* $f1:ident => $v1:ident,
            $(#[$a2:meta])* $f2:ident => $v2:ident $(,)?
        }
    ) => {
        crate::decoder_error!(@build $(#[$attr])* $vis $name; Decoder3Error;
            (First,  [$(#[$a0])*], $f0, $v0, $d0),
            (Second, [$(#[$a1])*], $f1, $v1, $d1),
            (Third,  [$(#[$a2])*], $f2, $v2, $d2),
        );
    };
    // ----- arity 4 -----
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident from Decoder4<$d0:ty, $d1:ty, $d2:ty, $d3:ty $(,)?> {
            $(#[$a0:meta])* $f0:ident => $v0:ident,
            $(#[$a1:meta])* $f1:ident => $v1:ident,
            $(#[$a2:meta])* $f2:ident => $v2:ident,
            $(#[$a3:meta])* $f3:ident => $v3:ident $(,)?
        }
    ) => {
        crate::decoder_error!(@build $(#[$attr])* $vis $name; Decoder4Error;
            (First,  [$(#[$a0])*], $f0, $v0, $d0),
            (Second, [$(#[$a1])*], $f1, $v1, $d1),
            (Third,  [$(#[$a2])*], $f2, $v2, $d2),
            (Fourth, [$(#[$a3])*], $f3, $v3, $d3),
        );
    };
    // ----- arity 6 -----
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident from Decoder6<$d0:ty, $d1:ty, $d2:ty, $d3:ty, $d4:ty, $d5:ty $(,)?> {
            $(#[$a0:meta])* $f0:ident => $v0:ident,
            $(#[$a1:meta])* $f1:ident => $v1:ident,
            $(#[$a2:meta])* $f2:ident => $v2:ident,
            $(#[$a3:meta])* $f3:ident => $v3:ident,
            $(#[$a4:meta])* $f4:ident => $v4:ident,
            $(#[$a5:meta])* $f5:ident => $v5:ident $(,)?
        }
    ) => {
        crate::decoder_error!(@build $(#[$attr])* $vis $name; Decoder6Error;
            (First,  [$(#[$a0])*], $f0, $v0, $d0),
            (Second, [$(#[$a1])*], $f1, $v1, $d1),
            (Third,  [$(#[$a2])*], $f2, $v2, $d2),
            (Fourth, [$(#[$a3])*], $f3, $v3, $d3),
            (Fifth,  [$(#[$a4])*], $f4, $v4, $d4),
            (Sixth,  [$(#[$a5])*], $f5, $v5, $d5),
        );
    };

    // ----- shared codegen -----
    (@build
        $(#[$attr:meta])* $vis:vis $name:ident; $errenum:ident;
        $( ($wrap:ident, [$(#[$fattr:meta])*], $field:ident, $variant:ident, $dec:ty) ),* $(,)?
    ) => {
        $(#[$attr])*
        $vis enum $name {
            $(
                $(#[$fattr])*
                $variant( <$dec as encoding::Decoder>::Error ),
            )*
        }

        impl ::core::convert::From< encoding::$errenum< $( <$dec as encoding::Decoder>::Error ),* > >
            for $name
        {
            fn from(e: encoding::$errenum< $( <$dec as encoding::Decoder>::Error ),* >) -> Self {
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
