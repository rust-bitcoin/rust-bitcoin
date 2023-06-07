//! Contains helpers for parsing-related errors.

/// Creates an error type intended for string parsing errors.
///
/// The resulting error type has two fields: `input` and `source`. The type of `input` is
/// [`InputString`](super::InputString), the type of `source` is specified as the second argument
/// to the macro.
///
/// The resulting type is public, conditionally implements [`std::error::Error`] and has a private
/// `new()` method for convenience.
///
/// ## Parameters
///
/// * `name` - the name of the error type
/// * `source` - the type of the source type
/// * `subject` - English description of the type being parsed (e.g. "a bitcoin amount")
/// * `derive` - list of derives to add
#[macro_export]
macro_rules! parse_error_type {
    ($vis:vis $name:ident, $source:ty, $subject:expr $(, $derive:path)* $(,)?) => {
        #[derive(Debug $(, $derive)*)]
        $vis struct $name {
            input: $crate::error::InputString,
            source: $source,
        }

        impl $name {
            /// Creates `Self`.
            fn new<T: Into<$crate::error::InputString>>(input: T, source: $source) -> Self {
                $name {
                    input: input.into(),
                    source,
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                $crate::error::write_err!("{}", self.input.display_cannot_parse($subject); self.source)
            }
        }

        $crate::error::impl_std_error!($name, source);
    }
}
