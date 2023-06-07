//! Implements the [`InputString`] type storing the parsed input.

use core::fmt;

use storage::Storage;

/// Conditionally stores the input string in parse errors.
///
/// This type stores the input string of a parse function depending on whether `alloc` feature is
/// enabled. When it is enabled, the string is stored inside as `String`. When disabled this is a
/// zero-sized type and attempt to store a string does nothing.
///
/// This provides two methods to format the error strings depending on the context.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InputString(Storage);

impl InputString {
    /// Displays a message saying `failed to parse <self> as <what>`.
    ///
    /// This is normally used whith the `write_err!` macro.
    pub fn display_cannot_parse<'a, T>(&'a self, what: &'a T) -> CannotParse<'a, T>
    where
        T: fmt::Display + ?Sized,
    {
        CannotParse { input: self, what }
    }

    /// Formats a message saying `<self> is not a known <what>`.
    ///
    /// This is normally used in leaf parse errors (with no source) when parsing an enum.
    pub fn unknown_variant<T>(&self, what: &T, f: &mut fmt::Formatter) -> fmt::Result
    where
        T: fmt::Display + ?Sized,
    {
        storage::unknown_variant(&self.0, what, f)
    }
}

macro_rules! impl_from {
    ($($type:ty),+ $(,)?) => {
        $(
            impl From<$type> for InputString {
                fn from(input: $type) -> Self {
                    #[allow(clippy::useless_conversion)]
                    InputString(input.into())
                }
            }
        )+
    }
}

impl_from!(&str);

/// Displays message saying `failed to parse <input> as <what>`.
///
/// This is created by `display_cannot_parse` method and should be used as
/// `write_err!("{}", self.input.display_cannot_parse("what is parsed"); self.source)` in parse
/// error [`Display`](fmt::Display) imlementation if the error has source. If the error doesn't
/// have a source just use regular `write!` with same formatting arguments.
pub struct CannotParse<'a, T: fmt::Display + ?Sized> {
    input: &'a InputString,
    what: &'a T,
}

impl<'a, T: fmt::Display + ?Sized> fmt::Display for CannotParse<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        storage::cannot_parse(&self.input.0, &self.what, f)
    }
}

#[cfg(not(feature = "alloc"))]
mod storage {
    use core::fmt;

    #[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
    pub(super) struct Storage;

    impl fmt::Debug for Storage {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("<unknown input string - compiled without the `alloc` feature>")
        }
    }

    impl From<&str> for Storage {
        fn from(_value: &str) -> Self { Storage }
    }

    pub(super) fn cannot_parse<W>(_: &Storage, what: &W, f: &mut fmt::Formatter) -> fmt::Result
    where
        W: fmt::Display + ?Sized,
    {
        write!(f, "failed to parse {}", what)
    }

    pub(super) fn unknown_variant<W>(_: &Storage, what: &W, f: &mut fmt::Formatter) -> fmt::Result
    where
        W: fmt::Display + ?Sized,
    {
        write!(f, "unknown {}", what)
    }
}

#[cfg(feature = "alloc")]
mod storage {
    use core::fmt;

    use super::InputString;

    pub(super) type Storage = alloc::string::String;

    pub(super) fn cannot_parse<W>(input: &Storage, what: &W, f: &mut fmt::Formatter) -> fmt::Result
    where
        W: fmt::Display + ?Sized,
    {
        write!(f, "failed to parse '{}' as {}", input, what)
    }

    pub(super) fn unknown_variant<W>(inp: &Storage, what: &W, f: &mut fmt::Formatter) -> fmt::Result
    where
        W: fmt::Display + ?Sized,
    {
        write!(f, "'{}' is not a known {}", inp, what)
    }

    impl_from!(alloc::string::String, alloc::boxed::Box<str>, alloc::borrow::Cow<'_, str>);
}
