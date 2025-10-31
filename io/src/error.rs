// SPDX-License-Identifier: CC0-1.0

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
use core::fmt;

/// The `io` crate error type.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    /// We want this type to be `?UnwindSafe` and `?RefUnwindSafe` - the same as `std::io::Error`.
    ///
    /// In `std` builds the existence of `dyn std::error:Error` prevents `UnwindSafe` and
    /// `RefUnwindSafe` from being automatically implemented. But in `no-std` builds without the
    /// marker nothing prevents it.
    _not_unwind_safe: core::marker::PhantomData<NotUnwindSafe>,

    #[cfg(feature = "std")]
    error: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    error: Option<Box<dyn fmt::Debug + Send + Sync + 'static>>,
}

impl Error {
    /// Constructs a new I/O error.
    #[cfg(feature = "std")]
    pub fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self { kind, _not_unwind_safe: core::marker::PhantomData, error: Some(error.into()) }
    }

    /// Constructs a new I/O error.
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub fn new<E: sealed::IntoBoxDynDebug>(kind: ErrorKind, error: E) -> Self {
        Self { kind, _not_unwind_safe: core::marker::PhantomData, error: Some(error.into()) }
    }

    /// Returns the error kind for this error.
    pub fn kind(&self) -> ErrorKind { self.kind }

    /// Returns a reference to this error.
    #[cfg(feature = "std")]
    pub fn get_ref(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.error.as_deref()
    }

    /// Returns a reference to this error.
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub fn get_ref(&self) -> Option<&(dyn fmt::Debug + Send + Sync + 'static)> {
        self.error.as_deref()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            _not_unwind_safe: core::marker::PhantomData,
            #[cfg(any(feature = "std", feature = "alloc"))]
            error: None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        fmt.write_fmt(format_args!("I/O Error: {}", self.kind.description()))?;
        #[cfg(any(feature = "alloc", feature = "std"))]
        if let Some(e) = &self.error {
            fmt.write_fmt(format_args!(". {:?}", e))?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.as_ref().and_then(|e| e.as_ref().source())
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(o: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::from_std(o.kind()),
            _not_unwind_safe: core::marker::PhantomData,
            error: o.into_inner(),
        }
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(o: Error) -> Self {
        if let Some(err) = o.error {
            Self::new(o.kind.to_std(), err)
        } else {
            o.kind.to_std().into()
        }
    }
}

/// Useful for preventing `UnwindSafe` and `RefUnwindSafe` from being automatically implemented.
struct NotUnwindSafe {
    _not_unwind_safe: core::marker::PhantomData<(&'static mut (), core::cell::UnsafeCell<()>)>,
}

unsafe impl Sync for NotUnwindSafe {}

macro_rules! define_errorkind {
    ($($(#[$($attr:tt)*])* $kind:ident),*) => {
        #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
        /// A minimal subset of [`std::io::ErrorKind`] which is used for [`Error`].
        ///
        /// Note that, as with [`std::io`], only [`Self::Interrupted`] has defined semantics in this
        /// crate, all other variants are provided here only to provide higher-fidelity conversions
        /// to and from [`std::io::Error`].
        pub enum ErrorKind {
            $(
                $(#[$($attr)*])*
                $kind
            ),*
        }

        impl From<core::convert::Infallible> for ErrorKind {
            fn from(never: core::convert::Infallible) -> Self { match never {} }
        }

        impl ErrorKind {
            fn description(&self) -> &'static str {
                match self {
                    $(Self::$kind => stringify!($kind)),*
                }
            }

            #[cfg(feature = "std")]
            fn to_std(self) -> std::io::ErrorKind {
                match self {
                    $(Self::$kind => std::io::ErrorKind::$kind),*
                }
            }

            #[cfg(feature = "std")]
            fn from_std(o: std::io::ErrorKind) -> ErrorKind {
                match o {
                    $(std::io::ErrorKind::$kind => ErrorKind::$kind),*,
                    _ => ErrorKind::Other
                }
            }
        }
    }
}

define_errorkind!(
    /// An entity was not found, often a file.
    NotFound,
    /// The operation lacked the necessary privileges to complete.
    PermissionDenied,
    /// The connection was refused by the remote server.
    ConnectionRefused,
    /// The connection was reset by the remote server.
    ConnectionReset,
    /// The connection was aborted (terminated) by the remote server.
    ConnectionAborted,
    /// The network operation failed because it was not connected yet.
    NotConnected,
    /// A socket address could not be bound because the address is already in use elsewhere.
    AddrInUse,
    /// A nonexistent interface was requested or the requested address was not local.
    AddrNotAvailable,
    /// The operation failed because a pipe was closed.
    BrokenPipe,
    /// An entity already exists, often a file.
    AlreadyExists,
    /// The operation needs to block to complete, but the blocking operation was requested to not occur.
    WouldBlock,
    /// A parameter was incorrect.
    InvalidInput,
    /// Data not valid for the operation were encountered.
    InvalidData,
    /// The I/O operation’s timeout expired, causing it to be canceled.
    TimedOut,
    /// An error returned when an operation could not be completed because a call to `write` returned `Ok(0)`.
    WriteZero,
    /// This operation was interrupted.
    Interrupted,
    /// An error returned when an operation could not be completed because an "end of file" was reached prematurely.
    UnexpectedEof,
    // Note: Any time we bump the MSRV any new error kinds should be added here!
    /// A custom error that does not fall under any other I/O error kind
    Other
);

#[cfg(all(feature = "alloc", not(feature = "std")))]
mod sealed {
    use alloc::boxed::Box;
    use alloc::string::String;
    use core::fmt;

    pub trait IntoBoxDynDebug {
        fn into(self) -> Box<dyn fmt::Debug + Send + Sync + 'static>;
    }

    impl IntoBoxDynDebug for &str {
        fn into(self) -> Box<dyn fmt::Debug + Send + Sync + 'static> {
            Box::new(String::from(self))
        }
    }

    impl IntoBoxDynDebug for String {
        fn into(self) -> Box<dyn fmt::Debug + Send + Sync + 'static> { Box::new(self) }
    }
}
