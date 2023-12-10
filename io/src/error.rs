#[cfg(any(feature = "alloc", feature = "std"))]
use alloc::boxed::Box;
use core::fmt::{Debug, Display, Formatter};

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,

    #[cfg(feature = "std")]
    error: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    error: Option<Box<dyn Debug + Send + Sync + 'static>>,
}

impl Error {
    #[cfg(feature = "std")]
    pub fn new<E>(kind: ErrorKind, error: E) -> Error
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self { kind, error: Some(error.into()) }
    }

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub fn new<E: sealed::IntoBoxDynDebug>(kind: ErrorKind, error: E) -> Error {
        Self { kind, error: Some(error.into()) }
    }

    pub fn kind(&self) -> ErrorKind { self.kind }

    #[cfg(feature = "std")]
    pub fn get_ref(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.error.as_deref()
    }

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub fn get_ref(&self) -> Option<&(dyn Debug + Send + Sync + 'static)> { self.error.as_deref() }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Self {
            kind,
            #[cfg(any(feature = "std", feature = "alloc"))]
            error: None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, fmt: &mut Formatter) -> core::result::Result<(), core::fmt::Error> {
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

    #[allow(deprecated)]
    fn description(&self) -> &str {
        match self.error.as_ref() {
            Some(e) => e.description(),
            None => self.kind.description(),
        }
    }

    #[allow(deprecated)]
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.error.as_ref().and_then(|e| e.as_ref().cause())
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(o: std::io::Error) -> Error {
        Self { kind: ErrorKind::from_std(o.kind()), error: o.into_inner() }
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(o: Error) -> std::io::Error {
        if let Some(err) = o.error {
            std::io::Error::new(o.kind.to_std(), err)
        } else {
            o.kind.to_std().into()
        }
    }
}

macro_rules! define_errorkind {
    ($($kind: ident),*) => {
        #[non_exhaustive]
        #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
        /// A minimal subset of [`std::io::ErrorKind`] which is used for [`Error`]. Note that, as with
        /// [`std::io`], only [`Self::Interrupted`] has defined semantics in this crate, all other
        /// variants are provided here only to provide higher-fidelity conversions to and from
        /// [`std::io::Error`].
        pub enum ErrorKind {
            $($kind),*
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
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    UnexpectedEof,
    // Note: Any time we bump the MSRV any new error kinds should be added here!
    Other
);

#[cfg(all(feature = "alloc", not(feature = "std")))]
mod sealed {
    use alloc::boxed::Box;
    use alloc::string::String;
    use core::fmt::Debug;

    pub trait IntoBoxDynDebug {
        fn into(self) -> Box<dyn Debug + Send + Sync + 'static>;
    }

    impl IntoBoxDynDebug for &str {
        fn into(self) -> Box<dyn Debug + Send + Sync + 'static> { Box::new(String::from(self)) }
    }

    impl IntoBoxDynDebug for String {
        fn into(self) -> Box<dyn Debug + Send + Sync + 'static> { Box::new(self) }
    }
}
