#[cfg(feature = "alloc")]
use alloc::boxed::Box;
use internals::rust_version;

/// A bridging wrapper providing the IO traits for types that already implement `std` IO traits.
#[repr(transparent)]
pub struct FromStd<T>(T);

impl<T> FromStd<T> {
    /// Wraps an IO type.
    #[inline]
    pub const fn new(inner: T) -> Self { Self(inner) }

    /// Returns the wrapped value.
    #[inline]
    pub fn into_inner(self) -> T { self.0 }

    /// Returns a reference to the wrapped value.
    #[inline]
    pub fn inner(&self) -> &T { &self.0 }

    /// Returns a mutable reference to the wrapped value.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T { &mut self.0 }

    /// Wraps a mutable reference to IO type.
    #[inline]
    pub fn new_mut(inner: &mut T) -> &mut Self {
        // SAFETY: the type is repr(transparent) and the lifetimes match
        unsafe { &mut *(inner as *mut _ as *mut Self) }
    }

    /// Wraps a boxed IO type.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn new_boxed(inner: Box<T>) -> Box<Self> {
        // SAFETY: the type is repr(transparent) and the pointer is created from Box
        unsafe { Box::from_raw(Box::into_raw(inner) as *mut Self) }
    }
}

impl<T: std::io::Read> super::Read for FromStd<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> super::Result<usize> {
        self.0.read(buf).map_err(Into::into)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> super::Result<()> {
        self.0.read_exact(buf).map_err(Into::into)
    }
}

impl<T: std::io::BufRead> super::BufRead for FromStd<T> {
    #[inline]
    fn fill_buf(&mut self) -> super::Result<&[u8]> { self.0.fill_buf().map_err(Into::into) }

    #[inline]
    fn consume(&mut self, amount: usize) { self.0.consume(amount) }
}

impl<T: std::io::Write> super::Write for FromStd<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> super::Result<usize> {
        self.0.write(buf).map_err(Into::into)
    }

    #[inline]
    fn flush(&mut self) -> super::Result<()> { self.0.flush().map_err(Into::into) }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> super::Result<()> {
        self.0.write_all(buf).map_err(Into::into)
    }
}

// We also impl std traits so that mixing the calls is not annoying.

impl<T: std::io::Read> std::io::Read for FromStd<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.0.read(buf) }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> { self.0.read_exact(buf) }
}

impl<T: std::io::BufRead> std::io::BufRead for FromStd<T> {
    #[inline]
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> { self.0.fill_buf() }

    #[inline]
    fn consume(&mut self, amount: usize) { self.0.consume(amount) }
}

impl<T: std::io::Write> std::io::Write for FromStd<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.0.write(buf) }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> { self.0.flush() }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> { self.0.write_all(buf) }
}

/// A bridging wrapper providing the std traits for types that already implement our traits.
#[repr(transparent)]
pub struct ToStd<T>(T);

impl<T> ToStd<T> {
    /// Wraps an IO type.
    #[inline]
    pub const fn new(inner: T) -> Self { Self(inner) }

    /// Returns the wrapped value.
    #[inline]
    pub fn into_inner(self) -> T { self.0 }

    /// Returns a reference to the wrapped value.
    #[inline]
    pub fn inner(&self) -> &T { &self.0 }

    /// Returns a mutable reference to the wrapped value.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T { &mut self.0 }

    /// Wraps a mutable reference to IO type.
    #[inline]
    pub fn new_mut(inner: &mut T) -> &mut Self {
        // SAFETY: the type is repr(transparent) and the lifetimes match
        unsafe { &mut *(inner as *mut _ as *mut Self) }
    }

    /// Wraps a boxed IO type.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn new_boxed(inner: Box<T>) -> Box<Self> {
        // SAFETY: the type is repr(transparent) and the pointer is created from Box
        unsafe { Box::from_raw(Box::into_raw(inner) as *mut Self) }
    }
}

impl<T: super::Read> std::io::Read for ToStd<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf).map_err(Into::into)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.0.read_exact(buf).map_err(Into::into)
    }
}

impl<T: super::BufRead> std::io::BufRead for ToStd<T> {
    #[inline]
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> { self.0.fill_buf().map_err(Into::into) }

    #[inline]
    fn consume(&mut self, amount: usize) { self.0.consume(amount) }
}

impl<T: super::Write> std::io::Write for ToStd<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf).map_err(Into::into)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> { self.0.flush().map_err(Into::into) }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_all(buf).map_err(Into::into)
    }
}

// We also impl our traits so that mixing the calls is not annoying.

impl<T: super::Read> super::Read for ToStd<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> super::Result<usize> { self.0.read(buf) }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> super::Result<()> { self.0.read_exact(buf) }
}

impl<T: super::BufRead> super::BufRead for ToStd<T> {
    #[inline]
    fn fill_buf(&mut self) -> super::Result<&[u8]> { self.0.fill_buf() }

    #[inline]
    fn consume(&mut self, amount: usize) { self.0.consume(amount) }
}

impl<T: super::Write> super::Write for ToStd<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> super::Result<usize> { self.0.write(buf) }

    #[inline]
    fn flush(&mut self) -> super::Result<()> { self.0.flush() }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> super::Result<()> { self.0.write_all(buf) }
}

macro_rules! impl_our {
    (impl$(<$($gen:ident $(: $gent:path)?),*>)? Read for $std_type:ty $(where $($where:tt)*)?) => {
        impl$(<$($gen$(: $gent)?),*>)? super::Read for $std_type $(where $($where)*)? {
            #[inline]
            fn read(&mut self, buf: &mut [u8]) -> super::Result<usize> {
                std::io::Read::read(self, buf).map_err(Into::into)
            }

            #[inline]
            fn read_exact(&mut self, buf: &mut [u8]) -> super::Result<()> {
                std::io::Read::read_exact(self, buf).map_err(Into::into)
            }
        }
    };

    (impl$(<$($gen:ident $(: $gent:path)?),*>)? BufRead for $std_type:ty $(where $($where:tt)*)?) => {
        impl$(<$($gen$(: $gent)?),*>)? super::BufRead for $std_type $(where $($where)*)? {
            #[inline]
            fn fill_buf(&mut self) -> super::Result<&[u8]> {
                std::io::BufRead::fill_buf(self).map_err(Into::into)
            }

            #[inline]
            fn consume(&mut self, amount: usize) {
                std::io::BufRead::consume(self, amount)
            }
        }
    };

    (impl$(<$($gen:ident $(: $gent:path)?),*>)? Write for $std_type:ty $(where $($where:tt)*)?) => {
        impl$(<$($gen$(: $gent)?),*>)? super::Write for $std_type $(where $($where)*)? {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> super::Result<usize> {
                std::io::Write::write(self, buf).map_err(Into::into)
            }

            #[inline]
            fn flush(&mut self) -> super::Result<()> {
                std::io::Write::flush(self).map_err(Into::into)
            }

            #[inline]
            fn write_all(&mut self, buf: &[u8]) -> super::Result<()> {
                std::io::Write::write_all(self, buf).map_err(Into::into)
            }
        }
    };
}

rust_version! {
    if >= 1.72 {
        impl_our! {
            impl<R: std::io::Read> Read for std::io::BufReader<R> where R: ?Sized
        }

        impl_our! {
            impl<R: std::io::Read> BufRead for std::io::BufReader<R> where R: ?Sized
        }

        impl_our! {
            impl<W: std::io::Write> Write for std::io::BufWriter<W> where W: ?Sized
        }

        impl_our! {
            impl<W: std::io::Write> Write for std::io::LineWriter<W> where W: ?Sized
        }
    } else {
        impl_our! {
            impl<R: std::io::Read> Read for std::io::BufReader<R>
        }

        impl_our! {
            impl<R: std::io::Read> BufRead for std::io::BufReader<R>
        }

        impl_our! {
            impl<W: std::io::Write> Write for std::io::BufWriter<W>
        }

        impl_our! {
            impl<W: std::io::Write> Write for std::io::LineWriter<W>
        }
    }
}

impl std::io::Write for super::Sink {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { Ok(buf.len()) }

    #[inline]
    fn write_all(&mut self, _: &[u8]) -> std::io::Result<()> { Ok(()) }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl_our! {
    impl<R: std::io::Read> Read for std::io::Take<R>
}

impl_our! {
    impl<R: std::io::BufRead> BufRead for std::io::Take<R>
}

impl_our! {
    impl<R1: std::io::Read, R2: std::io::Read> Read for std::io::Chain<R1, R2>
}

impl_our! {
    impl<R1: std::io::BufRead, R2: std::io::BufRead> BufRead for std::io::Chain<R1, R2>
}

impl_our! {
    impl<T: AsRef<[u8]>> Read for std::io::Cursor<T>
}

impl_our! {
    impl<T: AsRef<[u8]>> BufRead for std::io::Cursor<T>
}

impl_our! {
    impl Write for std::io::Cursor<std::vec::Vec<u8>>
}

impl_our! {
    impl Write for std::io::Cursor<&'_ mut std::vec::Vec<u8>>
}

impl_our! {
    impl Write for std::io::Cursor<std::boxed::Box<[u8]>>
}

impl_our! {
    impl Read for std::io::Empty
}

impl_our! {
    impl BufRead for std::io::Empty
}

rust_version! {
    if >= 1.73 {
        impl_our! {
            impl Write for std::io::Empty
        }

        // No idea why &Empty impls Write but not Read + BufRead
        impl_our! {
            impl Write for &'_ std::io::Empty
        }

        impl_our! {
            impl Read for std::sync::Arc<std::fs::File>
        }

        impl_our! {
            impl Write for std::sync::Arc<std::fs::File>
        }
    }
}

impl_our! {
    impl Read for std::io::Repeat
}

impl_our! {
    impl Read for std::io::Stdin
}

rust_version! {
    if >= 1.78 {
        impl_our! {
            impl Read for &'_ std::io::Stdin
        }
    }
}

impl_our! {
    impl Write for std::io::Stdout
}

impl_our! {
    impl Write for &'_ std::io::Stdout
}

impl_our! {
    impl Write for std::io::Stderr
}

impl_our! {
    impl Write for &'_ std::io::Stderr
}

impl_our! {
    impl Read for std::io::StdinLock<'_>
}

impl_our! {
    impl BufRead for std::io::StdinLock<'_>
}

impl_our! {
    impl Read for std::fs::File
}

impl_our! {
    impl Write for std::fs::File
}

impl_our! {
    impl Read for &'_ std::fs::File
}

impl_our! {
    impl Write for &'_ std::fs::File
}

impl_our! {
    impl Read for std::net::TcpStream
}

impl_our! {
    impl Write for std::net::TcpStream
}

impl_our! {
    impl Read for &'_ std::net::TcpStream
}

impl_our! {
    impl Write for &'_ std::net::TcpStream
}

#[cfg(target_family = "unix")]
impl_our! {
    impl Read for std::os::unix::net::UnixStream
}

#[cfg(target_family = "unix")]
impl_our! {
    impl Write for std::os::unix::net::UnixStream
}

#[cfg(target_family = "unix")]
impl_our! {
    impl Read for &'_ std::os::unix::net::UnixStream
}

#[cfg(target_family = "unix")]
impl_our! {
    impl Write for &'_ std::os::unix::net::UnixStream
}

impl_our! {
    impl Read for std::process::ChildStderr
}

impl_our! {
    impl Read for std::process::ChildStdout
}

impl_our! {
    impl Write for std::process::ChildStdin
}

// No ide why other &ChildStd* are not implemented
impl_our! {
    impl Write for &'_ std::process::ChildStdin
}

rust_version! {
    if >= 1.75 {
        impl_our! {
            impl Read for std::collections::VecDeque<u8>
        }

        impl_our! {
            impl BufRead for std::collections::VecDeque<u8>
        }
    }
}

impl_our! {
    impl Write for std::collections::VecDeque<u8>
}
