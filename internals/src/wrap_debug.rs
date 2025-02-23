//! Contains a wrapper for a function that implements `Debug`.
use core::fmt;

/// A wrapper for a function that implements `Debug`.
pub struct WrapDebug<F: Fn(&mut fmt::Formatter) -> fmt::Result>(pub F);

impl<F: Fn(&mut fmt::Formatter) -> fmt::Result> fmt::Debug for WrapDebug<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { (self.0)(f) }
}
