//! Helpers for integers

/// Extensions for signed integers
pub trait IntExt {
    /// the unsigned integer type
    type Unsigned;

    ///use this to find unsigned absolute if rust version less that 1.51
    #[cfg(not(rust_v_1_51))]
    fn unsigned_abs(self) -> Self::Unsigned;
}

impl IntExt for i64 {
    type Unsigned = u64;

    fn unsigned_abs(self) -> Self::Unsigned {
        if self < 0 {
            -self as u64
        } else {
            self as u64
        }
    }
}
