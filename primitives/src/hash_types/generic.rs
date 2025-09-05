// SPDX-License-Identifier: CC0-1.0

// NOTE: This is not a normal module.
//
// Generic implementation of hash wrapper types.
//
// File is included in other files using `include!` allowing us to
// follow the DRY principle without using macros. 

impl HashType {
    /// Returns the underlying byte array.
    pub const fn to_byte_array(self) -> [u8; LEN] { self.0.to_byte_array() }

    /// Returns a reference to the underlying byte array.
    pub const fn as_byte_array(&self) -> &[u8; LEN] { self.0.as_byte_array() }
}

#[cfg(feature = "serde")]
super::impl_serde!(HashType, LEN);
super::impl_bytelike_traits!(HashType, LEN);

#[cfg(feature = "hex")]
hex::impl_fmt_traits! {
    #[display_backward(REVERSE)]
    impl fmt_traits for HashType {
        const LENGTH: usize = LEN;
    }
}

#[cfg(feature = "hex")]
impl str::FromStr for HashType {
    type Err = hex::HexToArrayError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = <[u8; LEN]>::from_hex(s)?;
        if REVERSE {
            bytes.reverse();
        }
        Ok(Self::from_byte_array(bytes))
    }
}

#[cfg(not(feature = "hex"))]
impl fmt::Debug for HashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // FIXME: Should we use `HashType(...)` as is customary?
        // f.write_str("HashType(")?;
        for byte in self.as_byte_array() {
            write!(f, "{:02x}", byte)?
        }
        Ok(())
        // f.write_str(")")
    }
}
