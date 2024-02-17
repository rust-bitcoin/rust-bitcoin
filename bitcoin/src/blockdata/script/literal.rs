use internals::array_vec::ArrayVec;
use super::{Script, ScriptBuf};
use core::fmt;

#[doc(hidden)]
#[macro_export]
#[rustfmt::skip]
macro_rules! script_len {
    ((), ($($len:tt)*)) => { $($len)* };
    ((OP_PUSHDATA ($data:expr) $($remaining:tt)*), ($($total:tt)*)) => { $crate::script_len!(($($remaining)*), ($($total)* + $crate::script::literal::push_data_len($data.len()))) };
    ((OP_PUSHDATA ($len:expr, $data:expr) $($remaining:tt)*), ($($total:tt)*)) => { $crate::script_len!(($($remaining)*), ($($total)* + $crate::script::literal::push_data_len($len))) };
    (($op:ident $($remaining:tt)*), ($($total:tt)*)) => { $crate::script_len!(($($remaining)*), ($($total)* + 1)) };
}
#[doc(hidden)]
pub use script_len;

#[doc(hidden)]
#[macro_export]
#[rustfmt::skip]
macro_rules! emit_script {
    ($buf:expr, ) => {};
    ($buf:expr, OP_PUSHDATA ($data:expr) $($remaining:tt)*) => {
        $buf.extend_from_slice(&$crate::script::literal::encoded_push_op($data.len()));
        $buf.extend_from_slice(&$data);
        $crate::emit_script!($buf, $($remaining)*);
    };
    ($buf:expr, OP_PUSHDATA ($len:expr, $data:expr) $($remaining:tt)*) => {
        assert_eq!($len, $data.len());
        $buf.extend_from_slice(&$crate::script::literal::encoded_push_op($data.len()));
        $buf.extend_from_slice(&$data);
        $crate::emit_script!($buf, $($remaining)*);
    };
    ($buf:expr, OP_PUSHDATA1 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHDATA1");
    };
    ($buf:expr, OP_PUSHDATA2 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHDATA2");
    };
    ($buf:expr, OP_PUSHDATA4 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHDATA4");
    };
    ($buf:expr, OP_PUSHBYTES_0 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_0");
    };
    ($buf:expr, OP_PUSHBYTES_1 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_1");
    };
    ($buf:expr, OP_PUSHBYTES_2 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_2");
    };
    ($buf:expr, OP_PUSHBYTES_3 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_3");
    };
    ($buf:expr, OP_PUSHBYTES_4 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_4");
    };
    ($buf:expr, OP_PUSHBYTES_5 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_5");
    };
    ($buf:expr, OP_PUSHBYTES_6 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_6");
    };
    ($buf:expr, OP_PUSHBYTES_7 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_7");
    };
    ($buf:expr, OP_PUSHBYTES_8 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_8");
    };
    ($buf:expr, OP_PUSHBYTES_9 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_9");
    };
    ($buf:expr, OP_PUSHBYTES_10 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_10");
    };
    ($buf:expr, OP_PUSHBYTES_11 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_11");
    };
    ($buf:expr, OP_PUSHBYTES_12 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_12");
    };
    ($buf:expr, OP_PUSHBYTES_13 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_13");
    };
    ($buf:expr, OP_PUSHBYTES_14 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_14");
    };
    ($buf:expr, OP_PUSHBYTES_15 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_15");
    };
    ($buf:expr, OP_PUSHBYTES_16 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_16");
    };
    ($buf:expr, OP_PUSHBYTES_17 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_17");
    };
    ($buf:expr, OP_PUSHBYTES_18 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_18");
    };
    ($buf:expr, OP_PUSHBYTES_19 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_19");
    };
    ($buf:expr, OP_PUSHBYTES_20 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_20");
    };
    ($buf:expr, OP_PUSHBYTES_21 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_21");
    };
    ($buf:expr, OP_PUSHBYTES_22 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_22");
    };
    ($buf:expr, OP_PUSHBYTES_23 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_23");
    };
    ($buf:expr, OP_PUSHBYTES_24 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_24");
    };
    ($buf:expr, OP_PUSHBYTES_25 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_25");
    };
    ($buf:expr, OP_PUSHBYTES_26 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_26");
    };
    ($buf:expr, OP_PUSHBYTES_27 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_27");
    };
    ($buf:expr, OP_PUSHBYTES_28 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_28");
    };
    ($buf:expr, OP_PUSHBYTES_29 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_29");
    };
    ($buf:expr, OP_PUSHBYTES_30 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_30");
    };
    ($buf:expr, OP_PUSHBYTES_31 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_31");
    };
    ($buf:expr, OP_PUSHBYTES_32 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_32");
    };
    ($buf:expr, OP_PUSHBYTES_33 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_33");
    };
    ($buf:expr, OP_PUSHBYTES_34 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_34");
    };
    ($buf:expr, OP_PUSHBYTES_35 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_35");
    };
    ($buf:expr, OP_PUSHBYTES_36 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_36");
    };
    ($buf:expr, OP_PUSHBYTES_37 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_37");
    };
    ($buf:expr, OP_PUSHBYTES_38 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_38");
    };
    ($buf:expr, OP_PUSHBYTES_39 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_39");
    };
    ($buf:expr, OP_PUSHBYTES_40 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_40");
    };
    ($buf:expr, OP_PUSHBYTES_41 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_41");
    };
    ($buf:expr, OP_PUSHBYTES_42 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_42");
    };
    ($buf:expr, OP_PUSHBYTES_43 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_43");
    };
    ($buf:expr, OP_PUSHBYTES_44 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_44");
    };
    ($buf:expr, OP_PUSHBYTES_45 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_45");
    };
    ($buf:expr, OP_PUSHBYTES_46 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_46");
    };
    ($buf:expr, OP_PUSHBYTES_47 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_47");
    };
    ($buf:expr, OP_PUSHBYTES_48 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_48");
    };
    ($buf:expr, OP_PUSHBYTES_49 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_49");
    };
    ($buf:expr, OP_PUSHBYTES_50 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_50");
    };
    ($buf:expr, OP_PUSHBYTES_51 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_51");
    };
    ($buf:expr, OP_PUSHBYTES_52 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_52");
    };
    ($buf:expr, OP_PUSHBYTES_53 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_53");
    };
    ($buf:expr, OP_PUSHBYTES_54 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_54");
    };
    ($buf:expr, OP_PUSHBYTES_55 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_55");
    };
    ($buf:expr, OP_PUSHBYTES_56 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_56");
    };
    ($buf:expr, OP_PUSHBYTES_57 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_57");
    };
    ($buf:expr, OP_PUSHBYTES_58 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_58");
    };
    ($buf:expr, OP_PUSHBYTES_59 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_59");
    };
    ($buf:expr, OP_PUSHBYTES_60 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_60");
    };
    ($buf:expr, OP_PUSHBYTES_61 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_61");
    };
    ($buf:expr, OP_PUSHBYTES_62 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_62");
    };
    ($buf:expr, OP_PUSHBYTES_63 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_63");
    };
    ($buf:expr, OP_PUSHBYTES_64 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_64");
    };
    ($buf:expr, OP_PUSHBYTES_65 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_65");
    };
    ($buf:expr, OP_PUSHBYTES_66 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_66");
    };
    ($buf:expr, OP_PUSHBYTES_67 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_67");
    };
    ($buf:expr, OP_PUSHBYTES_68 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_68");
    };
    ($buf:expr, OP_PUSHBYTES_69 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_69");
    };
    ($buf:expr, OP_PUSHBYTES_70 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_70");
    };
    ($buf:expr, OP_PUSHBYTES_71 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_71");
    };
    ($buf:expr, OP_PUSHBYTES_72 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_72");
    };
    ($buf:expr, OP_PUSHBYTES_73 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_73");
    };
    ($buf:expr, OP_PUSHBYTES_74 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_74");
    };
    ($buf:expr, OP_PUSHBYTES_75 $($remaining:tt)*) => {
        compile_error!("Use OP_PUSHDATA instead of OP_PUSHBYTES_75");
    };
    ($buf:expr, $op:ident $($remaining:tt)*) => {
        $buf.push($crate::blockdata::opcodes::all::$op.to_u8());
        $crate::emit_script!($buf, $($remaining)*);
    };
}
#[doc(hidden)]
pub use emit_script;

/// Creates a script "literal".
///
/// This macro parses a human-readable script at compile time and produces [`ArrayScript`].
/// It is a very convenient way of constructing the script.
///
/// The syntax uses standard opcodes (`OP_*` from `opcodes::all`) except for data pushes which are
/// written as `OP_PUSHDATA (your_data_here)` if `your_data_here` is `const` or
/// `OP_PUSHDATA (data_len, your_data_here)` if `your_data_here` is not `const`, however `data_len`
/// has to be a known constant expression (not associated in generic context).
///
/// This implies that variable-length scripts are currently not supported thus effectively
/// excluding legacy public keys (P2PK) and ECDSA signatures.
#[macro_export]
macro_rules! script {
    ($($script:tt)*) => {
        {
            #[allow(unused_mut)] // triggers when empty
            let mut buf = $crate::internals::array_vec::ArrayVec::<u8, { $crate::script_len!(($($script)*), (0)) }>::new();
            $crate::emit_script!(buf, $($script)*);
            // the correct length is pre-computed.
            let arr = buf.unwrap();
            $crate::script::ArrayScript::from_byte_array(arr)
        }
    }
}
pub use script;

#[doc(hidden)]
pub const fn push_data_len(slice_len: usize) -> usize {
    let _data_too_long = [()][(slice_len > u32::MAX as usize) as usize];
    slice_len + match slice_len {
        0..=0x4b => 1,
        0x4c..=0xff => 2,
        0x100..=0xffff => 3,
        _ => 5,
    }
}

// Intentionally returns encoded op rather than pushing to an array vec to deduplicate generated
// code
#[doc(hidden)]
pub fn encoded_push_op(len: usize) -> ArrayVec<u8, 5> {
    use super::super::opcodes::all::{OP_PUSHBYTES_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
    let mut buf = ArrayVec::new();
    match len {
        0..=0x4b => buf.push(OP_PUSHBYTES_0.to_u8() + len as u8),
        0x4c..=0xff => {
            buf.push(OP_PUSHDATA1.to_u8());
            buf.push(len as u8)
        },
        0x100..=0xffff => {
            buf.push(OP_PUSHDATA2.to_u8());
            buf.extend_from_slice(&(len as u16).to_le_bytes())
        },
        _ => {
            buf.push(OP_PUSHDATA4.to_u8());
            buf.extend_from_slice(&(len as u32).to_le_bytes());
        },
    }
    buf
}

/// A script with statically-known length.
///
/// This type is similar to `Box<Script>` except it doesn't force heap allocation.
/// It is mainly useful when one needs to create a temporary script - such as before pushing it
/// into [`Witness`](crate::Witness) as a taproot leaf script.
///
/// It is recommended that you use the [`script`] macro to create it.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ArrayScript<const N: usize>([u8; N]);

impl<const N: usize> ArrayScript<N> {
    /// Creates `ArrayScript` from raw bytes.
    pub const fn from_byte_array(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Converts `self` to `ScriptBuf`.
    ///
    /// This allocates so it kinda loses the point of this type but it's useful when you want a
    /// `ScriptBuf` but want to use the [`script`] macro to construct it.
    pub fn to_buf(self) -> ScriptBuf {
        self.as_script().to_owned()
    }

    /// Returns a reference to the unsized [`Script`].
    pub fn as_script(&self) -> &Script {
        Script::from_bytes(&self.0)
    }

    /// Returns a mutable reference to the unsized [`Script`].
    pub fn as_mut_script(&mut self) -> &mut Script {
        Script::from_bytes_mut(&mut self.0)
    }
}

impl<const N: usize> fmt::Display for ArrayScript<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_script(), f)
    }
}

impl<const N: usize> fmt::Debug for ArrayScript<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_script(), f)
    }
}

impl<const N: usize> core::ops::Deref for ArrayScript<N> {
    type Target = Script;

    fn deref(&self) -> &Self::Target {
        self.as_script()
    }
}

impl<const N: usize> core::ops::DerefMut for ArrayScript<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_script()
    }
}

impl<const N: usize> PartialEq<Script> for ArrayScript<N> {
    fn eq(&self, other: &Script) -> bool {
        self.as_script() == other
    }
}

impl<const N: usize> PartialEq<ArrayScript<N>> for Script {
    fn eq(&self, other: &ArrayScript<N>) -> bool {
        other == self
    }
}

impl<const N: usize> PartialEq<ScriptBuf> for ArrayScript<N> {
    fn eq(&self, other: &ScriptBuf) -> bool {
        self.as_script() == other
    }
}

impl<const N: usize> PartialEq<ArrayScript<N>> for ScriptBuf {
    fn eq(&self, other: &ArrayScript<N>) -> bool {
        other == self
    }
}

#[cfg(test)]
mod tests {
    use super::script;
    use super::super::{Script, ScriptBuf};
    // no wildcard to test that we don't really need the import
    use super::super::super::opcodes::all;
    use crate::key::PubkeyHash;
    use hashes::Hash;

    #[test]
    fn empty() {
        let script = script! {};
        assert!(script.is_empty());
    }

    #[test]
    fn single() {
        let script = script! { OP_DUP };
        let expected = Script::builder().push_opcode(all::OP_DUP).into_script();
        assert_eq!(script, expected);
    }

    #[test]
    fn p2tr() {
        let script = script! { OP_PUSHNUM_1 OP_PUSHDATA ([0; 32]) };
        let expected = Script::builder()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(&[0; 32])
            .into_script();
        assert_eq!(script, expected);
    }

    #[test]
    fn p2pkh() {
        let script = script! { OP_DUP OP_HASH160 OP_PUSHDATA ([0; 20]) OP_EQUALVERIFY OP_CHECKSIG };
        let expected = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0; 20]));
        assert_eq!(script, expected);
    }

    #[test]
    fn non_const() {
        // intentionally non-const
        fn produce_value() -> [u8; 32] {
            [0; 32]
        }

        let script = script! { OP_PUSHDATA (32, produce_value()) };
        let expected = Script::builder()
            .push_slice(&[0; 32])
            .into_script();
        assert_eq!(script, expected);
    }
}
