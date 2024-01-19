use core::fmt;
use super::{Decoder, Encoder};

/// Decodes a varint.
///
/// For more information about decoder see the documentation of the [`Decoder`] trait.
#[derive(Default, Debug, Clone)]
pub struct VarIntDecoder {
    buf: internals::array_vec::ArrayVec<u8, 9>,
}

impl Decoder for VarIntDecoder {
    type Value = u64;
    type Error = VarIntDecodeError;

    fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        if bytes.is_empty() { return Ok(()); }
        if self.buf.is_empty() {
            self.buf.push(bytes[0]);
            *bytes = &bytes[1..];
        }
        let max_len = match self.buf[0] {
            0xFF => 9,
            0xFE => 5,
            0xFD => 3,
            _ => 1
        };
        let to_copy = bytes.len().min(max_len - self.buf.len());
        self.buf.extend_from_slice(&bytes[..to_copy]);
        *bytes = &bytes[to_copy..];
        Ok(())
    }

    fn end(self) -> Result<Self::Value, Self::Error> {
        fn arr<const N: usize>(slice: &[u8]) -> Result<[u8; N], VarIntDecodeError> {
            slice.try_into().map_err(|_| {
                VarIntDecodeError::UnexpectedEnd { required: N, received: slice.len() }
            })
        }

        let (first, payload) = self.buf.split_first()
            .ok_or(VarIntDecodeError::UnexpectedEnd { required: 1, received: 0 })?;
        match *first {
            0xFF => {
                let x =  u64::from_le_bytes(arr(payload)?);
                if x < 0x100000000 {
                    Err(VarIntDecodeError::NonMinimal { value: x })
                } else {
                    Ok(x)
                }
            },
            0xFE => {
                let x =  u32::from_le_bytes(arr(payload)?);
                if x < 0x10000 {
                    Err(VarIntDecodeError::NonMinimal { value: x.into() })
                } else {
                    Ok(x.into())
                }
            },
            0xFD => {
                let x =  u16::from_le_bytes(arr(payload)?);
                if x < 0xFD {
                    Err(VarIntDecodeError::NonMinimal { value: x.into() })
                } else {
                    Ok(x.into())
                }
            },
            n => {
                Ok(n.into())
            },
        }
    }
}

/// Encodes a varint.
pub struct VarIntEncoder {
    buf: internals::array_vec::ArrayVec<u8, 9>,
}

impl VarIntEncoder {
    pub fn new(value: u64) -> Self {
        // In theory, varint consists of two parts: prefix and optional payload, so this could have
        // two states, one for each part. However we need to have some buffer anyway because of
        // trait requirement to return `&[u8]`, so we use ArrayVec and while we're at it it makes a
        // lot of sense to just encode everything upfront.
        let mut buf = internals::array_vec::ArrayVec::new();
        match value {
            0..=0xFC => {
                buf.push(value as u8);
            }
            0xFD..=0xFFFF => {
                buf.push(0xFD);
                buf.extend_from_slice(&(value as u16).to_le_bytes());
            }
            0x10000..=0xFFFFFFFF => {
                buf.push(0xFE);
                buf.extend_from_slice(&(value as u32).to_le_bytes());
            }
            _ => {
                buf.push(0xFF);
                buf.extend_from_slice(&value.to_le_bytes());
            }
        }

        VarIntEncoder { buf }
    }

    pub fn len(value: u64) -> usize {
        Self::payload_len(value) + 1
    }

    fn payload_len(value: u64) -> usize {
        match value {
            0..=0xFC => {
                0
            }
            0xFD..=0xFFFF => {
                2
            }
            0x10000..=0xFFFFFFFF => {
                4
            }
            _ => {
                8
            }
        }
    }

    pub fn dyn_encoded_len(value: u64, max_steps: usize) -> (usize, usize) {
        if max_steps == 0 {
            return (0, 0)
        }
        (Self::payload_len(value), max_steps - 1)
    }

}

impl Encoder for VarIntEncoder {
    fn encoded_chunk(&self) -> &[u8] {
        &self.buf
    }

    fn next(&mut self) -> bool {
        false
    }
}

/// Returned when decoding a var int fails.
#[derive(Debug)]
pub enum VarIntDecodeError {
    UnexpectedEnd { required: usize, received: usize },
    NonMinimal { value: u64 },
}

impl fmt::Display for VarIntDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { required: 1, received: 0 } => write!(f, "required at least one byte but the input is empty"),
            Self::UnexpectedEnd { required, received: 0 } => write!(f, "required at least {} bytes but the input is empty", required),
            Self::UnexpectedEnd { required, received } => write!(f, "required at least {} bytes but only {} bytes were received", required, received),
            Self::NonMinimal { value } => write!(f, "the value {} was not encoded minimally", value),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VarIntDecodeError {}
