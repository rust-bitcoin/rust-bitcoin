use super::*;
use alloc::vec::Vec;

#[allow(clippy::type_complexity)] // doesn't seem really that complex
pub struct VecDecoder<T: Decode>(Then<VarIntDecoder, InnerVecDecoder<T>, fn (u64) -> InnerVecDecoder<T>>) where T::Decoder: Default;

impl<T: Decode> Decoder for VecDecoder<T> where T::Decoder: Default {
    type Value = Vec<T>;
    type Error = VecDecodeError<<T::Decoder as Decoder>::Error>;

    fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        self.0.decode_chunk(bytes).map_err(|error| {
            error
                .map_left(VecDecodeError::Length)
                .map_right(|(error, position)| VecDecodeError::Element { error, position })
                .either_into()
        })
    }

    fn end(self) -> Result<Self::Value, Self::Error> {
        // TODO: unexpected end
        self.0.end().map_err(|error| {
            error
                .map_left(VecDecodeError::Length)
                .map_right(|(error, position)| VecDecodeError::Element { error, position })
                .either_into()
        })
    }
}

impl<T> fmt::Debug for VecDecoder<T> where T: Decode + fmt::Debug, T::Decoder: Default + fmt::Debug {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("VecDecoder")
            .field(&self.0)
            .finish()
    }
}

/// Returned when decoding a varint-prefixed `Vec` of decodable element fails to parse.
#[derive(Debug)]
pub enum VecDecodeError<E> {
    /// Failed decoding length (varint).
    Length(VarIntDecodeError),
    /// Failed to decode element .
    Element { error: E, position: usize },
    UnexpectedEnd,
}

impl<E: fmt::Display> fmt::Display for VecDecodeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use internals::write_err;

        match self {
            Self::Length(error) => write_err!(f, "failed to parse length"; error),
            Self::Element { error, position } => write_err!(f, "failed to parse element at position {} (starting from 0)", position; error),
            Self::UnexpectedEnd => write!(f, "the input reached end (EOF) unexpectedly"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for VecDecodeError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Length(error) => Some(error),
            Self::Element { error, .. } => Some(error),
            Self::UnexpectedEnd => None,
        }
    }
}

impl<T: Decode> Default for VecDecoder<T> where T::Decoder: Default {
    fn default() -> Self {
        VecDecoder(VarIntDecoder::default().then(|len| {
            let cap = len.min(4000000) as usize;
            InnerVecDecoder {
                vec: Vec::with_capacity(cap),
                required: len as usize,
                decoder: Default::default(),
            }
        }))
    }
}


struct InnerVecDecoder<T: Decode> where T::Decoder: Default {
    vec: Vec<T>,
    required: usize,
    decoder: T::Decoder,
}

impl<T> fmt::Debug for InnerVecDecoder<T> where T: Decode + fmt::Debug, T::Decoder: Default + fmt::Debug {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("InnerVecDecoder")
            .field("vec", &self.vec)
            .field("required", &self.required)
            .field("decoder", &self.decoder)
            .finish()
    }
}

impl<T: Decode> Decoder for InnerVecDecoder<T> where T::Decoder: Default {
    type Value = Vec<T>;
    type Error = (<T::Decoder as Decoder>::Error, usize);

    fn decode_chunk(&mut self, bytes: &mut &[u8]) -> Result<(), Self::Error> {
        while self.vec.len() < self.required {
            self.decoder.decode_chunk(bytes).map_err(|error| (error, self.vec.len()))?;
            if !bytes.is_empty() {
                let item = self.decoder.take().map_err(|error| (error, self.vec.len()))?;
                self.vec.push(item);
            } else {
                return Ok(())
            }
        }
        Ok(())
    }

    fn end(mut self) -> Result<Self::Value, Self::Error> {
        while self.vec.len() < self.required {
            // If the item is zero-sized this will just produce enough
            // If the item is not zero sized this will error which is what we want
            let item = self.decoder.take().map_err(|error| (error, self.vec.len()))?;
            self.vec.push(item);
        }
        Ok(self.vec)
    }
}
