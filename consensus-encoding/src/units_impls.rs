//! Decoders and encoders for types from [`bitcoin-units`](units).

use super::{Decode, Encode, EncodeTc};
use units::Amount;

mapped_decoder! {
    Amount => #[derive(Default)] pub struct AmountDecoder(<u64 as Decode>::Decoder) using Amount::from_sat;
}

encoder_newtype! {
    Amount => pub struct AmountEncoder(<u64 as EncodeTc<'static>>::Encoder);
}

impl Encode for Amount {
    const MIN_ENCODED_LEN: usize = 8;
    const IS_KNOWN_LEN: bool = true;

    fn encoder(&self) -> <Self as EncodeTc<'_>>::Encoder {
        AmountEncoder(self.to_sat().encoder())
    }

    fn dyn_encoded_len(&self, max_steps: usize) -> (usize, usize) {
        (0, max_steps)
    }
}
