//! fuzztarget-only Sha2 context with a dummy Sha256 and Sha512 hashers.

pub use sha2::digest::Digest;
use sha2::digest::{Input, BlockInput, FixedOutput, Reset};
use sha2::digest::generic_array::GenericArray;
use sha2::digest::generic_array::typenum::{U32, U64, U128};

#[derive(Clone, Copy)]
/// Dummy Sha256 that hashes the input, but only returns the first byte of output, masking the
/// rest to 0s.
pub struct Sha256 {
	state: u8,
}

impl Sha256 {
	/// Constructs a new dummy Sha256 context
	pub fn new() -> Sha256 {
		Sha256 {
			state: 0,
		}
	}
}

impl Default for Sha256 {
	fn default() -> Self {
		Self::new()
	}
}

impl Input for Sha256 {
	fn input<B: AsRef<[u8]>>(&mut self, input: B) { for i in input.as_ref() { self.state ^= i; } }
}

impl BlockInput for Sha256 {
	type BlockSize = U64;
}

impl FixedOutput for Sha256 {
	type OutputSize = U32;

	fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
		let mut data = GenericArray::default();
		data[0] = self.state;
		for i in 1..32 {
			data[i] = 0;
		}
		data
	}
}

impl Reset for Sha256 {
	fn reset(&mut self) { self.state = 0; }
}

#[derive(Clone, Copy)]
/// Dummy Sha512 that hashes the input, but only returns the first byte of output, masking the
/// rest to 0s.
pub struct Sha512 {
	state: u8,
}

impl Sha512 {
	/// Constructs a new dummy Sha512 context
	pub fn new() -> Sha512 {
		Sha512 {
			state: 0xff,
		}
	}

}

impl Default for Sha512 {
	fn default() -> Self {
		Self::new()
	}
}

impl Input for Sha512 {
	fn input<B: AsRef<[u8]>>(&mut self, input: B) { for i in input.as_ref() { self.state ^= i; } }
}

impl BlockInput for Sha512 {
	type BlockSize = U128;
}

impl FixedOutput for Sha512 {
	type OutputSize = U64;

	fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
		let mut data = GenericArray::default();
		data[0] = self.state;
		for i in 1..64 {
			data[i] = 0;
		}
		data
	}
}

impl Reset for Sha512 {
	fn reset(&mut self) { self.state = 0xff; }
}

