//! fuzztarget-only Sha2 context with a dummy Sha256 and Sha512 hashers.

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, Reset}

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

	fn result(&mut self) -> [u8; 32] {
		let mut data = [0_u8; 32];
		data[0] = self.state;
		for i in 1..32 {
			data[i] = 0;
		}
		data
	}

	fn input(&mut self, data: &[u8]) { for i in data { self.state ^= i; } }
	fn reset(&mut self) { self.state = 0; }
	fn output_bits(&self) -> usize { 256 }
	fn block_size(&self) -> usize { 64 }
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

	fn result(&mut self) {
		let mut data = [0_u8; 64];
		data[0] = self.state;
		for i in 1..64 {
			data[i] = 0;
		}
	}

	fn input(&mut self, data: &[u8]) { for i in data { self.state ^= i; } }
	fn reset(&mut self) { self.state = 0xff; }
	fn output_bits(&self) -> usize { 512 }
	fn block_size(&self) -> usize { 128 }
}
