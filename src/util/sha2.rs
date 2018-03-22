//! fuzztarget-only Sha2 context with a dummy Sha256 and Sha512 hashers.

use crypto::digest::Digest;
use crypto::sha2;

#[derive(Clone, Copy)]
/// Dummy Sha256 that hashes the input, but only returns the first byte of output, masking the
/// rest to 0s.
pub struct Sha256 {
	state: sha2::Sha256,
}

impl Sha256 {
	/// Constructs a new dummy Sha256 context
	pub fn new() -> Sha256 {
		Sha256 {
			state: sha2::Sha256::new(),
		}
	}
}

impl Digest for Sha256 {
	fn result(&mut self, data: &mut [u8]) {
		self.state.result(data);
		for i in 1..32 {
			data[i] = 0;
		}
	}

	fn input(&mut self, data: &[u8]) { self.state.input(data); }
	fn reset(&mut self) { self.state.reset(); }
	fn output_bits(&self) -> usize { self.state.output_bits() }
	fn block_size(&self) -> usize { self.state.block_size() }
}

#[derive(Clone, Copy)]
/// Dummy Sha512 that hashes the input, but only returns the first byte of output, masking the
/// rest to 0s.
pub struct Sha512 {
	state: sha2::Sha512,
}

impl Sha512 {
	/// Constructs a new dummy Sha512 context
	pub fn new() -> Sha512 {
		Sha512 {
			state: sha2::Sha512::new(),
		}
	}
}

impl Digest for Sha512 {
	fn result(&mut self, data: &mut [u8]) {
		self.state.result(data);
		for i in 1..64 {
			data[i] = 0;
		}
	}

	fn input(&mut self, data: &[u8]) { self.state.input(data); }
	fn reset(&mut self) { self.state.reset(); }
	fn output_bits(&self) -> usize { self.state.output_bits() }
	fn block_size(&self) -> usize { self.state.block_size() }
}
