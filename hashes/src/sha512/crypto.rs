// SPDX-License-Identifier: CC0-1.0

use internals::slice::SliceExt;

use super::{HashEngine, BLOCK_SIZE};

#[allow(non_snake_case)]
fn Ch(x: u64, y: u64, z: u64) -> u64 { z ^ (x & (y ^ z)) }
#[allow(non_snake_case)]
fn Maj(x: u64, y: u64, z: u64) -> u64 { (x & y) | (z & (x | y)) }
#[allow(non_snake_case)]
fn Sigma0(x: u64) -> u64 { x.rotate_left(36) ^ x.rotate_left(30) ^ x.rotate_left(25) }
#[allow(non_snake_case)]
fn Sigma1(x: u64) -> u64 { x.rotate_left(50) ^ x.rotate_left(46) ^ x.rotate_left(23) }
fn sigma0(x: u64) -> u64 { x.rotate_left(63) ^ x.rotate_left(56) ^ (x >> 7) }
fn sigma1(x: u64) -> u64 { x.rotate_left(45) ^ x.rotate_left(3) ^ (x >> 6) }

#[cfg(feature = "small-hash")]
#[macro_use]
mod small_hash {
    use super::*;

    #[rustfmt::skip]
    pub(super) fn round(a: u64, b: u64, c: u64, d: &mut u64, e: u64,
                        f: u64, g: u64, h: &mut u64, k: u64, w: u64,
    ) {
        let t1 =
            h.wrapping_add(Sigma1(e)).wrapping_add(Ch(e, f, g)).wrapping_add(k).wrapping_add(w);
        let t2 = Sigma0(a).wrapping_add(Maj(a, b, c));
        *d = d.wrapping_add(t1);
        *h = t1.wrapping_add(t2);
    }
    #[rustfmt::skip]
    pub(super) fn later_round(a: u64, b: u64, c: u64, d: &mut u64, e: u64,
                              f: u64, g: u64, h: &mut u64, k: u64, w: u64,
                              w1: u64, w2: u64, w3: u64,
    ) -> u64 {
        let w = w.wrapping_add(sigma1(w1)).wrapping_add(w2).wrapping_add(sigma0(w3));
        round(a, b, c, d, e, f, g, h, k, w);
        w
    }

    macro_rules! round(
        // first round
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr) => (
            small_hash::round($a, $b, $c, &mut $d, $e, $f, $g, &mut $h, $k, $w)
        );
        // later rounds we reassign $w before doing the first-round computation
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr, $w1:expr, $w2:expr, $w3:expr) => (
            $w = small_hash::later_round($a, $b, $c, &mut $d, $e, $f, $g, &mut $h, $k, $w, $w1, $w2, $w3)
        )
    );
}

#[cfg(not(feature = "small-hash"))]
#[macro_use]
mod fast_hash {
    macro_rules! round(
        // first round
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr) => (
            let t1 = $h.wrapping_add(Sigma1($e)).wrapping_add(Ch($e, $f, $g)).wrapping_add($k).wrapping_add($w);
            let t2 = Sigma0($a).wrapping_add(Maj($a, $b, $c));
            $d = $d.wrapping_add(t1);
            $h = t1.wrapping_add(t2);
        );
        // later rounds we reassign $w before doing the first-round computation
        ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $k:expr, $w:expr, $w1:expr, $w2:expr, $w3:expr) => (
            $w = $w.wrapping_add(sigma1($w1)).wrapping_add($w2).wrapping_add(sigma0($w3));
            round!($a, $b, $c, $d, $e, $f, $g, $h, $k, $w);
        )
    );
}

impl HashEngine {
    // Algorithm copied from libsecp256k1
    pub(crate) fn process_block(&mut self) {
        debug_assert_eq!(self.buffer.len(), BLOCK_SIZE);

        let mut w = [0u64; 16];
        for (w_val, buff_bytes) in w.iter_mut().zip(self.buffer.bitcoin_as_chunks().0) {
            *w_val = u64::from_be_bytes(*buff_bytes);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        round!(a, b, c, d, e, f, g, h, 0x428a2f98d728ae22, w[0]);
        round!(h, a, b, c, d, e, f, g, 0x7137449123ef65cd, w[1]);
        round!(g, h, a, b, c, d, e, f, 0xb5c0fbcfec4d3b2f, w[2]);
        round!(f, g, h, a, b, c, d, e, 0xe9b5dba58189dbbc, w[3]);
        round!(e, f, g, h, a, b, c, d, 0x3956c25bf348b538, w[4]);
        round!(d, e, f, g, h, a, b, c, 0x59f111f1b605d019, w[5]);
        round!(c, d, e, f, g, h, a, b, 0x923f82a4af194f9b, w[6]);
        round!(b, c, d, e, f, g, h, a, 0xab1c5ed5da6d8118, w[7]);
        round!(a, b, c, d, e, f, g, h, 0xd807aa98a3030242, w[8]);
        round!(h, a, b, c, d, e, f, g, 0x12835b0145706fbe, w[9]);
        round!(g, h, a, b, c, d, e, f, 0x243185be4ee4b28c, w[10]);
        round!(f, g, h, a, b, c, d, e, 0x550c7dc3d5ffb4e2, w[11]);
        round!(e, f, g, h, a, b, c, d, 0x72be5d74f27b896f, w[12]);
        round!(d, e, f, g, h, a, b, c, 0x80deb1fe3b1696b1, w[13]);
        round!(c, d, e, f, g, h, a, b, 0x9bdc06a725c71235, w[14]);
        round!(b, c, d, e, f, g, h, a, 0xc19bf174cf692694, w[15]);

        round!(a, b, c, d, e, f, g, h, 0xe49b69c19ef14ad2, w[0], w[14], w[9], w[1]);
        round!(h, a, b, c, d, e, f, g, 0xefbe4786384f25e3, w[1], w[15], w[10], w[2]);
        round!(g, h, a, b, c, d, e, f, 0x0fc19dc68b8cd5b5, w[2], w[0], w[11], w[3]);
        round!(f, g, h, a, b, c, d, e, 0x240ca1cc77ac9c65, w[3], w[1], w[12], w[4]);
        round!(e, f, g, h, a, b, c, d, 0x2de92c6f592b0275, w[4], w[2], w[13], w[5]);
        round!(d, e, f, g, h, a, b, c, 0x4a7484aa6ea6e483, w[5], w[3], w[14], w[6]);
        round!(c, d, e, f, g, h, a, b, 0x5cb0a9dcbd41fbd4, w[6], w[4], w[15], w[7]);
        round!(b, c, d, e, f, g, h, a, 0x76f988da831153b5, w[7], w[5], w[0], w[8]);
        round!(a, b, c, d, e, f, g, h, 0x983e5152ee66dfab, w[8], w[6], w[1], w[9]);
        round!(h, a, b, c, d, e, f, g, 0xa831c66d2db43210, w[9], w[7], w[2], w[10]);
        round!(g, h, a, b, c, d, e, f, 0xb00327c898fb213f, w[10], w[8], w[3], w[11]);
        round!(f, g, h, a, b, c, d, e, 0xbf597fc7beef0ee4, w[11], w[9], w[4], w[12]);
        round!(e, f, g, h, a, b, c, d, 0xc6e00bf33da88fc2, w[12], w[10], w[5], w[13]);
        round!(d, e, f, g, h, a, b, c, 0xd5a79147930aa725, w[13], w[11], w[6], w[14]);
        round!(c, d, e, f, g, h, a, b, 0x06ca6351e003826f, w[14], w[12], w[7], w[15]);
        round!(b, c, d, e, f, g, h, a, 0x142929670a0e6e70, w[15], w[13], w[8], w[0]);

        round!(a, b, c, d, e, f, g, h, 0x27b70a8546d22ffc, w[0], w[14], w[9], w[1]);
        round!(h, a, b, c, d, e, f, g, 0x2e1b21385c26c926, w[1], w[15], w[10], w[2]);
        round!(g, h, a, b, c, d, e, f, 0x4d2c6dfc5ac42aed, w[2], w[0], w[11], w[3]);
        round!(f, g, h, a, b, c, d, e, 0x53380d139d95b3df, w[3], w[1], w[12], w[4]);
        round!(e, f, g, h, a, b, c, d, 0x650a73548baf63de, w[4], w[2], w[13], w[5]);
        round!(d, e, f, g, h, a, b, c, 0x766a0abb3c77b2a8, w[5], w[3], w[14], w[6]);
        round!(c, d, e, f, g, h, a, b, 0x81c2c92e47edaee6, w[6], w[4], w[15], w[7]);
        round!(b, c, d, e, f, g, h, a, 0x92722c851482353b, w[7], w[5], w[0], w[8]);
        round!(a, b, c, d, e, f, g, h, 0xa2bfe8a14cf10364, w[8], w[6], w[1], w[9]);
        round!(h, a, b, c, d, e, f, g, 0xa81a664bbc423001, w[9], w[7], w[2], w[10]);
        round!(g, h, a, b, c, d, e, f, 0xc24b8b70d0f89791, w[10], w[8], w[3], w[11]);
        round!(f, g, h, a, b, c, d, e, 0xc76c51a30654be30, w[11], w[9], w[4], w[12]);
        round!(e, f, g, h, a, b, c, d, 0xd192e819d6ef5218, w[12], w[10], w[5], w[13]);
        round!(d, e, f, g, h, a, b, c, 0xd69906245565a910, w[13], w[11], w[6], w[14]);
        round!(c, d, e, f, g, h, a, b, 0xf40e35855771202a, w[14], w[12], w[7], w[15]);
        round!(b, c, d, e, f, g, h, a, 0x106aa07032bbd1b8, w[15], w[13], w[8], w[0]);

        round!(a, b, c, d, e, f, g, h, 0x19a4c116b8d2d0c8, w[0], w[14], w[9], w[1]);
        round!(h, a, b, c, d, e, f, g, 0x1e376c085141ab53, w[1], w[15], w[10], w[2]);
        round!(g, h, a, b, c, d, e, f, 0x2748774cdf8eeb99, w[2], w[0], w[11], w[3]);
        round!(f, g, h, a, b, c, d, e, 0x34b0bcb5e19b48a8, w[3], w[1], w[12], w[4]);
        round!(e, f, g, h, a, b, c, d, 0x391c0cb3c5c95a63, w[4], w[2], w[13], w[5]);
        round!(d, e, f, g, h, a, b, c, 0x4ed8aa4ae3418acb, w[5], w[3], w[14], w[6]);
        round!(c, d, e, f, g, h, a, b, 0x5b9cca4f7763e373, w[6], w[4], w[15], w[7]);
        round!(b, c, d, e, f, g, h, a, 0x682e6ff3d6b2b8a3, w[7], w[5], w[0], w[8]);
        round!(a, b, c, d, e, f, g, h, 0x748f82ee5defb2fc, w[8], w[6], w[1], w[9]);
        round!(h, a, b, c, d, e, f, g, 0x78a5636f43172f60, w[9], w[7], w[2], w[10]);
        round!(g, h, a, b, c, d, e, f, 0x84c87814a1f0ab72, w[10], w[8], w[3], w[11]);
        round!(f, g, h, a, b, c, d, e, 0x8cc702081a6439ec, w[11], w[9], w[4], w[12]);
        round!(e, f, g, h, a, b, c, d, 0x90befffa23631e28, w[12], w[10], w[5], w[13]);
        round!(d, e, f, g, h, a, b, c, 0xa4506cebde82bde9, w[13], w[11], w[6], w[14]);
        round!(c, d, e, f, g, h, a, b, 0xbef9a3f7b2c67915, w[14], w[12], w[7], w[15]);
        round!(b, c, d, e, f, g, h, a, 0xc67178f2e372532b, w[15], w[13], w[8], w[0]);

        round!(a, b, c, d, e, f, g, h, 0xca273eceea26619c, w[0], w[14], w[9], w[1]);
        round!(h, a, b, c, d, e, f, g, 0xd186b8c721c0c207, w[1], w[15], w[10], w[2]);
        round!(g, h, a, b, c, d, e, f, 0xeada7dd6cde0eb1e, w[2], w[0], w[11], w[3]);
        round!(f, g, h, a, b, c, d, e, 0xf57d4f7fee6ed178, w[3], w[1], w[12], w[4]);
        round!(e, f, g, h, a, b, c, d, 0x06f067aa72176fba, w[4], w[2], w[13], w[5]);
        round!(d, e, f, g, h, a, b, c, 0x0a637dc5a2c898a6, w[5], w[3], w[14], w[6]);
        round!(c, d, e, f, g, h, a, b, 0x113f9804bef90dae, w[6], w[4], w[15], w[7]);
        round!(b, c, d, e, f, g, h, a, 0x1b710b35131c471b, w[7], w[5], w[0], w[8]);
        round!(a, b, c, d, e, f, g, h, 0x28db77f523047d84, w[8], w[6], w[1], w[9]);
        round!(h, a, b, c, d, e, f, g, 0x32caab7b40c72493, w[9], w[7], w[2], w[10]);
        round!(g, h, a, b, c, d, e, f, 0x3c9ebe0a15c9bebc, w[10], w[8], w[3], w[11]);
        round!(f, g, h, a, b, c, d, e, 0x431d67c49c100d4c, w[11], w[9], w[4], w[12]);
        round!(e, f, g, h, a, b, c, d, 0x4cc5d4becb3e42b6, w[12], w[10], w[5], w[13]);
        round!(d, e, f, g, h, a, b, c, 0x597f299cfc657e2a, w[13], w[11], w[6], w[14]);
        round!(c, d, e, f, g, h, a, b, 0x5fcb6fab3ad6faec, w[14], w[12], w[7], w[15]);
        round!(b, c, d, e, f, g, h, a, 0x6c44198c4a475817, w[15], w[13], w[8], w[0]);

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}
