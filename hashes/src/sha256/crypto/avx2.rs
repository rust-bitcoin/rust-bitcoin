// SPDX-License-Identifier: CC0-1.0

//! 8-way AVX2 SHA256 (for `SHA256d` of 64-byte inputs).

#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::inline_always)]
#![allow(non_snake_case)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m256i, _mm256_add_epi32, _mm256_and_si256, _mm256_extract_epi32, _mm256_or_si256,
    _mm256_set1_epi32, _mm256_set_epi32, _mm256_shuffle_epi8, _mm256_slli_epi32, _mm256_srli_epi32,
    _mm256_xor_si256,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m256i, _mm256_add_epi32, _mm256_and_si256, _mm256_extract_epi32, _mm256_or_si256,
    _mm256_set1_epi32, _mm256_set_epi32, _mm256_shuffle_epi8, _mm256_slli_epi32, _mm256_srli_epi32,
    _mm256_xor_si256,
};

// SIMD helpers copied from Core
// https://github.com/bitcoin/bitcoin/blob/master/src/crypto/sha256_avx2.cpp

#[inline(always)]
unsafe fn K(x: u32) -> __m256i { _mm256_set1_epi32(x as i32) }

#[inline(always)]
unsafe fn Add(x: __m256i, y: __m256i) -> __m256i { _mm256_add_epi32(x, y) }

#[inline(always)]
unsafe fn Add3(x: __m256i, y: __m256i, z: __m256i) -> __m256i { Add(Add(x, y), z) }

#[inline(always)]
unsafe fn Add4(x: __m256i, y: __m256i, z: __m256i, w: __m256i) -> __m256i {
    Add(Add(x, y), Add(z, w))
}

macro_rules! inc2 {
    ($w:ident, $a:expr) => {{
        $w = Add($w, $a);
        $w
    }};
}
macro_rules! inc3 {
    ($w:ident, $a:expr, $b:expr) => {{
        $w = Add3($w, $a, $b);
        $w
    }};
}
macro_rules! inc4 {
    ($w:ident, $a:expr, $b:expr, $c:expr) => {{
        $w = Add4($w, $a, $b, $c);
        $w
    }};
}

#[inline(always)]
unsafe fn Xor(x: __m256i, y: __m256i) -> __m256i { _mm256_xor_si256(x, y) }

#[inline(always)]
unsafe fn Xor3(x: __m256i, y: __m256i, z: __m256i) -> __m256i { Xor(Xor(x, y), z) }

#[inline(always)]
unsafe fn Or(x: __m256i, y: __m256i) -> __m256i { _mm256_or_si256(x, y) }

#[inline(always)]
unsafe fn And(x: __m256i, y: __m256i) -> __m256i { _mm256_and_si256(x, y) }

#[inline(always)]
unsafe fn ShR<const N: i32>(x: __m256i) -> __m256i { _mm256_srli_epi32::<N>(x) }

#[inline(always)]
unsafe fn ShL<const N: i32>(x: __m256i) -> __m256i { _mm256_slli_epi32::<N>(x) }

#[inline(always)]
unsafe fn Ch(x: __m256i, y: __m256i, z: __m256i) -> __m256i { Xor(z, And(x, Xor(y, z))) }

#[inline(always)]
unsafe fn Maj(x: __m256i, y: __m256i, z: __m256i) -> __m256i { Or(And(x, y), And(z, Or(x, y))) }

#[inline(always)]
unsafe fn Sigma0(x: __m256i) -> __m256i {
    Xor3(
        Or(ShR::<2>(x), ShL::<30>(x)),
        Or(ShR::<13>(x), ShL::<19>(x)),
        Or(ShR::<22>(x), ShL::<10>(x)),
    )
}

#[inline(always)]
unsafe fn Sigma1(x: __m256i) -> __m256i {
    Xor3(
        Or(ShR::<6>(x), ShL::<26>(x)),
        Or(ShR::<11>(x), ShL::<21>(x)),
        Or(ShR::<25>(x), ShL::<7>(x)),
    )
}

#[inline(always)]
unsafe fn sigma0(x: __m256i) -> __m256i {
    Xor3(Or(ShR::<7>(x), ShL::<25>(x)), Or(ShR::<18>(x), ShL::<14>(x)), ShR::<3>(x))
}

#[inline(always)]
unsafe fn sigma1(x: __m256i) -> __m256i {
    Xor3(Or(ShR::<17>(x), ShL::<15>(x)), Or(ShR::<19>(x), ShL::<13>(x)), ShR::<10>(x))
}

// One round of SHA-256.
macro_rules! round {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $kw:expr) => {{
        let t1 = Add4($h, Sigma1($e), Ch($e, $f, $g), $kw);
        let t2 = Add(Sigma0($a), Maj($a, $b, $c));
        $d = Add($d, t1);
        $h = Add(t1, t2);
    }};
}

#[inline(always)]
unsafe fn Read8(input: &[[u8; 64]; 8], offset: usize) -> __m256i {
    let ret = _mm256_set_epi32(
        i32::from_le_bytes(input[0][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[1][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[2][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[3][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[4][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[5][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[6][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[7][offset..offset + 4].try_into().unwrap()),
    );
    _mm256_shuffle_epi8(
        ret,
        _mm256_set_epi32(
            0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607,
            0x00010203,
        ),
    )
}

#[inline(always)]
unsafe fn Write8(output: &mut [[u8; 32]; 8], offset: usize, v: __m256i) {
    let v = _mm256_shuffle_epi8(
        v,
        _mm256_set_epi32(
            0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203, 0x0C0D0E0F, 0x08090A0B, 0x04050607,
            0x00010203,
        ),
    );
    output[0][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<7>(v).to_le_bytes());
    output[1][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<6>(v).to_le_bytes());
    output[2][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<5>(v).to_le_bytes());
    output[3][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<4>(v).to_le_bytes());
    output[4][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<3>(v).to_le_bytes());
    output[5][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<2>(v).to_le_bytes());
    output[6][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<1>(v).to_le_bytes());
    output[7][offset..offset + 4].copy_from_slice(&_mm256_extract_epi32::<0>(v).to_le_bytes());
}

/// Computes `SHA256d` of eight 64-byte inputs in parallel using AVX2
#[target_feature(enable = "avx,avx2")]
pub(super) unsafe fn sha256d_64_8way(output: &mut [[u8; 32]; 8], input: &[[u8; 64]; 8]) {
    // ------------------ Transform 1 -------------------
    let mut a = K(0x6a09e667);
    let mut b = K(0xbb67ae85);
    let mut c = K(0x3c6ef372);
    let mut d = K(0xa54ff53a);
    let mut e = K(0x510e527f);
    let mut f = K(0x9b05688c);
    let mut g = K(0x1f83d9ab);
    let mut h = K(0x5be0cd19);

    let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7);
    let (mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15);

    // Rounds 0-15: message schedule comes directly from the input
    round!(
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        Add(K(0x428a2f98), {
            w0 = Read8(input, 0);
            w0
        })
    );
    round!(
        h,
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        Add(K(0x71374491), {
            w1 = Read8(input, 4);
            w1
        })
    );
    round!(
        g,
        h,
        a,
        b,
        c,
        d,
        e,
        f,
        Add(K(0xb5c0fbcf), {
            w2 = Read8(input, 8);
            w2
        })
    );
    round!(
        f,
        g,
        h,
        a,
        b,
        c,
        d,
        e,
        Add(K(0xe9b5dba5), {
            w3 = Read8(input, 12);
            w3
        })
    );
    round!(
        e,
        f,
        g,
        h,
        a,
        b,
        c,
        d,
        Add(K(0x3956c25b), {
            w4 = Read8(input, 16);
            w4
        })
    );
    round!(
        d,
        e,
        f,
        g,
        h,
        a,
        b,
        c,
        Add(K(0x59f111f1), {
            w5 = Read8(input, 20);
            w5
        })
    );
    round!(
        c,
        d,
        e,
        f,
        g,
        h,
        a,
        b,
        Add(K(0x923f82a4), {
            w6 = Read8(input, 24);
            w6
        })
    );
    round!(
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        a,
        Add(K(0xab1c5ed5), {
            w7 = Read8(input, 28);
            w7
        })
    );
    round!(
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        Add(K(0xd807aa98), {
            w8 = Read8(input, 32);
            w8
        })
    );
    round!(
        h,
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        Add(K(0x12835b01), {
            w9 = Read8(input, 36);
            w9
        })
    );
    round!(
        g,
        h,
        a,
        b,
        c,
        d,
        e,
        f,
        Add(K(0x243185be), {
            w10 = Read8(input, 40);
            w10
        })
    );
    round!(
        f,
        g,
        h,
        a,
        b,
        c,
        d,
        e,
        Add(K(0x550c7dc3), {
            w11 = Read8(input, 44);
            w11
        })
    );
    round!(
        e,
        f,
        g,
        h,
        a,
        b,
        c,
        d,
        Add(K(0x72be5d74), {
            w12 = Read8(input, 48);
            w12
        })
    );
    round!(
        d,
        e,
        f,
        g,
        h,
        a,
        b,
        c,
        Add(K(0x80deb1fe), {
            w13 = Read8(input, 52);
            w13
        })
    );
    round!(
        c,
        d,
        e,
        f,
        g,
        h,
        a,
        b,
        Add(K(0x9bdc06a7), {
            w14 = Read8(input, 56);
            w14
        })
    );
    round!(
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        a,
        Add(K(0xc19bf174), {
            w15 = Read8(input, 60);
            w15
        })
    );

    // Rounds 16-63: expanded message schedule
    round!(a, b, c, d, e, f, g, h, Add(K(0xe49b69c1), inc4!(w0, sigma1(w14), w9, sigma0(w1))));
    round!(h, a, b, c, d, e, f, g, Add(K(0xefbe4786), inc4!(w1, sigma1(w15), w10, sigma0(w2))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x0fc19dc6), inc4!(w2, sigma1(w0), w11, sigma0(w3))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x240ca1cc), inc4!(w3, sigma1(w1), w12, sigma0(w4))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x2de92c6f), inc4!(w4, sigma1(w2), w13, sigma0(w5))));
    round!(d, e, f, g, h, a, b, c, Add(K(0x4a7484aa), inc4!(w5, sigma1(w3), w14, sigma0(w6))));
    round!(c, d, e, f, g, h, a, b, Add(K(0x5cb0a9dc), inc4!(w6, sigma1(w4), w15, sigma0(w7))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x76f988da), inc4!(w7, sigma1(w5), w0, sigma0(w8))));
    round!(a, b, c, d, e, f, g, h, Add(K(0x983e5152), inc4!(w8, sigma1(w6), w1, sigma0(w9))));
    round!(h, a, b, c, d, e, f, g, Add(K(0xa831c66d), inc4!(w9, sigma1(w7), w2, sigma0(w10))));
    round!(g, h, a, b, c, d, e, f, Add(K(0xb00327c8), inc4!(w10, sigma1(w8), w3, sigma0(w11))));
    round!(f, g, h, a, b, c, d, e, Add(K(0xbf597fc7), inc4!(w11, sigma1(w9), w4, sigma0(w12))));
    round!(e, f, g, h, a, b, c, d, Add(K(0xc6e00bf3), inc4!(w12, sigma1(w10), w5, sigma0(w13))));
    round!(d, e, f, g, h, a, b, c, Add(K(0xd5a79147), inc4!(w13, sigma1(w11), w6, sigma0(w14))));
    round!(c, d, e, f, g, h, a, b, Add(K(0x06ca6351), inc4!(w14, sigma1(w12), w7, sigma0(w15))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x14292967), inc4!(w15, sigma1(w13), w8, sigma0(w0))));
    round!(a, b, c, d, e, f, g, h, Add(K(0x27b70a85), inc4!(w0, sigma1(w14), w9, sigma0(w1))));
    round!(h, a, b, c, d, e, f, g, Add(K(0x2e1b2138), inc4!(w1, sigma1(w15), w10, sigma0(w2))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x4d2c6dfc), inc4!(w2, sigma1(w0), w11, sigma0(w3))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x53380d13), inc4!(w3, sigma1(w1), w12, sigma0(w4))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x650a7354), inc4!(w4, sigma1(w2), w13, sigma0(w5))));
    round!(d, e, f, g, h, a, b, c, Add(K(0x766a0abb), inc4!(w5, sigma1(w3), w14, sigma0(w6))));
    round!(c, d, e, f, g, h, a, b, Add(K(0x81c2c92e), inc4!(w6, sigma1(w4), w15, sigma0(w7))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x92722c85), inc4!(w7, sigma1(w5), w0, sigma0(w8))));
    round!(a, b, c, d, e, f, g, h, Add(K(0xa2bfe8a1), inc4!(w8, sigma1(w6), w1, sigma0(w9))));
    round!(h, a, b, c, d, e, f, g, Add(K(0xa81a664b), inc4!(w9, sigma1(w7), w2, sigma0(w10))));
    round!(g, h, a, b, c, d, e, f, Add(K(0xc24b8b70), inc4!(w10, sigma1(w8), w3, sigma0(w11))));
    round!(f, g, h, a, b, c, d, e, Add(K(0xc76c51a3), inc4!(w11, sigma1(w9), w4, sigma0(w12))));
    round!(e, f, g, h, a, b, c, d, Add(K(0xd192e819), inc4!(w12, sigma1(w10), w5, sigma0(w13))));
    round!(d, e, f, g, h, a, b, c, Add(K(0xd6990624), inc4!(w13, sigma1(w11), w6, sigma0(w14))));
    round!(c, d, e, f, g, h, a, b, Add(K(0xf40e3585), inc4!(w14, sigma1(w12), w7, sigma0(w15))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x106aa070), inc4!(w15, sigma1(w13), w8, sigma0(w0))));
    round!(a, b, c, d, e, f, g, h, Add(K(0x19a4c116), inc4!(w0, sigma1(w14), w9, sigma0(w1))));
    round!(h, a, b, c, d, e, f, g, Add(K(0x1e376c08), inc4!(w1, sigma1(w15), w10, sigma0(w2))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x2748774c), inc4!(w2, sigma1(w0), w11, sigma0(w3))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x34b0bcb5), inc4!(w3, sigma1(w1), w12, sigma0(w4))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x391c0cb3), inc4!(w4, sigma1(w2), w13, sigma0(w5))));
    round!(d, e, f, g, h, a, b, c, Add(K(0x4ed8aa4a), inc4!(w5, sigma1(w3), w14, sigma0(w6))));
    round!(c, d, e, f, g, h, a, b, Add(K(0x5b9cca4f), inc4!(w6, sigma1(w4), w15, sigma0(w7))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x682e6ff3), inc4!(w7, sigma1(w5), w0, sigma0(w8))));
    round!(a, b, c, d, e, f, g, h, Add(K(0x748f82ee), inc4!(w8, sigma1(w6), w1, sigma0(w9))));
    round!(h, a, b, c, d, e, f, g, Add(K(0x78a5636f), inc4!(w9, sigma1(w7), w2, sigma0(w10))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x84c87814), inc4!(w10, sigma1(w8), w3, sigma0(w11))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x8cc70208), inc4!(w11, sigma1(w9), w4, sigma0(w12))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x90befffa), inc4!(w12, sigma1(w10), w5, sigma0(w13))));
    round!(d, e, f, g, h, a, b, c, Add(K(0xa4506ceb), inc4!(w13, sigma1(w11), w6, sigma0(w14))));
    round!(c, d, e, f, g, h, a, b, Add(K(0xbef9a3f7), inc4!(w14, sigma1(w12), w7, sigma0(w15))));
    round!(b, c, d, e, f, g, h, a, Add(K(0xc67178f2), inc4!(w15, sigma1(w13), w8, sigma0(w0))));

    // Transform 1: Update state
    a = Add(a, K(0x6a09e667));
    b = Add(b, K(0xbb67ae85));
    c = Add(c, K(0x3c6ef372));
    d = Add(d, K(0xa54ff53a));
    e = Add(e, K(0x510e527f));
    f = Add(f, K(0x9b05688c));
    g = Add(g, K(0x1f83d9ab));
    h = Add(h, K(0x5be0cd19));

    // Save state
    let s0 = a;
    let s1 = b;
    let s2 = c;
    let s3 = d;
    let s4 = e;
    let s5 = f;
    let s6 = g;
    let s7 = h;

    // ------------------ Transform 2 -------------------
    // W is fully constant here, so we just use pre-computed K[i] + W[i] constant
    round!(a, b, c, d, e, f, g, h, K(0xc28a2f98));
    round!(h, a, b, c, d, e, f, g, K(0x71374491));
    round!(g, h, a, b, c, d, e, f, K(0xb5c0fbcf));
    round!(f, g, h, a, b, c, d, e, K(0xe9b5dba5));
    round!(e, f, g, h, a, b, c, d, K(0x3956c25b));
    round!(d, e, f, g, h, a, b, c, K(0x59f111f1));
    round!(c, d, e, f, g, h, a, b, K(0x923f82a4));
    round!(b, c, d, e, f, g, h, a, K(0xab1c5ed5));
    round!(a, b, c, d, e, f, g, h, K(0xd807aa98));
    round!(h, a, b, c, d, e, f, g, K(0x12835b01));
    round!(g, h, a, b, c, d, e, f, K(0x243185be));
    round!(f, g, h, a, b, c, d, e, K(0x550c7dc3));
    round!(e, f, g, h, a, b, c, d, K(0x72be5d74));
    round!(d, e, f, g, h, a, b, c, K(0x80deb1fe));
    round!(c, d, e, f, g, h, a, b, K(0x9bdc06a7));
    round!(b, c, d, e, f, g, h, a, K(0xc19bf374));
    round!(a, b, c, d, e, f, g, h, K(0x649b69c1));
    round!(h, a, b, c, d, e, f, g, K(0xf0fe4786));
    round!(g, h, a, b, c, d, e, f, K(0x0fe1edc6));
    round!(f, g, h, a, b, c, d, e, K(0x240cf254));
    round!(e, f, g, h, a, b, c, d, K(0x4fe9346f));
    round!(d, e, f, g, h, a, b, c, K(0x6cc984be));
    round!(c, d, e, f, g, h, a, b, K(0x61b9411e));
    round!(b, c, d, e, f, g, h, a, K(0x16f988fa));
    round!(a, b, c, d, e, f, g, h, K(0xf2c65152));
    round!(h, a, b, c, d, e, f, g, K(0xa88e5a6d));
    round!(g, h, a, b, c, d, e, f, K(0xb019fc65));
    round!(f, g, h, a, b, c, d, e, K(0xb9d99ec7));
    round!(e, f, g, h, a, b, c, d, K(0x9a1231c3));
    round!(d, e, f, g, h, a, b, c, K(0xe70eeaa0));
    round!(c, d, e, f, g, h, a, b, K(0xfdb1232b));
    round!(b, c, d, e, f, g, h, a, K(0xc7353eb0));
    round!(a, b, c, d, e, f, g, h, K(0x3069bad5));
    round!(h, a, b, c, d, e, f, g, K(0xcb976d5f));
    round!(g, h, a, b, c, d, e, f, K(0x5a0f118f));
    round!(f, g, h, a, b, c, d, e, K(0xdc1eeefd));
    round!(e, f, g, h, a, b, c, d, K(0x0a35b689));
    round!(d, e, f, g, h, a, b, c, K(0xde0b7a04));
    round!(c, d, e, f, g, h, a, b, K(0x58f4ca9d));
    round!(b, c, d, e, f, g, h, a, K(0xe15d5b16));
    round!(a, b, c, d, e, f, g, h, K(0x007f3e86));
    round!(h, a, b, c, d, e, f, g, K(0x37088980));
    round!(g, h, a, b, c, d, e, f, K(0xa507ea32));
    round!(f, g, h, a, b, c, d, e, K(0x6fab9537));
    round!(e, f, g, h, a, b, c, d, K(0x17406110));
    round!(d, e, f, g, h, a, b, c, K(0x0d8cd6f1));
    round!(c, d, e, f, g, h, a, b, K(0xcdaa3b6d));
    round!(b, c, d, e, f, g, h, a, K(0xc0bbbe37));
    round!(a, b, c, d, e, f, g, h, K(0x83613bda));
    round!(h, a, b, c, d, e, f, g, K(0xdb48a363));
    round!(g, h, a, b, c, d, e, f, K(0x0b02e931));
    round!(f, g, h, a, b, c, d, e, K(0x6fd15ca7));
    round!(e, f, g, h, a, b, c, d, K(0x521afaca));
    round!(d, e, f, g, h, a, b, c, K(0x31338431));
    round!(c, d, e, f, g, h, a, b, K(0x6ed41a95));
    round!(b, c, d, e, f, g, h, a, K(0x6d437890));
    round!(a, b, c, d, e, f, g, h, K(0xc39c91f2));
    round!(h, a, b, c, d, e, f, g, K(0x9eccabbd));
    round!(g, h, a, b, c, d, e, f, K(0xb5c9a0e6));
    round!(f, g, h, a, b, c, d, e, K(0x532fb63c));
    round!(e, f, g, h, a, b, c, d, K(0xd2c741c6));
    round!(d, e, f, g, h, a, b, c, K(0x07237ea3));
    round!(c, d, e, f, g, h, a, b, K(0xa4954b68));
    round!(b, c, d, e, f, g, h, a, K(0x4c191d76));

    // Transform 2: Update state
    w0 = Add(s0, a);
    w1 = Add(s1, b);
    w2 = Add(s2, c);
    w3 = Add(s3, d);
    w4 = Add(s4, e);
    w5 = Add(s5, f);
    w6 = Add(s6, g);
    w7 = Add(s7, h);

    // ------------------ Transform 3 -------------------
    a = K(0x6a09e667);
    b = K(0xbb67ae85);
    c = K(0x3c6ef372);
    d = K(0xa54ff53a);
    e = K(0x510e527f);
    f = K(0x9b05688c);
    g = K(0x1f83d9ab);
    h = K(0x5be0cd19);

    // Rounds 0-7: feed in the 32 byte message (w0..w7)
    round!(a, b, c, d, e, f, g, h, Add(K(0x428a2f98), w0));
    round!(h, a, b, c, d, e, f, g, Add(K(0x71374491), w1));
    round!(g, h, a, b, c, d, e, f, Add(K(0xb5c0fbcf), w2));
    round!(f, g, h, a, b, c, d, e, Add(K(0xe9b5dba5), w3));
    round!(e, f, g, h, a, b, c, d, Add(K(0x3956c25b), w4));
    round!(d, e, f, g, h, a, b, c, Add(K(0x59f111f1), w5));
    round!(c, d, e, f, g, h, a, b, Add(K(0x923f82a4), w6));
    round!(b, c, d, e, f, g, h, a, Add(K(0xab1c5ed5), w7));

    // Rounds 8-15: known padding
    round!(a, b, c, d, e, f, g, h, K(0x5807aa98));
    round!(h, a, b, c, d, e, f, g, K(0x12835b01));
    round!(g, h, a, b, c, d, e, f, K(0x243185be));
    round!(f, g, h, a, b, c, d, e, K(0x550c7dc3));
    round!(e, f, g, h, a, b, c, d, K(0x72be5d74));
    round!(d, e, f, g, h, a, b, c, K(0x80deb1fe));
    round!(c, d, e, f, g, h, a, b, K(0x9bdc06a7));
    round!(b, c, d, e, f, g, h, a, K(0xc19bf274));
    round!(a, b, c, d, e, f, g, h, Add(K(0xe49b69c1), inc2!(w0, sigma0(w1))));
    round!(h, a, b, c, d, e, f, g, Add(K(0xefbe4786), inc3!(w1, K(0x00a00000), sigma0(w2))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x0fc19dc6), inc3!(w2, sigma1(w0), sigma0(w3))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x240ca1cc), inc3!(w3, sigma1(w1), sigma0(w4))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x2de92c6f), inc3!(w4, sigma1(w2), sigma0(w5))));
    round!(d, e, f, g, h, a, b, c, Add(K(0x4a7484aa), inc3!(w5, sigma1(w3), sigma0(w6))));
    round!(
        c,
        d,
        e,
        f,
        g,
        h,
        a,
        b,
        Add(K(0x5cb0a9dc), inc4!(w6, sigma1(w4), K(0x00000100), sigma0(w7)))
    );
    round!(b, c, d, e, f, g, h, a, Add(K(0x76f988da), inc4!(w7, sigma1(w5), w0, K(0x11002000))));
    round!(
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        Add(K(0x983e5152), {
            w8 = Add3(K(0x80000000), sigma1(w6), w1);
            w8
        })
    );
    round!(
        h,
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        Add(K(0xa831c66d), {
            w9 = Add(sigma1(w7), w2);
            w9
        })
    );
    round!(
        g,
        h,
        a,
        b,
        c,
        d,
        e,
        f,
        Add(K(0xb00327c8), {
            w10 = Add(sigma1(w8), w3);
            w10
        })
    );
    round!(
        f,
        g,
        h,
        a,
        b,
        c,
        d,
        e,
        Add(K(0xbf597fc7), {
            w11 = Add(sigma1(w9), w4);
            w11
        })
    );
    round!(
        e,
        f,
        g,
        h,
        a,
        b,
        c,
        d,
        Add(K(0xc6e00bf3), {
            w12 = Add(sigma1(w10), w5);
            w12
        })
    );
    round!(
        d,
        e,
        f,
        g,
        h,
        a,
        b,
        c,
        Add(K(0xd5a79147), {
            w13 = Add(sigma1(w11), w6);
            w13
        })
    );
    round!(
        c,
        d,
        e,
        f,
        g,
        h,
        a,
        b,
        Add(K(0x06ca6351), {
            w14 = Add3(sigma1(w12), w7, K(0x00400022));
            w14
        })
    );
    round!(
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        a,
        Add(K(0x14292967), {
            w15 = Add4(K(0x00000100), sigma1(w13), w8, sigma0(w0));
            w15
        })
    );
    round!(a, b, c, d, e, f, g, h, Add(K(0x27b70a85), inc4!(w0, sigma1(w14), w9, sigma0(w1))));
    round!(h, a, b, c, d, e, f, g, Add(K(0x2e1b2138), inc4!(w1, sigma1(w15), w10, sigma0(w2))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x4d2c6dfc), inc4!(w2, sigma1(w0), w11, sigma0(w3))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x53380d13), inc4!(w3, sigma1(w1), w12, sigma0(w4))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x650a7354), inc4!(w4, sigma1(w2), w13, sigma0(w5))));
    round!(d, e, f, g, h, a, b, c, Add(K(0x766a0abb), inc4!(w5, sigma1(w3), w14, sigma0(w6))));
    round!(c, d, e, f, g, h, a, b, Add(K(0x81c2c92e), inc4!(w6, sigma1(w4), w15, sigma0(w7))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x92722c85), inc4!(w7, sigma1(w5), w0, sigma0(w8))));
    round!(a, b, c, d, e, f, g, h, Add(K(0xa2bfe8a1), inc4!(w8, sigma1(w6), w1, sigma0(w9))));
    round!(h, a, b, c, d, e, f, g, Add(K(0xa81a664b), inc4!(w9, sigma1(w7), w2, sigma0(w10))));
    round!(g, h, a, b, c, d, e, f, Add(K(0xc24b8b70), inc4!(w10, sigma1(w8), w3, sigma0(w11))));
    round!(f, g, h, a, b, c, d, e, Add(K(0xc76c51a3), inc4!(w11, sigma1(w9), w4, sigma0(w12))));
    round!(e, f, g, h, a, b, c, d, Add(K(0xd192e819), inc4!(w12, sigma1(w10), w5, sigma0(w13))));
    round!(d, e, f, g, h, a, b, c, Add(K(0xd6990624), inc4!(w13, sigma1(w11), w6, sigma0(w14))));
    round!(c, d, e, f, g, h, a, b, Add(K(0xf40e3585), inc4!(w14, sigma1(w12), w7, sigma0(w15))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x106aa070), inc4!(w15, sigma1(w13), w8, sigma0(w0))));
    round!(a, b, c, d, e, f, g, h, Add(K(0x19a4c116), inc4!(w0, sigma1(w14), w9, sigma0(w1))));
    round!(h, a, b, c, d, e, f, g, Add(K(0x1e376c08), inc4!(w1, sigma1(w15), w10, sigma0(w2))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x2748774c), inc4!(w2, sigma1(w0), w11, sigma0(w3))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x34b0bcb5), inc4!(w3, sigma1(w1), w12, sigma0(w4))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x391c0cb3), inc4!(w4, sigma1(w2), w13, sigma0(w5))));
    round!(d, e, f, g, h, a, b, c, Add(K(0x4ed8aa4a), inc4!(w5, sigma1(w3), w14, sigma0(w6))));
    round!(c, d, e, f, g, h, a, b, Add(K(0x5b9cca4f), inc4!(w6, sigma1(w4), w15, sigma0(w7))));
    round!(b, c, d, e, f, g, h, a, Add(K(0x682e6ff3), inc4!(w7, sigma1(w5), w0, sigma0(w8))));
    round!(a, b, c, d, e, f, g, h, Add(K(0x748f82ee), inc4!(w8, sigma1(w6), w1, sigma0(w9))));
    round!(h, a, b, c, d, e, f, g, Add(K(0x78a5636f), inc4!(w9, sigma1(w7), w2, sigma0(w10))));
    round!(g, h, a, b, c, d, e, f, Add(K(0x84c87814), inc4!(w10, sigma1(w8), w3, sigma0(w11))));
    round!(f, g, h, a, b, c, d, e, Add(K(0x8cc70208), inc4!(w11, sigma1(w9), w4, sigma0(w12))));
    round!(e, f, g, h, a, b, c, d, Add(K(0x90befffa), inc4!(w12, sigma1(w10), w5, sigma0(w13))));
    round!(d, e, f, g, h, a, b, c, Add(K(0xa4506ceb), inc4!(w13, sigma1(w11), w6, sigma0(w14))));
    round!(c, d, e, f, g, h, a, b, Add(K(0xbef9a3f7), inc4!(w14, sigma1(w12), w7, sigma0(w15))));
    round!(b, c, d, e, f, g, h, a, Add(K(0xc67178f2), inc4!(w15, sigma1(w13), w8, sigma0(w0))));

    // Transform 3:  Store result
    Write8(output, 0, Add(a, K(0x6a09e667)));
    Write8(output, 4, Add(b, K(0xbb67ae85)));
    Write8(output, 8, Add(c, K(0x3c6ef372)));
    Write8(output, 12, Add(d, K(0xa54ff53a)));
    Write8(output, 16, Add(e, K(0x510e527f)));
    Write8(output, 20, Add(f, K(0x9b05688c)));
    Write8(output, 24, Add(g, K(0x1f83d9ab)));
    Write8(output, 28, Add(h, K(0x5be0cd19)));
}
