// SPDX-License-Identifier: CC0-1.0

//! I/O hashing support.
//!
//! Support for various hashing related things e.g.
//!
//! - Hashing to a writer.
//! - Implement I/O traits for hash engines.

use hashes::hmac::HmacEngine;
use hashes::{
    hash160, ripemd160, sha1, sha256, sha256d, sha256t, sha384, sha512, sha512_256, siphash24,
    HashEngine as _,
};

use crate::BufRead;

macro_rules! impl_write {
    ($ty: ty, $write_fn: expr, $flush_fn: expr $(, $bounded_ty: ident : $bounds: path),*) => {
        // `std::io::Write` is implemented in `bitcoin_hashes` because of the orphan rule.
        impl<$($bounded_ty: $bounds),*> crate::Write for $ty {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
                $write_fn(self, buf)}

            #[inline]
            fn flush(&mut self) -> crate::Result<()> {
                $flush_fn(self)
            }
        }
    }
}

impl_write!(
    hash160::HashEngine,
    |us: &mut hash160::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    ripemd160::HashEngine,
    |us: &mut ripemd160::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha1::HashEngine,
    |us: &mut sha1::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha256::HashEngine,
    |us: &mut sha256::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha256d::HashEngine,
    |us: &mut sha256d::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha256t::HashEngine<T>,
    |us: &mut sha256t::HashEngine<T>, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) },
    T: sha256t::Tag
);

impl_write!(
    sha384::HashEngine,
    |us: &mut sha384::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha512::HashEngine,
    |us: &mut sha512::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha512_256::HashEngine,
    |us: &mut sha512_256::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    siphash24::HashEngine,
    |us: &mut siphash24::HashEngine, buf| {
        hashes::HashEngine::input(us, buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    HmacEngine<T>,
    |us: &mut HmacEngine<T>, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) },
    T: hashes::HashEngine
);

/// Hashes data from a reader.
///
/// # Errors
///
/// If an I/O error occurs while reading from the underlying reader.
pub fn hash_reader<T>(reader: &mut impl BufRead) -> Result<T::Hash, crate::Error>
where
    T: hashes::HashEngine + Default,
{
    let mut engine = T::default();
    loop {
        let bytes = reader.fill_buf()?;

        let read = bytes.len();
        // Empty slice means EOF.
        if read == 0 {
            break;
        }

        engine.input(bytes);
        reader.consume(read);
    }
    Ok(engine.finalize())
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use alloc::{format, vec};

    use hashes::hmac;

    use super::*;
    use crate::{Cursor, Write as _};

    macro_rules! write_test {
        ($mod:ident, $exp_empty:expr, $exp_256:expr, $exp_64k:expr,) => {
            #[test]
            fn $mod() {
                let mut engine = $mod::Hash::engine();
                engine.write_all(&[]).unwrap();
                assert_eq!(format!("{}", $mod::Hash::from_engine(engine)), $exp_empty);

                let mut engine = $mod::Hash::engine();
                engine.write_all(&[1; 256]).unwrap();
                assert_eq!(format!("{}", $mod::Hash::from_engine(engine)), $exp_256);

                let mut engine = $mod::Hash::engine();
                let large_buffer = vec![99u8; 64000];
                engine.write_all(&large_buffer).unwrap();
                assert_eq!(format!("{}", $mod::Hash::from_engine(engine)), $exp_64k);
            }
        };
    }

    write_test!(
        sha1,
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "ac458b067c6b021c7e9358229b636e9d1e4cb154",
        "e4b66838f9f7b6f91e5be32a02ae78094df402e7",
    );

    write_test!(
        sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "2661920f2409dd6c8adeb0c44972959f232b6429afa913845d0fd95e7e768234",
        "5c5e904f5d4fd587c7a906bf846e08a927286f388c54c39213a4884695271bbc",
    );

    write_test!(
        sha256d,
        "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        "374000d830c75d10d9417e493a7652920f30efbd300e3fb092f24c28c20baf64",
        "0050d4148ad7a0437ca0643fad5bf4614cd95d9ba21fde52370b37dcc3f03307",
    );

    write_test!(
        sha384,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "82135637ef6d6dd31a20e2bc9998681a3eecaf8f8c76d45e545214de38439d9a533848ec75f53e4b1a8805709c5124d0",
        "fb7511d9a98c5686f9c2f55e242397815c9229d8759451e1710b8da6861e08d52f0357176f4b74f8cad9e23ab65411c7",
    );

    write_test!(
        sha512,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "57ecf739d3a7ca647639adae80a05f4f361304bfcbfa1ceba93296b096e74287\
         45fc10c142cecdd3bb587a3dba598c072f6f78b31cc0a06a3da0105ee51f75d6",
        "dd28f78c53f3bc9bd0c2dca9642a1ad402a70412f985c1f6e54fadb98ce9c458\
         4761df8d04ed04bb734ba48dd2106bb9ea54524f1394cdd18e6da3166e71c3ee",
    );

    write_test!(
        sha512_256,
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        "8d4bb96e7956cf5f08bf5c45f7982630c46b0b022f25cbaf722ae97c06a6e7a2",
        "3367646f3e264653f7dd664ac2cb6d3b96329e86ffb7a29a1082e2a4ddc9ee7a",
    );

    write_test!(
        ripemd160,
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "e571a1ca5b780aa52bafdb9ec852544ffca418ba",
        "ddd2ecce739e823629c7d46ab18918e9c4a51c75",
    );

    write_test!(
        hash160,
        "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        "671356a1a874695ad3bc20cae440f4360835bd5a",
        "a9608c952c8dbcc20c53803d2ca5ad31d64d9313",
    );

    #[test]
    fn hmac() {
        let mut engine = hmac::HmacEngine::<sha256::HashEngine>::new(&[0xde, 0xad, 0xbe, 0xef]);
        engine.write_all(&[]).unwrap();
        assert_eq!(
            format!("{}", engine.finalize()),
            "bf5515149cf797955c4d3194cca42472883281951697c8375d9d9b107f384225"
        );

        let mut engine = hmac::HmacEngine::<sha256::HashEngine>::new(&[0xde, 0xad, 0xbe, 0xef]);
        engine.write_all(&[1; 256]).unwrap();
        assert_eq!(
            format!("{}", engine.finalize()),
            "59c9aca10c81c73cb4c196d94db741b6bf2050e0153d5a45f2526bff34675ac5"
        );

        let mut engine = hmac::HmacEngine::<sha256::HashEngine>::new(&[0xde, 0xad, 0xbe, 0xef]);
        let large_buffer = vec![99u8; 64000];
        engine.write_all(&large_buffer).unwrap();
        assert_eq!(
            format!("{}", engine.finalize()),
            "30df499717415a395379a1eaabe50038036e4abb5afc94aa55c952f4aa57be08"
        );
    }

    #[test]
    fn siphash24() {
        let mut engine = siphash24::HashEngine::with_keys(0, 0);
        engine.write_all(&[]).unwrap();
        assert_eq!(format!("{}", siphash24::Hash::from_engine(engine)), "d70077739d4b921e");

        let mut engine = siphash24::HashEngine::with_keys(0, 0);
        engine.write_all(&[1; 256]).unwrap();
        assert_eq!(format!("{}", siphash24::Hash::from_engine(engine)), "3a3ccefde9b5b1e3");

        let mut engine = siphash24::HashEngine::with_keys(0, 0);
        let large_buffer = vec![99u8; 64000];
        engine.write_all(&large_buffer).unwrap();
        assert_eq!(format!("{}", siphash24::Hash::from_engine(engine)), "ce456e4e4ecbc5bf");
    }

    // Data and expected hashes taken from `bitcoin_hashes/tests/regression.rs`.
    const DATA: &str = "arbitrary data to hash as a regression test";
    const HMAC_KEY: &[u8] = b"some key";

    macro_rules! impl_hash_reader_test {
        ($($test_name:ident, $module:ident, $want:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let hash = $module::Hash::hash(DATA.as_bytes());
                    let got = format!("{}", hash);
                    assert_eq!(got, $want);

                    let mut reader = Cursor::new(DATA);
                    let hash_from_reader = $crate::hash_reader::<$module::HashEngine>(&mut reader).unwrap();
                    assert_eq!(hash_from_reader, hash)
                }
            )*
        }
    }

    impl_hash_reader_test! {
        hash_from_reader_hash160, hash160, "a17909f6d5373b0085c4180ba207126e5040f74d";
        hash_from_reader_ripemd160, ripemd160, "e6801701c77a1cd85662335258c7869631b4a9a8";
        hash_from_reader_sha1, sha1, "e1e81eeabadafa3d5d41cc3f405385426b0f47fd";
        hash_from_reader_sha256, sha256, "d291c6c5a07fa1d9315cdae090ebe14169fbe0a219cd55a48d0d2104eab6ec51";
        hash_from_reader_sha256d, sha256d, "93a743b022290bde3233a619b21aaebe06c5cf5cc959464c41be35711e37731b";
        hash_from_reader_sha384, sha384, "f545bd83d297978d47a7f26b858a54188499dfb4d7d570a6a2362c765031d57a29d7e002df5e34d184e70b65a4f47153";
        hash_from_reader_sha512, sha512, "057d0a37e9e0ac9a93acde0752748da059a27bcf946c7af00692ac1a95db8d21f965f40af22efc4710f100f8d3e43f79f77b1f48e1e400a95b7344b7bc0dfd10";
        hash_from_reader_sha512_256, sha512_256, "e204244c429b5bca037a2a8a6e7ed8a42b808ceaff182560840bb8c5c8e9a2ec";
    }

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
    pub struct RegHashTag; // Name comes from regression tests in `bitcoin_hashes`.

    impl sha256t::Tag for RegHashTag {
        const MIDSTATE: sha256::Midstate = sha256::Midstate::new([0xab; 32], 64);
    }

    type RegHash = sha256t::Hash<RegHashTag>;

    #[test]
    fn regression_sha256t() {
        let hash = RegHash::hash(DATA.as_bytes());
        let got = format!("{}", hash);
        let want = "17db326d7c13867376ccca1f8a211377be3cbeaeb372f167822284866ddf14ca";
        assert_eq!(got, want);
    }

    #[test]
    fn regression_hmac_sha256_with_key() {
        let mut engine = HmacEngine::<sha256::HashEngine>::new(HMAC_KEY);
        engine.input(DATA.as_bytes());
        let hash = engine.finalize();

        let got = format!("{}", hash);
        let want = "d159cecaf4adf90b6a641bab767e4817d3a51c414acea3682686c35ec0b37b52";
        assert_eq!(got, want);
    }

    #[test]
    fn regression_hmac_sha512_with_key() {
        let mut engine = HmacEngine::<sha512::HashEngine>::new(HMAC_KEY);
        engine.input(DATA.as_bytes());
        let hash = engine.finalize();

        let got = format!("{}", hash);
        let want = "8511773748f89ba22c07fb3a2981a12c1823695119de41f4a62aead6b848bd34939acf16475c35ed7956114fead3e794cc162ecd35e447a4dabc3227d55f757b";
        assert_eq!(got, want);
    }

    #[test]
    fn regression_siphash24_with_key() {
        let mut engine = siphash24::HashEngine::with_keys(0, 0);
        engine.input(DATA.as_bytes());
        let hash = siphash24::Hash::from_engine(engine);

        let got = format!("{}", hash);
        let want = "e823ed82311d601a";
        assert_eq!(got, want);
    }
}
