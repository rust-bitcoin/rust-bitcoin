// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Taproot.
//!
// FIXME: This comment is not fully descriptive because of `TaprootSpendInfo`.
//! This module provides support for taproot tagged hashes.

/// Re-export everything from the [`primitives::taproot`] module.
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::primitives::taproot::*;

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use hashes::sha256t::Tag;
    use hashes::{sha256, Hash, HashEngine};
    use hex::FromHex;
    use secp256k1::{Secp256k1, VerifyOnly};

    use super::*;
    use crate::crypto::key::{TapTweak, TweakedPublicKey, UntweakedPublicKey, XOnlyPublicKey};
    use crate::prelude::*;
    use crate::sighash::{TapSighash, TapSighashTag};
    use crate::{Address, KnownHrp, ScriptBuf};
    extern crate serde_json;

    #[cfg(feature = "serde")]
    use {
        hex::test_hex_unwrap as hex,
        serde_test::Configure,
        serde_test::{assert_tokens, Token},
    };

    fn tag_engine(tag_name: &str) -> sha256::HashEngine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
        engine.input(tag_hash.as_ref());
        engine.input(tag_hash.as_ref());
        engine
    }

    #[test]
    fn test_midstates() {
        // test that engine creation roundtrips
        assert_eq!(tag_engine("TapLeaf").midstate(), TapLeafTag::engine().midstate());
        assert_eq!(tag_engine("TapBranch").midstate(), TapBranchTag::engine().midstate());
        assert_eq!(tag_engine("TapTweak").midstate(), TapTweakTag::engine().midstate());
        assert_eq!(tag_engine("TapSighash").midstate(), TapSighashTag::engine().midstate());

        // check that hash creation is the same as building into the same engine
        fn empty_hash(tag_name: &str) -> [u8; 32] {
            let mut e = tag_engine(tag_name);
            e.input(&[]);
            TapNodeHash::from_engine(e).to_byte_array()
        }
        assert_eq!(empty_hash("TapLeaf"), TapLeafHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapBranch"), TapNodeHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapTweak"), TapTweakHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapSighash"), TapSighash::hash(&[]).to_byte_array());
    }

    #[test]
    fn test_vectors_core() {
        //! Test vectors taken from Core

        // uninitialized writers
        //   CHashWriter writer = HasherTapLeaf;
        //   writer.GetSHA256().GetHex()
        assert_eq!(
            TapLeafHash::from_engine(TapLeafTag::engine()).to_string(),
            "5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb"
        );
        assert_eq!(
            TapNodeHash::from_engine(TapBranchTag::engine()).to_string(),
            "53c373ec4d6f3c53c1f5fb2ff506dcefe1a0ed74874f93fa93c8214cbe9ffddf"
        );
        assert_eq!(
            TapTweakHash::from_engine(TapTweakTag::engine()).to_string(),
            "8aa4229474ab0100b2d6f0687f031d1fc9d8eef92a042ad97d279bff456b15e4"
        );
        assert_eq!(
            TapSighash::from_engine(TapSighashTag::engine()).to_string(),
            "dabc11914abcd8072900042a2681e52f8dba99ce82e224f97b5fdb7cd4b9c803"
        );

        // 0-byte
        //   CHashWriter writer = HasherTapLeaf;
        //   writer << std::vector<unsigned char>{};
        //   writer.GetSHA256().GetHex()
        // Note that Core writes the 0 length prefix when an empty vector is written.
        assert_eq!(
            TapLeafHash::hash(&[0]).to_string(),
            "ed1382037800c9dd938dd8854f1a8863bcdeb6705069b4b56a66ec22519d5829"
        );
        assert_eq!(
            TapNodeHash::hash(&[0]).to_string(),
            "92534b1960c7e6245af7d5fda2588db04aa6d646abc2b588dab2b69e5645eb1d"
        );
        assert_eq!(
            TapTweakHash::hash(&[0]).to_string(),
            "cd8737b5e6047fc3f16f03e8b9959e3440e1bdf6dd02f7bb899c352ad490ea1e"
        );
        assert_eq!(
            TapSighash::hash(&[0]).to_string(),
            "c2fd0de003889a09c4afcf676656a0d8a1fb706313ff7d509afb00c323c010cd"
        );
    }

    fn _verify_tap_commitments(
        secp: &Secp256k1<VerifyOnly>,
        out_spk_hex: &str,
        script_hex: &str,
        control_block_hex: &str,
    ) {
        let out_pk = XOnlyPublicKey::from_str(&out_spk_hex[4..]).unwrap();
        let out_pk = TweakedPublicKey::dangerous_assume_tweaked(out_pk);
        let script = ScriptBuf::from_hex(script_hex).unwrap();
        let control_block =
            ControlBlock::decode(&Vec::<u8>::from_hex(control_block_hex).unwrap()).unwrap();
        assert_eq!(control_block_hex, control_block.serialize().to_lower_hex_string());
        assert!(control_block.verify_taproot_commitment(secp, out_pk.to_inner(), &script));
    }

    #[test]
    fn control_block_verify() {
        let secp = Secp256k1::verification_only();
        // test vectors obtained from printing values in feature_taproot.py from Bitcoin Core
        _verify_tap_commitments(&secp, "51205dc8e62b15e0ebdf44751676be35ba32eed2e84608b290d4061bbff136cd7ba9", "6a", "c1a9d6f66cd4b25004f526bfa873e56942f98e8e492bd79ed6532b966104817c2bda584e7d32612381cf88edc1c02e28a296e807c16ad22f591ee113946e48a71e0641e660d1e5392fb79d64838c2b84faf04b7f5f283c9d8bf83e39e177b64372a0cd22eeab7e093873e851e247714eff762d8a30be699ba4456cfe6491b282e193a071350ae099005a5950d74f73ba13077a57bc478007fb0e4d1099ce9cf3d4");
        _verify_tap_commitments(&secp, "5120e208c869c40d8827101c5ad3238018de0f3f5183d77a0c53d18ac28ddcbcd8ad", "f4", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40090ab1f4890d51115998242ebce636efb9ede1b516d9eb8952dc1068e0335306199aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4da14e029b1e154a85bfd9139e7aa2720b6070a4ceba8264ca61d5d3ac27aceb9ef4b54cd43c2d1fd5e11b5c2e93cf29b91ea3dc5b832201f02f7473a28c63246");
        _verify_tap_commitments(
            &secp,
            "5120567666e7df90e0450bb608e17c01ed3fbcfa5355a5f8273e34e583bfaa70ce09",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ac",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(&secp, "5120580a19e47269414a55eb86d5d0c6c9b371455d9fd2154412a57dec840df99fe1", "6a", "bca0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40042ba1bd1c63c03ccff60d4c4d53a653f87909eb3358e7fa45c9d805231fb08c933e1f4e0f9d17f591df1419df7d5b7eb5f744f404c5ef9ecdb1b89b18cafa3a816d8b5dba3205f9a9c05f866d91f40d2793a7586d502cb42f46c7a11f66ad4aa");
        _verify_tap_commitments(&secp, "5120228b94a4806254a38d6efa8a134c28ebc89546209559dfe40b2b0493bafacc5b", "6a50", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4009c9aed3dfd11ab0e78bf87ef3bf296269dc4b0f7712140386d6980992bab4b45");
        _verify_tap_commitments(
            &secp,
            "5120567666e7df90e0450bb608e17c01ed3fbcfa5355a5f8273e34e583bfaa70ce09",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ac",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(
            &secp,
            "5120b0a79103c31fe51eea61d2873bad8a25a310da319d7e7a85f825fa7a00ea3f85",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ad51",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(&secp, "5120f2f62e854a0012aeba78cd4ba4a0832447a5262d4c6eb4f1c95c7914b536fc6c", "6a86", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4009ad3d30479f0689dbdf59a6b840d60ad485b2effbed1825a75ce19a44e460e09056f60ea686d79cfa4fb79f197b2e905ac857a983be4a5a41a4873e865aa950780c0237de279dc063e67deec46ef8e1bc351bf12c4d67a6d568001faf097e797e6ee620f53cfe0f8acaddf2063c39c3577853bb46d61ffcba5a024c3e1216837");
        _verify_tap_commitments(&secp, "51202a4772070b49bae68b44315032cdbf9c40c7c2f896781b32b931b73dbfb26d7e", "6af8", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4006f183944a14618fc7fe9ceade0f58e43a19d3c3b179ea6c43c29616413b6971c99aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4c3462adec78cd04f3cc156bdadec50def99feae0dc6a23664e8a2b0d42d6ca9eb968dfdf46c23af642b2688351904e0a0630e71ffac5bcaba33b9b2c8a7495ec");
        _verify_tap_commitments(&secp, "5120a32b0b8cfafe0f0f8d5870030ba4d19a8725ad345cb3c8420f86ac4e0dff6207", "4c", "e8a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400615da7ac8d078e5fc7f4690fc2127ba40f0f97cc070ade5b3a7919783d91ef3f13734aab908ae998e57848a01268fe8217d70bc3ee8ea8ceae158ae964a4b5f3af20b50d7019bf47fde210eee5c52f1cfe71cfca78f2d3e7c1fd828c80351525");
        _verify_tap_commitments(
            &secp,
            "5120b0a79103c31fe51eea61d2873bad8a25a310da319d7e7a85f825fa7a00ea3f85",
            "203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ad51",
            "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400",
        );
        _verify_tap_commitments(&secp, "51208678459f1fa0f80e9b89b8ffdcaf46a022bdf60aa45f1fed9a96145edf4ec400", "6a50", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4001eff29e1a89e650076b8d3c56302881d09c9df215774ed99993aaed14acd6615");
        _verify_tap_commitments(&secp, "5120017316303aed02bcdec424c851c9eacbe192b013139bd9634c4e19b3475b06e1", "61", "02a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f40050462265ca552b23cbb4fe021b474313c8cb87d4a18b3f7bdbeb2b418279ba31fc6509d829cd42336f563363cb3538d78758e0876c71e13012eb2b656eb0edb051a2420a840d5c8c6c762abc7410af2c311f606b20ca2ace56a8139f84b1379a");
        _verify_tap_commitments(&secp, "5120896d4d5d2236e86c6e9320e86d1a7822e652907cbd508360e8c71aefc127c77d", "61", "14a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4001ab0e9d9a4858a0e69605fe9c5a42d739fbe26fa79650e7074f462b02645f7ea1c91802b298cd91e6b5af57c6a013d93397cd2ecbd5569382cc27becf44ff4fff8960b20f846160c159c58350f6b6072cf1b3daa5185b7a42524fb72cbc252576ae46732b8e31ac24bfa7d72f4c3713e8696f99d8ac6c07e4c820a03f249f144");
        _verify_tap_commitments(&secp, "512093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51", "04ffffffff203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ba04feffffff87ab", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400c9a5cd1f6c8a81f5648e39f9810591df1c9a8f1fe97c92e03ecd7c0c016c951983e05473c6e8238cb4c780ea2ce62552b2a3eee068ceffc00517cd7b97e10dad");
        _verify_tap_commitments(&secp, "5120b28d75a7179de6feb66b8bb0bfa2b2c739d1a41cf7366a1b393804a844db8a28", "61", "c4a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400eebc95ded88fb8050094e8dfa958c3be0894eaff0fafae678206b26918d8d7ac47039d40fe34d04b4155df7f1be7f2a49253c7e87812ea9e569e683ac27459e652d6503aa32d64734d00adfee8798b2eed28858abf3bd038e8fa58eb7df4a2d9");
        _verify_tap_commitments(&secp, "512043e4aa733fc6f43c78a31c2b3c192623acf5cc8c01199ebcc4de88067baca83e", "bd4c", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4003f7be6f8848b5bddf332c4d7bd83077f73701e2479f70e02b5730e841234d082b8b41ebea96ffd937715d9faeaa6895e6ef3b22919c554b75df12b3371d328023e443d1df50634ecc1cd169803a1e546f0d44304d8fc5056c408e597fed469b8437d6660eaad3cf72e35ba6e5ff7ddd5e293c1e7e813c871df4f46508e9946ec");
        _verify_tap_commitments(&secp, "5120ee9aecb28f5f35ce1f8b5ec80275ac0f81bca4a21b29b4632fb4bcbef8823e6a", "2021a5981b13be29c9d4ea179ea44a8b773ea8c02d68f6f6eefd98de20d4bd055fac", "c13359c284c196b6e80f0cf1d93b6a397cf7ee722f0427b705bd954b88ada8838bd2622fd0e104fc50aa763b43c6a792d7d117029983abd687223b4344a9402c618bba7f5fc3fa8a57491f6842acde88c1e675ca35caea3b1a69ee2c2d9b10f615");
        _verify_tap_commitments(&secp, "5120885274df2252b44764dcef53c21f21154e8488b7e79fafbc96b9ebb22ad0200d", "6a50", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4000793597254158918e3369507f2d6fdbef17d18b1028bbb0719450ded0f42c58f");
        _verify_tap_commitments(&secp, "512066f6f6f91d47674d198a28388e1eb05ec24e6ddbba10f16396b1a80c08675121", "6a50", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400fe92aff70a2e8e2a4f34a913b99612468a41e0f8ecaff9a729a173d11013c27e");
        _verify_tap_commitments(&secp, "5120868ed9307bd4637491ff03e3aa2c216a08fe213cac8b6cedbb9ab31dbfa6512c", "61", "a2a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400da584e7d32612381cf88edc1c02e28a296e807c16ad22f591ee113946e48a71e46c7eccffefd2d573ec014130e508f0c9963ccebd7830409f7b1b1301725e9fa759d4ef857ec8e0bb42d6d31609d3c7e77de3bfa28c38f93393a6ddbabe819ec560ed4f061fbe742a5fd2a648d5209469420434c8753da3fa7067cc2bb4c172a");
        _verify_tap_commitments(&secp, "5120c1a00a9baa82888fd7d30291135a7eaa9e9966a5f16db2b10460572f8b108d8d", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "5ba0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4007960d7b37dd1361aee34510e77acb4d27ddca17648a17e28475032538c1eb500f5a747f2c0893f79fe153ae918ac3d696de9322aa679aae62051ff5ed83aa502b338bd907346abd4cd9cf06117cb35d55a5a8dd950843522f8de7b5c7fba1804c38b0778d3d76b383f6db6fdf9d6e770da8fffbfa5152c0b8b38129885bcdee6");
        _verify_tap_commitments(&secp, "5120bb9abeff7286b76dfc61800c548fe2621ff47506e47201a85c543b4a9a96fead", "75203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf47342796ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6eadac", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4003eb5cdc419e0a6a800f34583ce750f387be34879c26f4230991bd61da743ad9d34d288e79397b709ac22ad8cc57645d593af3e15b97a876362117177ab2519c000000000000000000000000000000000000000000000000000000000000000007160c3a48c8b17bc3aeaf01db9e0a96ac47a5a9fa329e046856e7765e89c8a93ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07feb9aa7cd72c78e66a85414cd19289f8b0ab1415013dc2a007666aa9248ec1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001fccc8bea662a9442a94f7ba0643c1d7ee7cc689f3b3506b7c8c99fd3f3b3d7772972dcdf2550cf95b65098aea67f72fef10abdcf1cef9815af8f4c4644b060e0000000000000000000000000000000000000000000000000000000000000000");
        _verify_tap_commitments(&secp, "5120afddc189ea51094b4cbf463806792e9c8b35dfdc5e01228c78376380d0046b00", "4d09024747703eb9f759ce5ecd839109fecc40974ab16f5173ea390daaa5a78f7abe898165c90990062af998c5dc7989818393158a2c62b7ece727e7f5400d2efd33db8732599f6d1dce6b5b68d2d47317f2de6c9df118f61227f98453225036618aaf058140f2415d134fa69ba041c724ad81387f8c568d12ddc49eb32a71532096181b3f85fd465b8e9a176bb19f45c070baad47a2cc4505414b88c31cb5b0a192b2d2d56c404a37070b04d42c875c4ac351224f5b254f9ad0b820f43cad292d6565f796bf083173e14723f1e543c85a61689ddd5cb6666b240c15c38ce3320bf0c3be9e0322e5ef72366c294d3a2d7e8b8e7db875e7ae814537554f10b91c72b8b413e026bd5d5e917de4b54fa8f43f38771a7f242aa32dcb7ca1b0588dbf54af7ab9455047fbb894cdfdd242166db784276430eb47d4df092a6b8cb160eb982fe7d14a44283bdb4a9861ca65c06fd8b2546cfbfe38bc77f527de1b9bfd2c95a3e283b7b1d1d2b2fa291256a90a7003aefcef47ceabf113865a494af43e96a38b0b00919855eb7722ea2363e0ddfc9c51c08631d01e2a2d56e786b4ff6f1e5d415facc9c2619c285d9ad43001878294157cb025f639fb954271fd1d6173f6bc16535672f6abdd72b0284b4ff3eaf5b7247719d7c39365622610efae6562bef6e08a0b370fba75bb04dbdb90a482d8417e057f8bd021ea6ac32d0d48b08be9f77833b11e5e739960c9837d7583", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400ff698adfda0327f188e2ee35f7aecc0f90c9138a350d450648d968c2b5dd7ef94ddd3ec418dc0d03ee4956feb708d838ed2b20e5a193465a6a1467fd3054e1ea141ea4c4c503a6271e19a090e2a69a24282e3be04c4f98720f7a0eb274d9693d13a8e3c139aa625fa2aefd09854570527f9ac545bda1b689719f5cb715612c07");
        _verify_tap_commitments(&secp, "5120afddc189ea51094b4cbf463806792e9c8b35dfdc5e01228c78376380d0046b00", "83", "c0a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f4007388cda01113397d4cd00bcfbd08fd68c3cfe3a42cbfe3a7651c1d5e6dacf1ad99aaf103cceb41d9bc37ec231aca89b984b5fd3c65977ce764d51033ac65adb4b59764bec92507e4a4c3f01a06f05980163ca10f1c549bfe01f85fa4f109a1295e607f5ed9f1008048474de336f11f67a1fbf2012f58944dede0ab19a3ca81f5");
        _verify_tap_commitments(&secp, "512093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51", "04ffffffff203455139bf238a3067bd72ed77e0ab8db590330f55ed58dba7366b53bf4734279ba04feffffff87ab", "c1a0eb12e60a52614986c623cbb6621dcdba3a47e3be6b37e032b7a11c7b98f400c9a5cd1f6c8a81f5648e39f9810591df1c9a8f1fe97c92e03ecd7c0c016c951983e05473c6e8238cb4c780ea2ce62552b2a3eee068ceffc00517cd7b97e10dad");
    }

    #[test]
    fn build_huffman_tree() {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str(
            "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        )
        .unwrap();

        let script_weights = vec![
            (10, ScriptBuf::from_hex("51").unwrap()), // semantics of script don't matter for this test
            (20, ScriptBuf::from_hex("52").unwrap()),
            (20, ScriptBuf::from_hex("53").unwrap()),
            (30, ScriptBuf::from_hex("54").unwrap()),
            (19, ScriptBuf::from_hex("55").unwrap()),
        ];
        let tree_info =
            TaprootSpendInfo::with_huffman_tree(&secp, internal_key, script_weights.clone())
                .unwrap();

        /* The resulting tree should put the scripts into a tree similar
         * to the following:
         *
         *   1      __/\__
         *         /      \
         *        /\     / \
         *   2   54 52  53 /\
         *   3            55 51
         */

        for (script, length) in [("51", 3), ("52", 2), ("53", 2), ("54", 2), ("55", 3)].iter() {
            assert_eq!(
                *length,
                tree_info
                    .script_map()
                    .get(&(ScriptBuf::from_hex(script).unwrap(), LeafVersion::TapScript))
                    .expect("Present Key")
                    .iter()
                    .next()
                    .expect("Present Path")
                    .len()
            );
        }

        // Obtain the output key
        let output_key = tree_info.output_key();

        // Try to create and verify a control block from each path
        for (_weights, script) in script_weights {
            let ver_script = (script, LeafVersion::TapScript);
            let ctrl_block = tree_info.control_block(&ver_script).unwrap();
            assert!(ctrl_block.verify_taproot_commitment(
                &secp,
                output_key.to_inner(),
                &ver_script.0
            ))
        }
    }

    #[test]
    fn taptree_builder() {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str(
            "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        )
        .unwrap();

        let builder = TaprootBuilder::new();
        // Create a tree as shown below
        // For example, imagine this tree:
        // A, B , C are at depth 2 and D,E are at 3
        //                                       ....
        //                                     /      \
        //                                    /\      /\
        //                                   /  \    /  \
        //                                  A    B  C  / \
        //                                            D   E
        let a = ScriptBuf::from_hex("51").unwrap();
        let b = ScriptBuf::from_hex("52").unwrap();
        let c = ScriptBuf::from_hex("53").unwrap();
        let d = ScriptBuf::from_hex("54").unwrap();
        let e = ScriptBuf::from_hex("55").unwrap();
        let builder = builder.add_leaf(2, a.clone()).unwrap();
        let builder = builder.add_leaf(2, b.clone()).unwrap();
        let builder = builder.add_leaf(2, c.clone()).unwrap();
        let builder = builder.add_leaf(3, d.clone()).unwrap();

        // Trying to finalize an incomplete tree returns the Err(builder)
        let builder = builder.finalize(&secp, internal_key).unwrap_err();
        let builder = builder.add_leaf(3, e.clone()).unwrap();

        #[cfg(feature = "serde")]
        {
            let tree = TapTree::try_from(builder.clone()).unwrap();
            // test roundtrip serialization with serde_test
            #[rustfmt::skip]
            assert_tokens(&tree.readable(), &[
                Token::Seq { len: Some(10) },
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("51"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("52"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("55"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("54"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("53"), Token::U8(192), Token::TupleVariantEnd,
                Token::SeqEnd,
            ],);

            let node_info = TapTree::try_from(builder.clone()).unwrap().into_node_info();
            // test roundtrip serialization with serde_test
            #[rustfmt::skip]
            assert_tokens(&node_info.readable(), &[
                Token::Seq { len: Some(10) },
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("51"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("52"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("55"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(3), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("54"), Token::U8(192), Token::TupleVariantEnd,
                Token::U64(2), Token::TupleVariant { name: "TapLeaf", variant: "Script", len: 2}, Token::Str("53"), Token::U8(192), Token::TupleVariantEnd,
                Token::SeqEnd,
            ],);
        }

        let tree_info = builder.finalize(&secp, internal_key).unwrap();
        let output_key = tree_info.output_key();

        for script in [a, b, c, d, e] {
            let ver_script = (script, LeafVersion::TapScript);
            let ctrl_block = tree_info.control_block(&ver_script).unwrap();
            assert!(ctrl_block.verify_taproot_commitment(
                &secp,
                output_key.to_inner(),
                &ver_script.0
            ))
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_leaf_version_serde() {
        let leaf_version = LeafVersion::TapScript;
        // use serde_test to test serialization and deserialization
        assert_tokens(&leaf_version, &[Token::U8(192)]);

        let json = serde_json::to_string(&leaf_version).unwrap();
        let leaf_version2 = serde_json::from_str(&json).unwrap();
        assert_eq!(leaf_version, leaf_version2);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_merkle_branch_serde() {
        let dummy_hash = hex!("03ba2a4dcd914fed29a1c630c7e811271b081a0e2f2f52cf1c197583dfd46c1b");
        let hash1 = TapNodeHash::from_slice(&dummy_hash).unwrap();
        let dummy_hash = hex!("8d79dedc2fa0b55167b5d28c61dbad9ce1191a433f3a1a6c8ee291631b2c94c9");
        let hash2 = TapNodeHash::from_slice(&dummy_hash).unwrap();
        let merkle_branch = TaprootMerkleBranch::from([hash1, hash2]);
        // use serde_test to test serialization and deserialization
        serde_test::assert_tokens(
            &merkle_branch.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::Str("03ba2a4dcd914fed29a1c630c7e811271b081a0e2f2f52cf1c197583dfd46c1b"),
                Token::Str("8d79dedc2fa0b55167b5d28c61dbad9ce1191a433f3a1a6c8ee291631b2c94c9"),
                Token::SeqEnd,
            ],
        );
    }

    #[test]
    fn bip_341_tests() {
        fn process_script_trees(
            v: &serde_json::Value,
            mut builder: TaprootBuilder,
            leaves: &mut Vec<(ScriptBuf, LeafVersion)>,
            depth: u8,
        ) -> TaprootBuilder {
            if v.is_null() {
                // nothing to push
            } else if v.is_array() {
                for leaf in v.as_array().unwrap() {
                    builder = process_script_trees(leaf, builder, leaves, depth + 1);
                }
            } else {
                let script = ScriptBuf::from_hex(v["script"].as_str().unwrap()).unwrap();
                let ver =
                    LeafVersion::from_consensus(v["leafVersion"].as_u64().unwrap() as u8).unwrap();
                leaves.push((script.clone(), ver));
                builder = builder.add_leaf_with_ver(depth, script, ver).unwrap();
            }
            builder
        }

        let data = bip_341_read_json();
        // Check the version of data
        assert!(data["version"] == 1);
        let secp = &secp256k1::Secp256k1::verification_only();

        for arr in data["scriptPubKey"].as_array().unwrap() {
            let internal_key =
                XOnlyPublicKey::from_str(arr["given"]["internalPubkey"].as_str().unwrap()).unwrap();
            // process the tree
            let script_tree = &arr["given"]["scriptTree"];
            let mut merkle_root = None;
            if script_tree.is_null() {
                assert!(arr["intermediary"]["merkleRoot"].is_null());
            } else {
                merkle_root = Some(
                    TapNodeHash::from_str(arr["intermediary"]["merkleRoot"].as_str().unwrap())
                        .unwrap(),
                );
                let leaf_hashes = arr["intermediary"]["leafHashes"].as_array().unwrap();
                let ctrl_blks = arr["expected"]["scriptPathControlBlocks"].as_array().unwrap();
                let mut builder = TaprootBuilder::new();
                let mut leaves = vec![];
                builder = process_script_trees(script_tree, builder, &mut leaves, 0);
                let spend_info = builder.finalize(secp, internal_key).unwrap();
                for (i, script_ver) in leaves.iter().enumerate() {
                    let expected_leaf_hash = leaf_hashes[i].as_str().unwrap();
                    let expected_ctrl_blk = ControlBlock::decode(
                        &Vec::<u8>::from_hex(ctrl_blks[i].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();

                    let leaf_hash = TapLeafHash::from_script(&script_ver.0, script_ver.1);
                    let ctrl_blk = spend_info.control_block(script_ver).unwrap();
                    assert_eq!(leaf_hash.to_string(), expected_leaf_hash);
                    assert_eq!(ctrl_blk, expected_ctrl_blk);
                }
            }
            let expected_output_key =
                XOnlyPublicKey::from_str(arr["intermediary"]["tweakedPubkey"].as_str().unwrap())
                    .unwrap();
            let expected_tweak =
                TapTweakHash::from_str(arr["intermediary"]["tweak"].as_str().unwrap()).unwrap();
            let expected_spk =
                ScriptBuf::from_hex(arr["expected"]["scriptPubKey"].as_str().unwrap()).unwrap();
            let expected_addr =
                Address::from_str(arr["expected"]["bip350Address"].as_str().unwrap())
                    .unwrap()
                    .assume_checked();

            let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
            let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
            let addr = Address::p2tr(secp, internal_key, merkle_root, KnownHrp::Mainnet);
            let spk = addr.script_pubkey();

            assert_eq!(expected_output_key, output_key.to_inner());
            assert_eq!(expected_tweak, tweak);
            assert_eq!(expected_addr, addr);
            assert_eq!(expected_spk, spk);
        }
    }

    fn bip_341_read_json() -> serde_json::Value {
        let json_str = include_str!("../../tests/data/bip341_tests.json");
        serde_json::from_str(json_str).expect("JSON was not well-formatted")
    }
}
