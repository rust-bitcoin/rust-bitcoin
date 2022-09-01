use crate::io;

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteCounterThreshold {
    counter: usize,
    threshold: usize,
}

impl WriteCounterThreshold {
    pub(crate) fn new(threshold: usize) -> Self { Self { counter: 0, threshold } }
    pub(crate) fn bytes_written(&self) -> usize { self.counter }

    fn increment_counter(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.counter += buf.len();
        if self.counter > self.threshold {
            Err(io::Error::from(io::ErrorKind::Other))
        } else {
            Ok(buf.len())
        }
    }
}

impl io::Write for WriteCounterThreshold {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.increment_counter(buf) }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.increment_counter(buf)?;
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod test {
    use crate::OutPoint;
    use bitcoin_hashes::Hash;

    use crate::consensus::{serialize, Encodable};
    use crate::constants::genesis_block;
    use crate::{BlockHash, Witness};

    #[test]
    fn test_serialized_len() {
        let tx = genesis_block(crate::Network::Bitcoin).txdata[0].clone();
        let len = serialize(&tx).len();
        assert_eq!(len, 204);
        assert_eq!(len, tx.serialized_len());
        let ser_stop = tx.serialized_len_early_stop(20);
        assert!(ser_stop.is_err());
        assert!(ser_stop.unwrap_err() > 20);

        let out_point = OutPoint::default();
        assert_eq!(serialize(&out_point).len(), out_point.serialized_len());

        assert_eq!(
            Ok(8),
            0u64.serialized_len_early_stop(1),
            "STATIC_SERIALIZED_LEN is None for int type"
        );

        let mut witness = Witness::default();
        witness.push(vec![0u8]);
        assert_eq!(serialize(&witness).len(), witness.serialized_len());
    }

    #[test]
    fn test_serialized_len_vec() {
        let hashes = vec![BlockHash::all_zeros(); 10];
        assert_eq!(serialize(&hashes).len(), 321);
        assert_eq!(hashes.serialized_len(), 321);
        assert_eq!(hashes.serialized_len_early_stop(1), Ok(321));
    }
}

#[cfg(bench)]
mod bench {
    use test::{black_box, Bencher};

    use crate::consensus::{deserialize, serialize, Encodable};
    use crate::constants::genesis_block;
    use crate::hashes::Hash;
    use crate::{Block, OutPoint, Txid};

    #[bench]
    pub fn bench_transaction_serialize_len(bh: &mut Bencher) {
        let tx = genesis_block(crate::Network::Bitcoin).txdata[0].clone();

        bh.iter(|| {
            black_box(serialize(&tx).len());
        });
    }

    #[bench]
    pub fn bench_transaction_serialized_len(bh: &mut Bencher) {
        let tx = genesis_block(crate::Network::Bitcoin).txdata[0].clone();

        bh.iter(|| {
            black_box(tx.serialized_len());
        });
    }

    #[bench]
    pub fn bench_block_serialized_len(bh: &mut Bencher) {
        let raw_block = include_bytes!("../test_data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            black_box(block.serialized_len());
        });
    }

    #[bench]
    pub fn bench_block_serialized_len_early_stop(bh: &mut Bencher) {
        let raw_block = include_bytes!("../test_data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            black_box(block.serialized_len_early_stop(512).unwrap_err());
        });
    }

    #[bench]
    pub fn bench_out_point_serialize_alloc(bh: &mut Bencher) {
        let out_point = OutPoint { txid: Txid::all_zeros(), vout: 0 };

        bh.iter(|| {
            let mut data = vec![];
            out_point.consensus_encode(&mut data).unwrap();
            black_box(data);
        });
    }

    #[bench]
    pub fn bench_out_point_serialize(bh: &mut Bencher) {
        let out_point = OutPoint { txid: Txid::all_zeros(), vout: 0 };

        bh.iter(|| {
            black_box(serialize(&out_point).len());
        });
    }
}
