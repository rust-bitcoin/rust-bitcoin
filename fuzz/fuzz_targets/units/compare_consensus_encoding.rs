use bitcoin::absolute::LockTime as AbsoluteLockTime;
use bitcoin::consensus::{deserialize, serialize};
use honggfuzz::fuzz;
use units::encoding;
use units::locktime::absolute;

#[derive(Debug)]
enum DecodeAllError<E> {
    Decode(E),
    TrailingBytes,
}

fn decode_all<T>(
    bytes: &[u8],
) -> Result<T, DecodeAllError<<T::Decoder as encoding::Decoder>::Error>>
where
    T: encoding::Decodable,
{
    let mut decoder = T::decoder();
    let mut remaining = bytes;

    while !remaining.is_empty() {
        if !encoding::Decoder::push_bytes(&mut decoder, &mut remaining)
            .map_err(DecodeAllError::Decode)?
        {
            break;
        }
    }

    if !remaining.is_empty() {
        return Err(DecodeAllError::TrailingBytes);
    }

    encoding::Decoder::end(decoder).map_err(DecodeAllError::Decode)
}

fn compare_amount(data: &[u8]) {
    let old: Result<units::Amount, _> = deserialize(data);
    let new: Result<units::Amount, _> = decode_all(data);

    match (old, new) {
        (Ok(old), Ok(new)) => {
            assert_eq!(old, new);
            assert_eq!(serialize(&old), encoding::encode_to_vec(&new));
        }
        (Err(_), Err(_)) => {}
        (Ok(old), Err(err)) =>
            panic!("legacy amount decoder accepted {old:?}, new decoder failed: {err:?}"),
        (Err(err), Ok(new)) =>
            panic!("new amount decoder accepted {new:?}, legacy decoder failed: {err:?}"),
    }
}

fn compare_absolute_height(data: &[u8]) {
    let old: Result<AbsoluteLockTime, _> = deserialize(data);
    let new: Result<absolute::Height, _> = decode_all(data);

    match (old, new) {
        (Ok(AbsoluteLockTime::Blocks(old)), Ok(new)) => {
            assert_eq!(old.to_consensus_u32(), new.to_consensus_u32());
            assert_eq!(serialize(&AbsoluteLockTime::Blocks(old)), encoding::encode_to_vec(&new));
        }
        (Ok(AbsoluteLockTime::Seconds(_)), Err(_)) | (Err(_), Err(_)) => {}
        (Ok(AbsoluteLockTime::Blocks(old)), Err(err)) => {
            panic!("legacy absolute height decoder accepted {old:?}, new decoder failed: {err:?}")
        }
        (Ok(AbsoluteLockTime::Seconds(old)), Ok(new)) => {
            panic!("new absolute height decoder accepted {new:?}, legacy decoder produced time lock {old:?}")
        }
        (Err(err), Ok(new)) =>
            panic!("new absolute height decoder accepted {new:?}, legacy decoder failed: {err:?}"),
    }
}

fn compare_absolute_time(data: &[u8]) {
    let old: Result<AbsoluteLockTime, _> = deserialize(data);
    let new: Result<absolute::Time, _> = decode_all(data);

    match (old, new) {
        (Ok(AbsoluteLockTime::Seconds(old)), Ok(new)) => {
            assert_eq!(old.to_consensus_u32(), new.to_consensus_u32());
            assert_eq!(serialize(&AbsoluteLockTime::Seconds(old)), encoding::encode_to_vec(&new));
        }
        (Ok(AbsoluteLockTime::Blocks(_)), Err(_)) | (Err(_), Err(_)) => {}
        (Ok(AbsoluteLockTime::Seconds(old)), Err(err)) => {
            panic!("legacy absolute time decoder accepted {old:?}, new decoder failed: {err:?}")
        }
        (Ok(AbsoluteLockTime::Blocks(old)), Ok(new)) => {
            panic!("new absolute time decoder accepted {new:?}, legacy decoder produced height lock {old:?}")
        }
        (Err(err), Ok(new)) =>
            panic!("new absolute time decoder accepted {new:?}, legacy decoder failed: {err:?}"),
    }
}

fn do_test(data: &[u8]) {
    compare_amount(data);
    compare_absolute_height(data);
    compare_absolute_time(data);
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        for hex in ["00000000", "ff64cd1d", "0065cd1d", "c82d00000000"] {
            let mut a = Vec::new();
            extend_vec_from_hex(hex, &mut a);
            super::do_test(&a);
        }
    }
}
