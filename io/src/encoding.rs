// SPDX-License-Identifier: CC0-1.0

//! Consensus encoding support for I/O readers and writers.

use encoding::{Encodable, Encoder as _};

use super::{Result, Write};

/// Consensus encodes an object to an I/O writer.
///
/// # Performance
///
/// This method writes data in potentially small chunks based on the encoder's
/// internal chunking strategy. For optimal performance with unbuffered writers
/// (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping your
/// writer with [`std::io::BufWriter`].
///
/// # Errors
///
/// Returns any I/O error encountered while writing to the writer.
pub fn consensus_encode_to_writer<T, W>(object: &T, writer: &mut W) -> Result<()>
where
    T: Encodable + ?Sized,
    W: Write + ?Sized,
{
    let mut encoder = object.encoder();
    loop {
        writer.write_all(encoder.current_chunk())?;
        if !encoder.advance() {
            break;
        }
    }
    Ok(())
}
