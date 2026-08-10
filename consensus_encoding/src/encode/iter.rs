// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use super::{Encode, Encoder, EncoderStatus};

/// An iterator bridge which maps consensus encodable items to its encoder.
///
/// This type is a wrapper around [`core::slice::Iter`] that bridges it to the [`IterEncoder`]
/// driver. This allows drivers such as [`SliceEncoder`] to store an [`IterEncoder`] with a
/// nameable type.
///
/// [`SliceEncoder`]: super::encoders::SliceEncoder
pub(super) struct Encoders<'e, T: Encode> {
    iter: core::slice::Iter<'e, T>,
}

impl<'e, T: Encode> Encoders<'e, T> {
    pub(super) fn new(sl: &'e [T]) -> Self { Self { iter: sl.iter() } }
}

impl<'e, T: Encode> Iterator for Encoders<'e, T> {
    type Item = T::Encoder<'e>;
    fn next(&mut self) -> Option<T::Encoder<'e>> {
        // A closure is required since MSRV (1.74.0) cannot infer the `Self: 'e` GAT bound on
        // `Encode::encoder` when passed as a bare function item here.
        #[allow(clippy::redundant_closure_for_method_calls)]
        self.iter.next().map(|item| item.encoder())
    }
}

impl<'e, T: Encode> fmt::Debug for Encoders<'e, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoders").field("remaining", &self.iter.as_slice().len()).finish()
    }
}

impl<'e, T: Encode> Clone for Encoders<'e, T> {
    fn clone(&self) -> Self { Self { iter: self.iter.clone() } }
}

enum EncoderState<I: Iterator>
where
    I::Item: Encoder,
{
    Encoding { current: I::Item, remaining: core::iter::Fuse<I> },
    Done,
}

/// An encoder that drives a sequence of encoders yielded by an iterator.
///
/// Items are encoded one after another with no separators.
pub struct IterEncoder<I: Iterator>
where
    I::Item: Encoder,
{
    state: EncoderState<I>,
}

impl<I: Iterator> IterEncoder<I>
where
    I::Item: Encoder,
{
    /// Constructs an `IterEncoder` from anything that can produce an iterator of encoders.
    pub fn new(iter: impl IntoIterator<IntoIter = I>) -> Self {
        // Protect against poorly implemented iterators.
        let mut iter = iter.into_iter().fuse();
        // Advance past any leading empty encoders so that the first call to
        // `current_chunk` satisfies the `Encoder` contract that it must return
        // non-empty bytes or the encoder must be `Done`.
        let state = loop {
            match iter.next() {
                Some(enc) if !enc.current_chunk().is_empty() =>
                    break EncoderState::Encoding { current: enc, remaining: iter },
                Some(_) => {}
                None => break EncoderState::Done,
            }
        };
        Self { state }
    }
}

impl<I: Iterator> fmt::Debug for IterEncoder<I>
where
    I::Item: Encoder + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            EncoderState::Encoding { current, .. } =>
                f.debug_struct("IterEncoder").field("current", current).finish(),
            EncoderState::Done => f.debug_struct("IterEncoder").finish(),
        }
    }
}

impl<I: Iterator> Clone for IterEncoder<I>
where
    I: Clone,
    I::Item: Encoder + Clone,
{
    fn clone(&self) -> Self {
        let state = match &self.state {
            EncoderState::Encoding { current, remaining } =>
                EncoderState::Encoding { current: current.clone(), remaining: remaining.clone() },
            EncoderState::Done => EncoderState::Done,
        };
        Self { state }
    }
}

impl<I: Iterator> Encoder for IterEncoder<I>
where
    I::Item: Encoder,
{
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            EncoderState::Encoding { current, .. } => current.current_chunk(),
            EncoderState::Done => &[],
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let EncoderState::Encoding { current, remaining } = &mut self.state else {
            return EncoderStatus::Finished;
        };

        loop {
            if current.advance().has_more() {
                return EncoderStatus::HasMore;
            }

            if let Some(next) = remaining.next() {
                *current = next;
                // If the next encoder is empty, skip in order to maintain `Encoder` contract
                // that it must return non-empty bytes or the encoder must be `Done`
                if !current.current_chunk().is_empty() {
                    return EncoderStatus::HasMore;
                }
            } else {
                self.state = EncoderState::Done;
                return EncoderStatus::Finished;
            }
        }
    }
}
