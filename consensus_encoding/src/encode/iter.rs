// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use super::{Encode, Encoder, EncoderStatus, ExactSizeEncoder};

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
        // Protect against poorly implemented callers.
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

impl<I: Iterator> ExactSizeEncoder for IterEncoder<I>
where
    I: Clone,
    I::Item: Encoder + ExactSizeEncoder,
{
    fn len(&self) -> usize {
        match &self.state {
            EncoderState::Encoding { current, remaining } => {
                let mut total = current.len();
                let remaining = remaining.clone();
                for item in remaining {
                    total += item.len();
                }
                total
            }
            EncoderState::Done => 0,
        }
    }
}

/// An encoder that drives a sequence of encoders yielded by an iterator.
///
/// Items are encoded one after another with no separators.
///
/// This is same as `IterEncoder` except more performant in exchange for fallible construction and
/// the requirement that the items implement `Encode` instead of `Encoder`.
///
/// You should use this one instead whenever possible and just skip encoding if `None` is returned.
pub struct NonEmptyIterEncoder<'e, I: Iterator<Item = &'e T>, T>
where
    T: Encode + 'e,
{
    current: T::Encoder<'e>,
    remaining: I,
}

impl<'e, T: Encode, I: Iterator<Item = &'e T>> NonEmptyIterEncoder<'e, I, T> {
    const ITEMS_ARE_NONEMPTY: bool = T::MIN_ENCODED_LEN > 0;

    /// Constructs an `NonEmptyIterEncoder` from anything that can produce an iterator of encoders.
    pub fn new(iter: impl IntoIterator<IntoIter = I>) -> Option<Self> {
        let mut iter = iter.into_iter();
        let mut current = iter.next()?.encoder();
        if !Self::ITEMS_ARE_NONEMPTY {
            // Advance past any leading empty encoders so that the first call to
            // `current_chunk` satisfies the `Encoder` contract that it must return
            // non-empty bytes or the encoder must be `Done`.
            while current.current_chunk().is_empty() {
                current = iter.next()?.encoder();
            }
        }
        Some(Self { current, remaining: iter })
    }
}

impl<'e, T: 'e + Encode, I: Iterator<Item = &'e T>> fmt::Debug for NonEmptyIterEncoder<'e, I, T>
where
    T::Encoder<'e>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonEmptyIterEncoder").field("current", &self.current).finish()
    }
}

impl<'e, T: 'e + Encode, I: Iterator<Item = &'e T>> Clone for NonEmptyIterEncoder<'e, I, T>
where
    I: Clone,
    T::Encoder<'e>: Clone,
{
    fn clone(&self) -> Self {
        Self { current: self.current.clone(), remaining: self.remaining.clone() }
    }
}

impl<'e, T: 'e + Encode, I: Iterator<Item = &'e T>> Encoder for NonEmptyIterEncoder<'e, I, T> {
    fn current_chunk(&self) -> &[u8] {
        self.current.current_chunk()
    }

    fn advance(&mut self) -> EncoderStatus {
        match self.current.advance() {
            EncoderStatus::HasMore => EncoderStatus::HasMore,
            EncoderStatus::Finished => {
                loop {
                    // A closure is required since MSRV (1.74.0) cannot infer the `Self: 'e` GAT bound
                    // on `Encode::encoder` when passed as a bare function item here.
                    #[allow(clippy::redundant_closure_for_method_calls)]
                    match self.remaining.next().map(|i| i.encoder()) {
                        Some(next) if Self::ITEMS_ARE_NONEMPTY || !next.current_chunk().is_empty() => {
                            self.current = next;
                            break EncoderStatus::HasMore;
                        },
                        // Skip empty encoders
                        Some(_) => (),
                        None => break EncoderStatus::Finished,
                    }
                }
            }
        }
    }
}

impl<'e, T: 'e + Encode, I: Iterator<Item = &'e T>> ExactSizeEncoder for NonEmptyIterEncoder<'e, I, T>
where
    I: Clone,
    T::Encoder<'e>: ExactSizeEncoder,
{
    fn len(&self) -> usize {
        let mut total = self.current.len();
        let remaining = self.remaining.clone();
        if is_exact_size_iterator::<I>() {
            total += self.remaining.size_hint().0 * T::MIN_ENCODED_LEN;
            for item in remaining {
                total += item.encoded_tail_len();
            }
        } else {
            for item in remaining {
                total += item.encoded_len();
            }
        }
        total
    }
}

fn is_exact_size_iterator<T>() -> bool {
    // We're not supposed to rely on this hack but we're only relying on it for optimizations that
    // fall back to slow version should specialization be removed.
    struct Hack<'a, U>(&'a core::cell::Cell<bool>, core::marker::PhantomData<U>);

    impl<'a, U> Clone for Hack<'a, U> {
        fn clone(&self) -> Self {
            self.0.set(false);
            Self(self.0, Default::default())
        }
    }

    impl<'a, U: ExactSizeIterator> Copy for Hack<'a, U> {}

    let is_esi = true.into();
    let _: [Hack<'_, T>; 1] = [Hack(&is_esi, Default::default())].clone();
    is_esi.get()
}
