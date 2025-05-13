use core::fmt;
use core::num::{NonZeroU8, NonZeroU64, NonZeroUsize};

pub(crate) struct Decimal<'a> {
    pub(crate) negative: bool,
    pub(crate) num_before_decimal_point: u64,
    /// `num_before_decimal_point` is multiplied by `10 ^ exp`.
    pub(crate) exp: usize,
    /// None means the number is round.
    pub(crate) num_after_decimal_point: Option<NumAfterDecimalPoint>,
    pub(crate) unit: Option<&'a str>,
}

#[derive(Copy, Clone)]
pub(crate) struct NumAfterDecimalPoint {
    pub(crate) value: NonZeroU64,
    pub(crate) nb_decimals: NonZeroU8,
    pub(crate) rounding: Rounding,
}

impl fmt::Display for Decimal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Decimal {
            negative,
            mut num_before_decimal_point,
            exp,
            num_after_decimal_point,
            unit,
        } = *self;

        // round the number if needed
        // rather than fiddling with chars, we just modify the number and let the simpler algorithm take over.
        let num_after_decimal_point = if let Some(num_after_decimal_point) = num_after_decimal_point {
            let NumAfterDecimalPoint {
                value: num_after_decimal_point,
                nb_decimals,
                rounding,
            } = num_after_decimal_point;
            let num_after_decimal_point = if let Some(format_precision) = f.precision() {
                if usize::from(u8::from(nb_decimals)) > format_precision {
                    let mut num_after_decimal_point = u64::from(num_after_decimal_point);

                    // precision is u8 so in this branch f.precision() < 255 which fits in u32
                    let rounding_divisor =
                        10u64.pow(u32::from(u8::from(nb_decimals)) - format_precision as u32); // Cast ok, commented above.
                    let remainder = num_after_decimal_point % rounding_divisor;
                    num_after_decimal_point -= remainder;
                    if remainder != 0 && !rounding.is_floor() {
                        if rounding.is_ceil() || remainder / (rounding_divisor / 10) >= 5 {
                            num_after_decimal_point += rounding_divisor;
                            // This is basically addition with carry - if the number after decimal point
                            // gets too large we have to add carry to the number before decimal point
                            let one_past_largest_nadp = 10u64.pow(u32::from(u8::from(nb_decimals)));
                            if num_after_decimal_point >= one_past_largest_nadp {
                                num_before_decimal_point += 1;
                                num_after_decimal_point -= one_past_largest_nadp;
                            }
                        }
                    }

                    NonZeroU64::new(num_after_decimal_point)
                } else {
                    Some(num_after_decimal_point)
                }
            } else {
                Some(num_after_decimal_point)
            };

            // normalize by stripping trailing zeros
            num_after_decimal_point.map(|num_after_decimal_point| {
                let mut norm_nb_decimals = usize::from(u8::from(nb_decimals));
                let mut num_after_decimal_point = u64::from(num_after_decimal_point);
                while num_after_decimal_point % 10 == 0 {
                    norm_nb_decimals -= 1;
                    num_after_decimal_point /= 10;
                }

                let norm_nb_decimals = NonZeroUsize::new(norm_nb_decimals)
                    .expect("the number of digits in num_after_decimal_point exceeds the number of decimals");
                let num_after_decimal_point = NonZeroU64::new(num_after_decimal_point)
                    .expect("after dividing non-zero with its factor the result is still non-zero");

                NumAfterDecimalPointInternal::NonZero {
                    value: num_after_decimal_point,
                    norm_nb_decimals,
                    trailing_zeros: f.precision().unwrap_or(0).saturating_sub(norm_nb_decimals.into()),
                }
            }).or_else(|| {
                f.precision()
                    .and_then(NonZeroUsize::new)
                    .map(NumAfterDecimalPointInternal::JustTrailingZeros)
            })
        } else {
            f.precision()
                .and_then(NonZeroUsize::new)
                .map(NumAfterDecimalPointInternal::JustTrailingZeros)
        };

        // Compute expected width of the number
        let mut num_width = match num_after_decimal_point {
            // 1 for decimal point
            Some(NumAfterDecimalPointInternal::JustTrailingZeros(count)) => usize::from(count).saturating_add(1),
            Some(NumAfterDecimalPointInternal::NonZero { norm_nb_decimals, trailing_zeros, .. }) => {
                usize::from(norm_nb_decimals).saturating_add(trailing_zeros).saturating_add(1)
            },
            None => 0,
        };
        num_width = num_width.saturating_add(dec_width(num_before_decimal_point) + exp);
        if f.sign_plus() || negative {
            num_width = num_width.saturating_add(1);
        }

        if let Some(unit) = unit {
            // + 1 for space; doesn't overflow because len <= isize::MAX
            num_width = num_width.saturating_add(unit.len() + 1);
        }

        let width = f.width().unwrap_or(0);
        let align = f.align().unwrap_or(fmt::Alignment::Right);
        let (left_pad, pad_right) = match (num_width < width, f.sign_aware_zero_pad(), align) {
            (false, _, _) => (0, 0),
            // Alignment is always right (ignored) when zero-padding
            (true, true, _) | (true, false, fmt::Alignment::Right) => (width - num_width, 0),
            (true, false, fmt::Alignment::Left) => (0, width - num_width),
            // If the required padding is odd it needs to be skewed to the left
            (true, false, fmt::Alignment::Center) =>
                ((width - num_width) / 2, (width - num_width + 1) / 2),
        };

        let fill = f.fill();
        if !f.sign_aware_zero_pad() {
            repeat_char(f, fill, left_pad)?;
        }

        if negative {
            write!(f, "-")?;
        } else if f.sign_plus() {
            write!(f, "+")?;
        }

        if f.sign_aware_zero_pad() {
            repeat_char(f, '0', left_pad)?;
        }

        write!(f, "{}", num_before_decimal_point)?;

        repeat_char(f, '0', exp)?;

        if let Some(num_after_decimal_point) = num_after_decimal_point {
            write!(f, ".")?;
            match num_after_decimal_point {
                NumAfterDecimalPointInternal::JustTrailingZeros(trailing_zeros) => {
                    repeat_char(f, '0', trailing_zeros.into())?
                },
                NumAfterDecimalPointInternal::NonZero { value, norm_nb_decimals, trailing_zeros } => {
                    write!(f, "{:0width$}", value, width = norm_nb_decimals.into())?;
                    repeat_char(f, '0', trailing_zeros)?
                }
            }
        }

        if let Some(unit) = unit {
            write!(f, " {}", unit)?;
        }

        repeat_char(f, fill, pad_right)?;
        Ok(())
    }
}

fn dec_width(mut num: u64) -> usize {
    let mut width = 1;
    loop {
        num /= 10;
        if num == 0 {
            break;
        }
        width += 1;
    }
    width
}

fn repeat_char(f: &mut dyn fmt::Write, c: char, count: usize) -> fmt::Result {
    for _ in 0..count {
        f.write_char(c)?;
    }
    Ok(())
}

enum NumAfterDecimalPointInternal {
    JustTrailingZeros(NonZeroUsize),
    NonZero { value: NonZeroU64, norm_nb_decimals: NonZeroUsize, trailing_zeros: usize },
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum Rounding {
    Floor,
    Round,
    Ceil,
}

impl Rounding {
    fn is_floor(self) -> bool {
        matches!(self, Rounding::Floor)
    }

    fn is_ceil(self) -> bool {
        matches!(self, Rounding::Ceil)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // May help identify a problem sooner
    #[cfg(feature = "alloc")]
    #[test]
    fn test_repeat_char() {
        let mut buf = alloc::string::String::new();
        repeat_char(&mut buf, '0', 0).unwrap();
        assert_eq!(buf.len(), 0);
        repeat_char(&mut buf, '0', 42).unwrap();
        assert_eq!(buf.len(), 42);
        assert!(buf.chars().all(|c| c == '0'));
    }
}
