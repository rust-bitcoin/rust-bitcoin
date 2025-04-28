use core::fmt;

pub(crate) struct Decimal<'a> {
    pub(crate) negative: bool,
    pub(crate) num_before_decimal_point: u64,
    /// `num_before_decimal_point` is multiplied by `10 ^ exp`.
    pub(crate) exp: usize,
    /// The number after decimal points normalized to not end with 0 if it's not 0
    pub(crate) num_after_decimal_point: u64,
    /// Number of decimals
    pub(crate) nb_decimals: u8,
    pub(crate) unit: Option<&'a str>,
}

impl fmt::Display for Decimal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Decimal {
            negative,
            mut num_before_decimal_point,
            exp,
            mut num_after_decimal_point,
            nb_decimals,
            unit,
        } = *self;

        // round the number if needed
        // rather than fiddling with chars, we just modify the number and let the simpler algorithm take over.
        if let Some(format_precision) = f.precision() {
            if usize::from(nb_decimals) > format_precision {
                // precision is u8 so in this branch f.precision() < 255 which fits in u32
                let rounding_divisor =
                    10u64.pow(u32::from(nb_decimals) - format_precision as u32); // Cast ok, commented above.
                let remainder = num_after_decimal_point % rounding_divisor;
                num_after_decimal_point -= remainder;
                if remainder / (rounding_divisor / 10) >= 5 {
                    num_after_decimal_point += rounding_divisor;
                    // This is basically addition with carry - if the number after decimal point
                    // gets too large we have to add carry to the number before decimal point
                    let one_past_largest_nadp = 10u64.pow(u32::from(nb_decimals));
                    if num_after_decimal_point >= one_past_largest_nadp {
                        num_before_decimal_point += 1;
                        num_after_decimal_point -= one_past_largest_nadp;
                    }
                }
            }
        }

        // normalize by stripping trailing zeros
        let norm_nb_decimals = if num_after_decimal_point == 0 {
            0
        } else {
            let mut norm_nb_decimals = usize::from(nb_decimals);
            while num_after_decimal_point % 10 == 0 {
                norm_nb_decimals -= 1;
                num_after_decimal_point /= 10;
            }

            norm_nb_decimals
        };

        let trailing_decimal_zeros = f.precision().unwrap_or(0).saturating_sub(norm_nb_decimals);
        let total_decimals = norm_nb_decimals + trailing_decimal_zeros;
        // Compute expected width of the number
        let mut num_width = if total_decimals > 0 {
            // 1 for decimal point
            1 + total_decimals
        } else {
            0
        };
        num_width += dec_width(num_before_decimal_point) + exp;
        if f.sign_plus() || negative {
            num_width += 1;
        }

        if let Some(unit) = unit {
            // + 1 for space
            num_width += unit.len() + 1;
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

        if total_decimals > 0 {
            write!(f, ".")?;
        }
        if norm_nb_decimals > 0 {
            write!(f, "{:0width$}", num_after_decimal_point, width = norm_nb_decimals)?;
        }
        repeat_char(f, '0', trailing_decimal_zeros)?;

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
