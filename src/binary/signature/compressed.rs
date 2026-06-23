use crate::dll::ParseError;
use bitvec::{order::Lsb0, view::BitView};
use scroll::{
    Pread, Pwrite,
    ctx::{TryFromCtx, TryIntoCtx},
};

/// A compressed unsigned integer used in signature and metadata blob encodings.
///
/// This is the ECMA-335 compressed-integer format with a length prefix encoded in
/// the high bits of the first byte:
///
/// - `0xxxxxxx`: 1-byte payload (7-bit value)
/// - `10xxxxxx`: 2-byte payload (14-bit value, big-endian)
/// - `110xxxxx`: 4-byte payload (29-bit value, big-endian)
///
/// Valid values are in the range `0..=0x1FFF_FFFF`.
///
/// This encoding appears throughout signature blobs (for example, counts and
/// coded references) and is not LEB128.
///
/// ECMA-335, II.23.2 (page 261).
#[derive(Debug)]
pub struct Unsigned(
    /// Decoded integer value.
    pub u32,
);

impl TryFromCtx<'_> for Unsigned {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1: u8 = from.gread_with(offset, scroll::LE)?;

        Ok((
            Unsigned(if b1 >> 7 == 0 {
                b1 as u32
            } else {
                if b1 >> 5 == 0b111 {
                    return Err(scroll::Error::Custom(
                        ParseError::BadCompressedInt { offset: 0 }.to_string(),
                    ));
                }

                let b2: u8 = from.gread_with(offset, scroll::LE)?;
                if b1 >> 6 == 0b10 {
                    u16::from_be_bytes([b1 & 0b0011_1111, b2]) as u32
                } else {
                    let b3: u8 = from.gread_with(offset, scroll::LE)?;
                    let b4: u8 = from.gread_with(offset, scroll::LE)?;
                    u32::from_be_bytes([b1 & 0b0001_1111, b2, b3, b4])
                }
            }),
            *offset,
        ))
    }
}
try_into_ctx!(Unsigned, |self, into| {
    let offset = &mut 0;

    if self.0 <= 0x7F {
        into.gwrite_with(self.0 as u8, offset, scroll::BE)?;
    } else if 0x80 <= self.0 && self.0 <= 0x3FFF {
        into.gwrite_with(self.0 as u16 | (1 << 15), offset, scroll::BE)?;
    } else if self.0 > 0x1FFF_FFFF {
        return Err(scroll::Error::Custom(
            ParseError::BadStructure("invalid unsigned compressed integer, range is 0..=0x1FFFFFFF").to_string(),
        ));
    } else {
        into.gwrite_with(self.0 | (0b11 << 30), offset, scroll::BE)?;
    }

    Ok(*offset)
});

/// A compressed signed integer used in signature and metadata blob encodings.
///
/// This uses the ECMA-335 signed compressed-integer scheme:
///
/// 1. Take the value in two's-complement form using 7, 14, or 29 bits.
/// 2. Rotate the bit pattern left by one bit so the sign information is packed
///    into the low bit.
/// 3. Prefix the encoded length using the same lead-bit pattern as [`Unsigned`].
///
/// Valid values are in the range `-(1 << 28)..=((1 << 28) - 1)`.
///
/// This encoding is specific to CLI signature/blob compression and is not
/// LEB128.
///
/// ECMA-335, II.23.2 (page 261).
#[derive(Debug)]
pub struct Signed(
    /// Decoded integer value.
    pub i32,
);

fn from_twos_complement(bits: usize, source: u32) -> i32 {
    let slice = source.view_bits::<Lsb0>();

    (-(1 << (bits - 1)) * slice[bits - 1] as i32)
        + slice[..=bits - 2]
            .iter()
            .by_vals()
            .enumerate()
            .map(|(i, b)| (1 << i) * b as i32)
            .sum::<i32>()
}

impl TryFromCtx<'_> for Signed {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1: u8 = from.gread_with(offset, scroll::LE)?;

        Ok((
            Signed(if b1 >> 7 == 0 {
                let value = (b1 & 0b0111_1111) as u32;
                from_twos_complement(7, (value >> 1) | (value << 6))
            } else {
                if b1 >> 5 == 0b111 {
                    return Err(scroll::Error::Custom(
                        ParseError::BadCompressedInt { offset: 0 }.to_string(),
                    ));
                }

                let b2: u8 = from.gread_with(offset, scroll::LE)?;
                if b1 >> 6 == 0b10 {
                    let value = u16::from_be_bytes([b1 & 0b0011_1111, b2]) as u32;
                    from_twos_complement(14, (value >> 1) | (value << 13))
                } else {
                    let b3: u8 = from.gread_with(offset, scroll::LE)?;
                    let b4: u8 = from.gread_with(offset, scroll::LE)?;
                    let value = u32::from_be_bytes([b1 & 0b0001_1111, b2, b3, b4]);
                    from_twos_complement(29, (value >> 1) | (value << 28))
                }
            }),
            *offset,
        ))
    }
}

fn into_twos_complement(bits: usize, mut source: i32) -> u32 {
    let mut result = 0_u32;
    if source < 0 {
        let neg = 1 << (bits - 1);
        result |= neg;
        source += neg as i32;
    }

    for i in (0..(bits - 1)).rev() {
        let bit = 1 << i;
        if source >= bit {
            result |= bit as u32;
            source -= bit;
        }
    }

    result
}

try_into_ctx!(Signed, |self, into| {
    let offset = &mut 0;

    if -(1 << 6) <= self.0 && self.0 <= ((1 << 6) - 1) {
        let value = into_twos_complement(7, self.0);
        let mut rotated = ((value << 1) | (value >> 6)) as u8;
        rotated.view_bits_mut::<Lsb0>().set(7, false);
        into.gwrite_with(rotated, offset, scroll::BE)?;
    } else if -(1 << 13) <= self.0 && self.0 <= ((1 << 13) - 1) {
        let value = into_twos_complement(14, self.0);
        let mut rotated = ((value << 1) | (value >> 13)) as u16;
        let view = rotated.view_bits_mut::<Lsb0>();
        view.set(15, true);
        view.set(14, false);
        into.gwrite_with(rotated, offset, scroll::BE)?;
    } else if -(1 << 28) <= self.0 && self.0 <= ((1 << 28) - 1) {
        let value = into_twos_complement(29, self.0);
        let mut rotated = (value << 1) | (value >> 28);
        let view = rotated.view_bits_mut::<Lsb0>();
        view.set(31, true);
        view.set(30, true);
        view.set(29, false);
        into.gwrite_with(rotated, offset, scroll::BE)?;
    } else {
        return Err(scroll::Error::Custom(
            ParseError::BadStructure("invalid signed compressed integer, range is (-2^28)..=(2^28 - 1)").to_string(),
        ));
    }
    Ok(*offset)
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression() {
        use scroll::{Pread, Pwrite};

        macro_rules! case {
            ($ty:ident($val:expr) => [$($byte:literal),+]) => {
                let $ty(val) = [$($byte),+].pread(0).unwrap();
                assert_eq!(val, $val);

                // we need to include the variable for repetition, so discard its value
                let mut buf = [$({ let _x = $byte; 0 }),+];
                buf.pwrite($ty($val), 0).unwrap();
                assert_eq!(buf, [$($byte),+]);
            }
        }

        case!(Unsigned(0x03) => [0x03]);
        case!(Unsigned(0x3FFF) => [0xBF, 0xFF]);
        case!(Unsigned(0x4000) => [0xC0, 0x00, 0x40, 0x00]);

        case!(Signed(3) => [0x06]);
        case!(Signed(-3) => [0x7B]);
        case!(Signed(64) => [0x80, 0x80]);
        case!(Signed(-8192) => [0x80, 0x01]);
        case!(Signed(268_435_455) => [0xDF, 0xFF, 0xFF, 0xFE]);
        case!(Signed(-268_435_456) => [0xC0, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn invalid_lead_byte_is_structured_error_without_panic() {
        let unsigned = std::panic::catch_unwind(|| [0xE0, 0, 0, 0].pread::<Unsigned>(0))
            .expect("invalid unsigned compressed integer should not panic");
        assert!(matches!(
            unsigned,
            Err(scroll::Error::Custom(message))
                if message == ParseError::BadCompressedInt { offset: 0 }.to_string()
        ));

        let signed = std::panic::catch_unwind(|| [0xE0, 0, 0, 0].pread::<Signed>(0))
            .expect("invalid signed compressed integer should not panic");
        assert!(matches!(
            signed,
            Err(scroll::Error::Custom(message))
                if message == ParseError::BadCompressedInt { offset: 0 }.to_string()
        ));
    }
}
