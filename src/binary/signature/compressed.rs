use bitvec::{order::Lsb0, view::BitView};
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};

#[derive(Debug)]
pub struct Unsigned(pub u32);

impl TryFromCtx<'_> for Unsigned {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1: u8 = from.gread_with(offset, scroll::LE)?;

        Ok((
            Unsigned(if b1 >> 7 == 0 {
                b1 as u32
            } else {
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
        throw!(
            "invalid unsigned compressed integer {:#010x}, range is 0..=0x1FFFFFFF",
            self.0
        );
    } else {
        into.gwrite_with(self.0 | (0b11 << 30), offset, scroll::BE)?;
    }

    Ok(*offset)
});

#[derive(Debug)]
pub struct Signed(pub i32);

fn from_twos_complement(bits: usize, source: u32) -> i32 {
    let slice = source.view_bits::<Lsb0>();

    (-(1 << (bits - 1)) * slice[bits - 1] as i32)
        + slice[..=bits - 2]
            .iter()
            .by_val()
            .enumerate()
            .map(|(i, b)| (1 << i) * b as i32)
            .sum::<i32>()
}

impl TryFromCtx<'_> for Signed {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1: u8 = from.gread_with(offset, scroll::LE)?;

        Ok((
            Signed(if b1 >> 7 == 0 {
                let value = (b1 & 0b0111_1111) as u32;
                from_twos_complement(7, (value >> 1) | (value << 6))
            } else {
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
        throw!(
            "invalid signed compressed integer {}, range is (-2^28)..=(2^28 - 1)",
            self.0
        );
    }
    Ok(*offset)
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression() {
        use scroll::{Pwrite, Pread};

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
}
