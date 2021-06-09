use bitvec::{order::Lsb0, view::BitView};
use scroll::{ctx::TryFromCtx, Pread};

#[derive(Debug)]
pub struct Unsigned(pub u32);

impl<'a> TryFromCtx<'a, ()> for Unsigned {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1 = from.gread_with::<u8>(offset, scroll::LE)? as u32;

        Ok((
            Unsigned(if b1 >> 7 == 0 {
                b1
            } else {
                let b2 = from.gread_with::<u8>(offset, scroll::LE)? as u32;
                if b1 >> 6 == 0b10 {
                    ((b1 & 0b111111) << 8) | b2
                } else {
                    let b3 = from.gread_with::<u8>(offset, scroll::LE)? as u32;
                    let b4 = from.gread_with::<u8>(offset, scroll::LE)? as u32;
                    ((b1 & 0b11111) << 24) | (b2 << 16) | (b3 << 8) | b4
                }
            }),
            *offset,
        ))
    }
}

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

impl<'a> TryFromCtx<'a, ()> for Signed {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1 = from.gread_with::<u8>(offset, scroll::LE)? as u32;

        Ok((
            Signed(if b1 >> 7 == 0 {
                let value = b1 & 0b1111111;
                from_twos_complement(7, (value >> 1) | (value << 6))
            } else {
                let b2 = from.gread_with::<u8>(offset, scroll::LE)? as u32;
                if b1 >> 6 == 0b10 {
                    let value = ((b1 & 0b111111) << 8) | b2;
                    from_twos_complement(14, (value >> 1) | (value << 13))
                } else {
                    let b3 = from.gread_with::<u8>(offset, scroll::LE)? as u32;
                    let b4 = from.gread_with::<u8>(offset, scroll::LE)? as u32;
                    let value = ((b1 & 0b11111) << 24) | (b2 << 16) | (b3 << 8) | b4;
                    from_twos_complement(29, (value >> 1) | (value << 28))
                }
            }),
            *offset,
        ))
    }
}
