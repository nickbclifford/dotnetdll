use scroll::{
    ctx::{StrCtx, TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};

#[derive(Debug)]
pub struct Header<'a> {
    pub offset: u32,
    pub size: u32,
    pub name: &'a str,
}

impl<'a> TryFromCtx<'a> for Header<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let stream_offset = from.gread_with(offset, scroll::LE)?;
        let stream_size = from.gread_with(offset, scroll::LE)?;

        let name = from.gread_with(offset, StrCtx::Delimiter(0))?;

        *offset = crate::utils::round_up_to_4(*offset).0;

        let obj = Header {
            offset: stream_offset,
            size: stream_size,
            name,
        };
        Ok((obj, *offset))
    }
}
impl TryIntoCtx for Header<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(self.offset, offset, scroll::LE)?;
        into.gwrite_with(self.size, offset, scroll::LE)?;

        // name is null-terminated
        into.gwrite(self.name, offset)?;
        into.gwrite_with(0_u8, offset, scroll::LE)?;

        // after initial null-termination, skip ahead to align to 4 bytes with nulls
        *offset = crate::utils::round_up_to_4(*offset).0;

        Ok(*offset)
    }
}
