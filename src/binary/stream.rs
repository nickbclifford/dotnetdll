use scroll::{
    ctx::{StrCtx, TryFromCtx},
    Pread,
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

        let rem = *offset % 4;
        if rem != 0 {
            *offset += 4 - rem;
        }

        let obj = Header {
            offset: stream_offset,
            size: stream_size,
            name,
        };
        Ok((obj, *offset))
    }
}
