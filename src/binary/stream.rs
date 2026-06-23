use scroll::{
    Pread, Pwrite,
    ctx::{StrCtx, TryFromCtx, TryIntoCtx},
};

/// One stream-header entry in the metadata root stream-header array.
///
/// Each entry declares a logical stream (for example `#~`, `#Strings`, `#US`,
/// `#Blob`, or `#GUID`) by name, byte offset from the start of the metadata
/// root, and stream size in bytes. Stream names are null-terminated and padded
/// so the next header begins on a 4-byte boundary. See ECMA-335, II.24.2.2.
#[derive(Debug)]
pub struct Header<'a> {
    /// Byte offset of the stream payload from the start of the metadata root.
    pub offset: u32,
    /// Stream payload size in bytes.
    pub size: u32,
    /// Stream name (`#~`, `#Strings`, `#US`, `#Blob`, `#GUID`, etc.).
    pub name: &'a str,
}

impl<'a> TryFromCtx<'a> for Header<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], (): ()) -> Result<(Self, usize), Self::Error> {
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

    fn try_into_ctx(self, into: &mut [u8], (): ()) -> Result<usize, Self::Error> {
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
