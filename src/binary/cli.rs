use super::stream;
use scroll::{
    ctx::{StrCtx, TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};

#[derive(Debug, Pread, Pwrite)]
pub struct RVASize {
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Pread, Pwrite)]
pub struct Header {
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata: RVASize,
    pub flags: u32,
    pub entry_point_token: u32,
    pub resources: RVASize,
    pub strong_name_signature: RVASize,
    pub code_manager_table: RVASize,
    pub vtable_fixups: RVASize,
    pub export_address_table_jumps: RVASize,
    pub managed_native_header: RVASize,
}

#[derive(Debug)]
pub struct Metadata<'a> {
    pub signature: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub reserved: u32,
    pub version: &'a str,
    pub flags: u16,
    pub stream_headers: Vec<stream::Header<'a>>,
}

impl<'a> TryFromCtx<'a> for Metadata<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let sig = from.gread_with(offset, scroll::LE)?;
        let maj = from.gread_with(offset, scroll::LE)?;
        let min = from.gread_with(offset, scroll::LE)?;
        let res = from.gread_with(offset, scroll::LE)?;
        let len: u32 = from.gread_with(offset, scroll::LE)?;

        let version: &str = from.gread_with(offset, StrCtx::Length(len as usize))?;

        let flags = from.gread_with(offset, scroll::LE)?;
        let n_streams: u16 = from.gread_with(offset, scroll::LE)?;

        let headers = (0..n_streams)
            .map(|_| from.gread(offset))
            .collect::<Result<_, _>>()?;

        Ok((
            Metadata {
                signature: sig,
                major_version: maj,
                minor_version: min,
                reserved: res,
                version: version.trim_matches('\0'),
                flags,
                stream_headers: headers,
            },
            *offset,
        ))
    }
}
impl TryIntoCtx for Metadata<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(self.signature, offset, scroll::LE)?;
        into.gwrite_with(self.major_version, offset, scroll::LE)?;
        into.gwrite_with(self.minor_version, offset, scroll::LE)?;
        into.gwrite_with(self.reserved, offset, scroll::LE)?;

        let mut len = self.version.len() + 1;
        let rem = len % 4;
        if rem != 0 {
            len += 4 - rem;
        }
        into.gwrite_with(len as u32, offset, scroll::LE)?;

        into.gwrite(self.version, offset)?;
        into.gwrite_with(0u8, offset, scroll::LE)?;

        // pad out to 4 bytes
        *offset += rem;

        into.gwrite_with(self.flags, offset, scroll::LE)?;

        into.gwrite_with(self.stream_headers.len() as u16, offset, scroll::LE)?;
        for h in self.stream_headers {
            into.gwrite(h, offset)?;
        }

        Ok(*offset)
    }
}
