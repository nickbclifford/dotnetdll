use super::stream;
use scroll::{
    ctx::{StrCtx, TryFromCtx},
    Pread,
};
use scroll_derive::Pread;

#[derive(Debug, Pread)]
pub struct RVASize {
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Pread)]
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
    pub length: u32,
    pub version: &'a str,
    pub flags: u16,
    pub streams: u16,
    pub stream_headers: Vec<stream::Header<'a>>,
}

impl<'a> TryFromCtx<'a, ()> for Metadata<'a> {
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
        let mut headers = Vec::with_capacity(n_streams as usize);
        for _ in 0..n_streams {
            let header = from.gread(offset)?;
            headers.push(header);
        }

        Ok((
            Metadata {
                signature: sig,
                major_version: maj,
                minor_version: min,
                reserved: res,
                length: len,
                version: version.trim_matches('\0'),
                flags,
                streams: n_streams,
                stream_headers: headers,
            },
            *offset,
        ))
    }
}
