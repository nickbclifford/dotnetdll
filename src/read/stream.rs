use scroll::{ctx::TryFromCtx, Endian, Pread};

#[derive(Debug)]
pub struct Header {
    pub offset: u32,
    pub size: u32,
    pub name: String,
}

impl<'a> TryFromCtx<'a, Endian> for Header {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let stream_offset = from.gread_with(offset, ctx)?;
        let stream_size = from.gread_with(offset, ctx)?;

        let mut name_buf = vec![];
        loop {
            let char: u8 = from.gread_with(offset, ctx)?;
            name_buf.push(char);
            if char == 0 && *offset % 4 == 0 {
                break;
            }
        }

        let obj = Header {
            offset: stream_offset,
            size: stream_size,
            name: String::from_utf8(name_buf.into_iter().take_while(|&c| c != 0).collect())
                .map_err(|e| scroll::Error::Custom(e.to_string()))?,
        };
        Ok((obj, *offset))
    }
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
    pub stream_headers: Vec<Header>,
}

impl<'a> TryFromCtx<'a, Endian> for Metadata<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let sig = from.gread_with(offset, ctx)?;
        let maj = from.gread_with(offset, ctx)?;
        let min = from.gread_with(offset, ctx)?;
        let res = from.gread_with(offset, ctx)?;
        let len = from.gread_with(offset, ctx)?;

        let version_buf: &[u8] = from.gread_with(offset, len as usize)?;
        let nul_end = version_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(len as usize);

        let flags = from.gread_with(offset, ctx)?;
        let n_streams = from.gread_with(offset, ctx)?;
        let mut headers = vec![];
        for _ in 0..n_streams {
            let header = from.gread_with(offset, ctx)?;
            headers.push(header);
        }

        Ok((
            Metadata {
                signature: sig,
                major_version: maj,
                minor_version: min,
                reserved: res,
                length: len,
                version: std::str::from_utf8(&version_buf[0..nul_end])
                    .map_err(|e| scroll::Error::Custom(e.to_string()))?,
                flags,
                streams: n_streams,
                stream_headers: headers,
            },
            *offset,
        ))
    }
}
