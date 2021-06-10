use scroll::{ctx::TryFromCtx, Pread};

#[derive(Debug)]
pub enum Header {
    Tiny {
        size: usize,
    },
    Fat {
        flags: u16,
        max_stack: u16,
        size: usize,
        local_var_sig_tok: u32,
    },
}

impl TryFromCtx<'_> for Header {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1: u8 = from.gread_with(offset, scroll::LE)?;
        Ok((
            if b1 & 0b11 == 2 {
                Header::Tiny {
                    size: (b1 >> 2) as usize,
                }
            } else {
                let b2: u8 = from.gread_with(offset, scroll::LE)?;

                Header::Fat {
                    flags: ((b2 as u16 & 0b1111) << 8) | b1 as u16,
                    max_stack: from.gread_with(offset, scroll::LE)?,
                    size: from.gread_with::<u32>(offset, scroll::LE)? as usize,
                    local_var_sig_tok: from.gread_with(offset, scroll::LE)?,
                }
            },
            *offset,
        ))
    }
}

#[derive(Debug, Pread)]
pub struct Exception {
    flags: u32,
    try_offset: u32,
    try_length: u32,
    handler_offset: u32,
    handler_length: u32,
    class_token: u32,
    filter_offset: u32,
}

#[derive(Debug)]
pub enum SectionKind {
    Exceptions(Vec<Exception>),
    Unrecognized,
}

#[derive(Debug)]
pub struct DataSection {
    section: SectionKind,
    more_sections: bool,
}

impl TryFromCtx<'_> for DataSection {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let kind: u8 = from.gread_with(offset, scroll::LE)?;
        let is_exception = kind & 1 == 1;
        let is_fat = kind & 0x40 == 0x40;
        let more_sections = kind & 0x80 == 0x80;

        let length = if is_fat {
            let mut bytes = [0u8; 3];
            from.gread_inout_with(offset, &mut bytes, scroll::LE)?;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
        } else {
            from.gread_with::<u8>(offset, scroll::LE)? as u32
        } as usize;

        let section = if is_exception {
            let n = (length - 4) / if is_fat { 16 } else { 28 };

            let mut exceptions = Vec::with_capacity(n);

            for _ in 0..n {
                let e = if is_fat {
                    from.gread_with(offset, scroll::LE)?
                } else {
                    Exception {
                        flags: from.gread_with::<u16>(offset, scroll::LE)? as u32,
                        try_offset: from.gread_with::<u16>(offset, scroll::LE)? as u32,
                        try_length: from.gread_with::<u8>(offset, scroll::LE)? as u32,
                        handler_offset: from.gread_with::<u16>(offset, scroll::LE)? as u32,
                        handler_length: from.gread_with::<u8>(offset, scroll::LE)? as u32,
                        class_token: from.gread_with(offset, scroll::LE)?,
                        filter_offset: from.gread_with(offset, scroll::LE)?,
                    }
                };

                exceptions.push(e);
            }

            SectionKind::Exceptions(exceptions)
        } else {
            *offset += length;
            SectionKind::Unrecognized
        };

        Ok((
            DataSection {
                section,
                more_sections,
            },
            *offset,
        ))
    }
}

#[derive(Debug)]
pub struct Method<'a> {
    pub header: Header,
    pub body: &'a [u8],
    pub data_sections: Vec<DataSection>,
}

impl<'a> TryFromCtx<'a> for Method<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let header = from.gread(offset)?;

        let body_size = match header {
            Header::Tiny { size } => size,
            Header::Fat { size, .. } => size,
        };

        let body = from.gread_with(offset, body_size)?;

        let mut data_sections = vec![];

        if let Header::Fat { flags, .. } = header {
            let mut has_next = flags & 0x8 == 0x8;

            // align to next 4-byte boundary
            let rem = *offset % 4;
            if has_next && rem != 0 {
                *offset += 4 - rem;
            }

            while has_next {
                let sec: DataSection = from.gread(offset)?;
                has_next = sec.more_sections;
                data_sections.push(sec);
            }
        }

        Ok((
            Method {
                header,
                body,
                data_sections,
            },
            *offset,
        ))
    }
}
