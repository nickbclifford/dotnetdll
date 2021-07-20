use super::il;
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
    pub flags: u32,
    pub try_offset: u32,
    pub try_length: u32,
    pub handler_offset: u32,
    pub handler_length: u32,
    pub class_token_or_filter: u32,
}

#[derive(Debug)]
pub enum SectionKind {
    Exceptions(Vec<Exception>),
    Unrecognized,
}

#[derive(Debug)]
pub struct DataSection {
    pub section: SectionKind,
    more_sections: bool,
}

impl TryFromCtx<'_> for DataSection {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let kind: u8 = from.gread_with(offset, scroll::LE)?;
        let is_exception = check_bitmask!(kind, 1);
        let is_fat = check_bitmask!(kind, 0x40);
        let more_sections = check_bitmask!(kind, 0x80);

        let length = if is_fat {
            let mut bytes = [0u8; 3];
            from.gread_inout_with(offset, &mut bytes, scroll::LE)?;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
        } else {
            from.gread_with::<u8>(offset, scroll::LE)? as u32
        } as usize;

        let section = if is_exception {
            if !is_fat {
                // 2 bytes of padding on small exception headers
                *offset += 2;
            }

            let n = (length - 4) / if is_fat { 24 } else { 12 };

            let exceptions = (0..n)
                .map(|_| {
                    if is_fat {
                        from.gread_with(offset, scroll::LE)
                    } else {
                        Ok(Exception {
                            flags: from.gread_with::<u16>(offset, scroll::LE)? as u32,
                            try_offset: from.gread_with::<u16>(offset, scroll::LE)? as u32,
                            try_length: from.gread_with::<u8>(offset, scroll::LE)? as u32,
                            handler_offset: from.gread_with::<u16>(offset, scroll::LE)? as u32,
                            handler_length: from.gread_with::<u8>(offset, scroll::LE)? as u32,
                            class_token_or_filter: from.gread_with(offset, scroll::LE)?,
                        })
                    }
                })
                .collect::<Result<_, _>>()?;

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
pub struct InstructionUnit {
    pub offset: usize,
    pub bytesize: usize,
    pub instruction: il::Instruction,
}

#[derive(Debug)]
pub struct Method {
    pub header: Header,
    pub body: Vec<InstructionUnit>,
    pub data_sections: Vec<DataSection>,
}

impl TryFromCtx<'_> for Method {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let header = from.gread(offset)?;

        let body_size = match header {
            Header::Tiny { size } => size,
            Header::Fat { size, .. } => size,
        };

        let body_bytes: &[u8] = from.gread_with(offset, body_size)?;
        let mut body = vec![];
        let mut body_offset = 0;
        while body_offset < body_size {
            let before_offset = body_offset;
            let instruction = body_bytes.gread(&mut body_offset)?;
            body.push(InstructionUnit {
                offset: before_offset,
                bytesize: body_offset - before_offset,
                instruction,
            });
        }

        let mut data_sections = vec![];

        if let Header::Fat { flags, .. } = header {
            let mut has_next = check_bitmask!(flags, 0x8);

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
