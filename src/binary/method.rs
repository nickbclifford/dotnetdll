use super::il;
use scroll::{
    Pread, Pwrite,
    ctx::{TryFromCtx, TryIntoCtx},
};
use scroll_buffer::DynamicBuffer;

/// The CIL method body header.
///
/// Method bodies are encoded using one of two physical header formats:
///
/// - [`Header::Tiny`], a 1-byte header for small methods (body size up to 63 bytes)
///   that do not declare locals and do not carry extra sections.
/// - [`Header::Fat`], a 12-byte (3 DWORD) header that supports full method metadata,
///   including locals and trailing data sections.
///
/// ECMA-335, II.25.4.2 and ECMA-335, II.25.4.3.
///
/// See also: [`crate::resolved::body::Header`].
#[derive(Debug)]
pub enum Header {
    /// A tiny method header.
    ///
    /// This format implies `maxstack = 8`, has no local variable signature token,
    /// and cannot be followed by additional method data sections.
    ///
    /// ECMA-335, II.25.4.2.
    Tiny {
        /// Size of the method body in bytes.
        size: usize,
    },
    /// A fat method header.
    ///
    /// This format stores explicit stack, locals, and size information and may
    /// indicate that extra sections follow the method body.
    ///
    /// ECMA-335, II.25.4.3.
    Fat {
        /// Whether one or more additional data sections follow the method body.
        more_sects: bool,
        /// Whether local variables must be zero-initialized before executing the body.
        init_locals: bool,
        /// Declared evaluation stack depth required by this method.
        max_stack: u16,
        /// Size of the method body in bytes.
        size: usize,
        /// Metadata token for the local variable signature (`StandAloneSig`) or zero.
        local_var_sig_tok: u32,
    },
}

impl TryFromCtx<'_> for Header {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let b1: u8 = from.gread_with(offset, scroll::LE)?;
        Ok((
            if b1 & 0b11 == 2 {
                Header::Tiny {
                    size: (b1 >> 2) as usize,
                }
            } else {
                // second byte isn't relevant right now
                // see ECMA-335, II.25.4.3 (page 285)
                *offset += 1;

                Header::Fat {
                    more_sects: check_bitmask!(b1, 0x8),
                    init_locals: check_bitmask!(b1, 0x10),
                    max_stack: from.gread_with(offset, scroll::LE)?,
                    size: from.gread_with::<u32>(offset, scroll::LE)? as usize,
                    local_var_sig_tok: from.gread_with(offset, scroll::LE)?,
                }
            },
            *offset,
        ))
    }
}
impl TryIntoCtx<(), DynamicBuffer> for Header {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        use Header::*;
        match self {
            Tiny { size } => {
                into.gwrite_with(((size as u8) << 2) | 0x2, offset, scroll::LE)?;
            }
            Fat {
                more_sects,
                init_locals,
                max_stack,
                size,
                local_var_sig_tok,
            } => {
                let mut flags: u16 = 0x3;
                if more_sects {
                    flags |= 0x8;
                }
                if init_locals {
                    flags |= 0x10;
                }

                let header_size: u16 = 3;

                bitfield::bitfield! {
                    pub struct FlagsSize(u16);
                    flags, set_flags: 11, 0;
                    size, set_size: 15, 12;
                }

                let mut fields = FlagsSize(0);
                fields.set_flags(flags);
                fields.set_size(header_size);

                into.gwrite_with(fields.0, offset, scroll::LE)?;

                into.gwrite_with(max_stack, offset, scroll::LE)?;
                into.gwrite_with(size as u32, offset, scroll::LE)?;
                into.gwrite_with(local_var_sig_tok, offset, scroll::LE)?;
            }
        }

        Ok(*offset)
    }
}

/// A single exception handling clause inside a method data section.
///
/// Offsets and lengths are expressed as byte ranges relative to the start of the
/// method body (the IL stream). `class_token_or_filter` is interpreted by
/// `flags`: for typed handlers it is a `TypeDef`/`TypeRef`/`TypeSpec` token,
/// and for filter handlers it is the byte offset of the filter decision block.
///
/// ECMA-335, II.25.4.6.
///
/// See also: [`crate::resolved::body::Exception`].
#[derive(Debug, Pread)]
pub struct Exception {
    /// Clause kind flags (`COR_ILEXCEPTION_CLAUSE_*`).
    pub flags: u32,
    /// Byte offset where the protected `try` region begins.
    pub try_offset: u32,
    /// Length in bytes of the protected `try` region.
    pub try_length: u32,
    /// Byte offset where the handler region begins.
    pub handler_offset: u32,
    /// Length in bytes of the handler region.
    pub handler_length: u32,
    /// Type token for typed handlers, or filter start offset for filter handlers.
    pub class_token_or_filter: u32,
}
impl TryIntoCtx<(), DynamicBuffer> for Exception {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        if let (Ok(tlen), Ok(hlen), Ok(toff), Ok(hoff)) = (
            u8::try_from(self.try_length),
            u8::try_from(self.handler_length),
            u16::try_from(self.try_offset),
            u16::try_from(self.handler_offset),
        ) {
            into.gwrite_with(self.flags as u8, offset, scroll::LE)?;
            into.gwrite_with(toff, offset, scroll::LE)?;
            into.gwrite_with(tlen, offset, scroll::LE)?;
            into.gwrite_with(hoff, offset, scroll::LE)?;
            into.gwrite_with(hlen, offset, scroll::LE)?;
        } else {
            into.gwrite_with(self.flags, offset, scroll::LE)?;
            into.gwrite_with(self.try_offset, offset, scroll::LE)?;
            into.gwrite_with(self.try_length, offset, scroll::LE)?;
            into.gwrite_with(self.handler_offset, offset, scroll::LE)?;
            into.gwrite_with(self.handler_length, offset, scroll::LE)?;
        }

        into.gwrite_with(self.class_token_or_filter, offset, scroll::LE)?;

        Ok(*offset)
    }
}

/// Decoded kind of an extra method data section.
///
/// The CLI currently standardizes exception handling sections; unknown kinds are
/// preserved as raw spans so the parser can skip them while keeping stream
/// alignment.
///
/// ECMA-335, II.25.4.5.
#[derive(Debug)]
pub enum SectionKind {
    /// Exception handling clauses for the method body.
    ///
    /// ECMA-335, II.25.4.6.
    Exceptions(Vec<Exception>),
    /// A section kind this crate does not currently decode.
    ///
    /// `is_fat` records whether the section used the fat section header format and
    /// `length` is the payload byte length reported in that header.
    Unrecognized { is_fat: bool, length: usize },
}

/// One extra data section that follows a method body.
///
/// These sections appear after the IL stream (aligned to a 4-byte boundary) and
/// are chained via a continuation bit in each section header.
///
/// ECMA-335, II.25.4.5.
///
/// See also: [`crate::resolved::body::DataSection`].
#[derive(Debug)]
pub struct DataSection {
    /// Parsed section payload.
    pub section: SectionKind,
    /// Whether another section follows this one.
    pub more_sections: bool,
}

impl TryFromCtx<'_> for DataSection {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let kind: u8 = from.gread_with(offset, scroll::LE)?;
        let is_exception = check_bitmask!(kind, 1);
        let is_fat = check_bitmask!(kind, 0x40);
        let more_sections = check_bitmask!(kind, 0x80);

        let length = if is_fat {
            let mut bytes = [0_u8; 3];
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
            SectionKind::Unrecognized { is_fat, length }
        };

        Ok((DataSection { section, more_sections }, *offset))
    }
}
impl TryIntoCtx<(), DynamicBuffer> for DataSection {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        use SectionKind::*;

        let mut kind: u8 = if self.more_sections { 0x80 } else { 0x0 };

        let (is_fat, length) = match &self.section {
            Exceptions(es) => {
                kind |= 0x1;

                let should_be_fat = !es.iter().all(|e| {
                    e.try_length < 256 && e.handler_length < 256 && e.try_offset < 65536 && e.handler_offset < 65536
                });

                (should_be_fat, (if should_be_fat { 24 } else { 12 } * es.len()) + 4)
            }
            Unrecognized { is_fat, length } => (*is_fat, *length),
        };

        if is_fat {
            kind |= 0x40;
        }

        into.gwrite_with(kind, offset, scroll::LE)?;

        if is_fat {
            let bytes = (length as u32).to_le_bytes();
            for b in &bytes[..3] {
                into.gwrite_with(b, offset, scroll::LE)?;
            }
        } else {
            into.gwrite_with(length as u8, offset, scroll::LE)?;
        }

        match self.section {
            Exceptions(e) => {
                // small exception table requires 2 bytes padding
                if !is_fat {
                    into.gwrite_with(0_u16, offset, scroll::LE)?;
                }

                for clause in e {
                    if is_fat {
                        into.gwrite(clause, offset)?;
                    } else {
                        into.gwrite_with(clause.flags as u16, offset, scroll::LE)?;
                        into.gwrite_with(clause.try_offset as u16, offset, scroll::LE)?;
                        into.gwrite_with(clause.try_length as u8, offset, scroll::LE)?;
                        into.gwrite_with(clause.handler_offset as u16, offset, scroll::LE)?;
                        into.gwrite_with(clause.handler_length as u8, offset, scroll::LE)?;
                        into.gwrite_with(clause.class_token_or_filter, offset, scroll::LE)?;
                    }
                }
            }
            Unrecognized {
                length: section_length, ..
            } => {
                // just skip any unknown sections
                *offset += section_length;
            }
        }

        Ok(*offset)
    }
}

/// A complete binary CIL method body.
///
/// A method body consists of a [`Header`], an IL instruction stream, and
/// optionally one or more trailing [`DataSection`] values (for example,
/// exception handling tables).
///
/// ECMA-335, II.25.4.2 through ECMA-335, II.25.4.6.
///
/// See also: [`crate::resolved::body::Method`].
#[derive(Debug)]
pub struct Method {
    /// The method header (tiny or fat).
    pub header: Header,
    /// Decoded CIL instructions for the method body.
    pub body: Vec<il::Instruction>,
    /// Trailing method data sections.
    pub data_sections: Vec<DataSection>,
}

impl TryFromCtx<'_> for Method {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let header = from.gread(offset)?;

        let body_size = match header {
            Header::Tiny { size } | Header::Fat { size, .. } => size,
        };

        let body_bytes: &[u8] = from.gread_with(offset, body_size)?;
        // body_size is an upper bound on instruction count (each IL instruction is ≥1 byte)
        let mut body = Vec::with_capacity(body_size);
        let mut body_offset = 0;
        while body_offset < body_size {
            body.push(body_bytes.gread(&mut body_offset)?);
        }

        let mut data_sections = vec![];

        if let Header::Fat {
            more_sects: mut has_next,
            ..
        } = header
        {
            // align to next 4-byte boundary
            *offset = crate::utils::round_up_to_4(*offset).0;

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
impl TryIntoCtx<(), DynamicBuffer> for Method {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite(self.header, offset)?;

        for i in self.body {
            into.gwrite(i, offset)?;
        }

        // align to next 4-byte boundary
        *offset = crate::utils::round_up_to_4(*offset).0;

        for d in self.data_sections {
            into.gwrite(d, offset)?;
        }

        Ok(*offset)
    }
}
