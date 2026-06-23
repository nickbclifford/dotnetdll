use super::{
    binary::{
        cli::{Header, Metadata, RVASize},
        heap::{BlobReader, GUIDReader, Reader, StringsReader, UserStringReader},
        metadata, method,
    },
    resolution::{Resolution, read},
};
use DLLError::*;
use object::{
    endian::{LittleEndian, U32Bytes},
    pe::{self, ImageDataDirectory},
    read::{
        Error as ObjectReadError, FileKind,
        pe::{PeFile32, PeFile64, SectionTable},
    },
};
use scroll::{Error as ScrollError, Pread};
use thiserror::Error;

/// Represents a binary DLL file. Used for binary introspection, metadata resolution, and resolution compilation.
#[derive(Debug)]
pub struct DLL<'a> {
    buffer: &'a [u8],
    /// The CLI header of the DLL, read from the 15th PE data directory. See ECMA-335, II.25.3.3 (page 283) for more information.
    pub cli: Header,
    sections: SectionTable<'a>,
}

/// Physical binary-format errors (ECMA-335 Partition II §II.23, §II.24, §II.25).
///
/// These represent malformed bytes that cannot be decoded into metadata structures.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Truncated or otherwise incomplete data at a specific byte offset.
    Truncated { offset: usize },
    /// Unknown element-type tag byte in a signature blob.
    BadElementType { tag: u8 },
    /// Unknown or unsupported table-kind bit in the metadata `Valid` bitmask.
    UnknownTableBit { bit: u8 },
    /// Invalid table tag byte in a raw metadata token.
    BadTokenTag { tag: u8 },
    /// Unsupported or malformed method/signature kind byte.
    BadSignatureKind { tag: u8, context: &'static str },
    /// Invalid native-intrinsic marshal tag.
    BadNativeIntrinsic { tag: u8 },
    /// Structural stream/section error.
    BadStructure(&'static str),
    /// Heap index points outside the heap boundary.
    HeapOutOfRange { heap: &'static str, offset: usize },
    /// Invalid compressed-integer encoding.
    BadCompressedInt { offset: usize },
}

/// ECMA-335 validity-rule violations (§II.22.1).
///
/// These represent cases where metadata bytes decode, but violate required constraints.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidityError {
    /// Exception-clause flags outside the allowed set {0x0000, 0x0001, 0x0002, 0x0004}.
    BadExceptionClauseFlags { flags: u32 },
    /// Generic-parameter variance/special-constraint flags outside the defined range.
    BadVarianceFlags { flags: u16 },
    /// Invalid `CustomAttributeType` coded-index tag.
    BadCustomAttributeType { tag: u8 },
    /// Invalid metadata flags for a given context.
    BadFlags { context: &'static str, flags: u32 },
}

/// Metadata-resolution failures.
///
/// These represent cross-row reference failures and other semantic lookup issues after decoding.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// A row index is out of range for its table.
    IndexOutOfRange {
        kind: &'static str,
        index: usize,
        max: usize,
    },
    /// A coded index or token targets a disallowed table for this context.
    BadTokenTarget { context: &'static str },
    /// A lazy-accessor lookup failed.
    LazyLookupFailed(&'static str),
    /// Arithmetic on metadata indices overflowed/underflowed.
    IndexArithmetic { context: &'static str },
    /// A required metadata row slot was missing when referenced.
    MissingRow { table: &'static str, index: usize },
    /// Inconsistent generic parameter owner/arity relationship.
    GenericArityMismatch { expected: usize, got: usize },
}

// TODO: now that Resolution is the typical entry point, move this into maybe its own module
/// The general error type for all dotnetdll operations.
///
/// ## Downstream migration guide (`CLI`/`Other` removal)
///
/// `DLLError` previously exposed `CLI(scroll::Error)` and `Other(&'static str)`.
/// Those legacy variants were removed in favor of structured error categories.
/// For downstream consumers (including `dotnet-rs`) that previously pattern-matched
/// on `CLI`/`Other`, use the mapping below:
///
/// - `DLLError::CLI(scroll::Error::Custom(_))`
///   → `DLLError::Parse(_)`, `DLLError::Validity(_)`, or `DLLError::Resolve(_)`
///   depending on whether the failure is physical-format parsing, ECMA validity,
///   or cross-row metadata resolution.
/// - `DLLError::CLI(non-Custom scroll error)`
///   → `DLLError::Decode(_)`.
/// - `DLLError::Other("method has no body (abstract or rva == 0)")`
///   → `DLLError::Resolve(ResolveError::LazyLookupFailed("method has no body (abstract or rva == 0)"))`.
/// - Other `DLLError::Other(...)` structural metadata failures
///   → `DLLError::Parse(ParseError::BadStructure(...))`.
///
/// If your integration only stringifies errors (for example,
/// `format!("{}", err)`), no migration code is required.
#[derive(Debug, Error)]
pub enum DLLError {
    /// Errors from parsing the PE binary format.
    /// This might happen if you try to load an invalid DLL with [`DLL::parse`].
    #[error("PE parsing: {0}")]
    PERead(#[from] ObjectReadError),
    /// Structured binary-format parse failures.
    #[error("Parse error: {0}")]
    Parse(ParseError),
    /// Structured metadata validity-rule violations.
    #[error("Validity error: {0}")]
    Validity(ValidityError),
    /// Structured metadata resolution failures.
    #[error("Resolution error: {0}")]
    Resolve(ResolveError),
    /// Decode errors from low-level scroll reads.
    #[error("Decode error: {0}")]
    Decode(#[from] ScrollError),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { offset } => write!(f, "truncated data at byte offset {offset}"),
            Self::BadElementType { tag } => write!(f, "invalid element type tag 0x{tag:02X}"),
            Self::UnknownTableBit { bit } => write!(f, "unknown metadata table bit {bit}"),
            Self::BadTokenTag { tag } => write!(f, "invalid metadata token tag 0x{tag:02X}"),
            Self::BadSignatureKind { tag, context } => {
                write!(f, "invalid signature kind 0x{tag:02X} ({context})")
            }
            Self::BadNativeIntrinsic { tag } => {
                write!(f, "invalid native intrinsic tag 0x{tag:02X}")
            }
            Self::BadStructure(msg) => write!(f, "invalid metadata structure: {msg}"),
            Self::HeapOutOfRange { heap, offset } => {
                write!(f, "{heap} heap offset {offset} is out of range")
            }
            Self::BadCompressedInt { offset } => {
                write!(f, "invalid compressed integer at byte offset {offset}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl std::fmt::Display for ValidityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadExceptionClauseFlags { flags } => {
                write!(f, "invalid exception clause flags 0x{flags:08X}")
            }
            Self::BadVarianceFlags { flags } => {
                write!(f, "invalid generic variance/constraint flags 0x{flags:04X}")
            }
            Self::BadCustomAttributeType { tag } => {
                write!(f, "invalid custom attribute type tag {tag}")
            }
            Self::BadFlags { context, flags } => {
                write!(f, "invalid metadata flags 0x{flags:X} ({context})")
            }
        }
    }
}

impl std::error::Error for ValidityError {}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndexOutOfRange { kind, index, max } => {
                write!(f, "{kind} index {index} is out of range (max {max})")
            }
            Self::BadTokenTarget { context } => {
                write!(f, "token or coded index points to an invalid table ({context})")
            }
            Self::LazyLookupFailed(msg) => write!(f, "lazy metadata lookup failed: {msg}"),
            Self::IndexArithmetic { context } => {
                write!(f, "metadata index arithmetic failed ({context})")
            }
            Self::MissingRow { table, index } => {
                write!(f, "missing required {table} row at index {index}")
            }
            Self::GenericArityMismatch { expected, got } => {
                write!(f, "generic arity mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

impl From<ParseError> for DLLError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<ValidityError> for DLLError {
    fn from(value: ValidityError) -> Self {
        Self::Validity(value)
    }
}

impl From<ResolveError> for DLLError {
    fn from(value: ResolveError) -> Self {
        Self::Resolve(value)
    }
}

pub type Result<T> = std::result::Result<T, DLLError>;

impl<'a> DLL<'a> {
    /// Parses a binary DLL from a byte slice.
    ///
    /// This method only parses the PE (Portable Executable) file structure and the CLI header.
    /// To resolve the metadata into a high-level representation, use [`DLL::resolve`].
    ///
    /// # Errors
    ///
    /// Returns an error when the input is not a PE32/PE32+ image, the CLI data
    /// directory is missing, or PE/CLI headers cannot be decoded.
    pub fn parse(bytes: &'a [u8]) -> Result<DLL<'a>> {
        let (sections, dir) = match FileKind::parse(bytes)? {
            FileKind::Pe32 => {
                let file = PeFile32::parse(bytes)?;
                (
                    file.section_table(),
                    file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
                )
            }
            FileKind::Pe64 => {
                let file = PeFile64::parse(bytes)?;
                (
                    file.section_table(),
                    file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
                )
            }
            _ => {
                return Err(ParseError::BadStructure("invalid object type, must be PE32 or PE64").into())
            }
        };

        let cli_b = dir
            .ok_or(ParseError::BadStructure(
                "missing CLI metadata data directory in PE image",
            ))?
            .data(bytes, &sections)?;
        Ok(DLL {
            buffer: bytes,
            cli: cli_b.pread_with(0, scroll::LE)?,
            sections,
        })
    }

    /// Returns the byte range described by an RVA/size pair.
    ///
    /// # Errors
    ///
    /// Returns an error when the RVA does not map to readable section data.
    pub fn at_rva(&self, rva: &RVASize) -> Result<&'a [u8]> {
        let dir = ImageDataDirectory {
            virtual_address: U32Bytes::new(LittleEndian, rva.rva),
            size: U32Bytes::new(LittleEndian, rva.size),
        };
        dir.data(self.buffer, &self.sections).map_err(PERead)
    }

    pub(crate) fn raw_rva(&self, rva: u32) -> Result<&'a [u8]> {
        self.sections
            .pe_data_at(self.buffer, rva)
            .ok_or(ParseError::BadStructure("bad stream offset").into())
    }

    fn get_stream(&self, name: &'static str) -> Result<Option<&'a [u8]>> {
        let meta = self.get_cli_metadata()?;
        let Some(header) = meta.stream_headers.iter().find(|h| h.name == name) else {
            return Ok(None);
        };
        let data = self.raw_rva(self.cli.metadata.rva + header.offset)?;
        Ok(Some(&data[..header.size as usize]))
    }

    /// Loads a metadata heap reader for heap type `T`.
    ///
    /// Missing heaps are treated as empty streams.
    ///
    /// # Errors
    ///
    /// Returns an error when CLI metadata stream headers cannot be read.
    pub fn get_heap<T: Reader<'a>>(&self) -> Result<T> {
        // heap names from the traits are known to be good
        // so if we can't find them, assume they are empty
        Ok(T::new(self.get_stream(T::NAME)?.unwrap_or(&[])))
    }

    /// Loads the four standard heaps and logical metadata table stream.
    ///
    /// Returns `#Strings`, `#Blob`, `#GUID`, and `#US` readers plus the parsed
    /// `#~` header.
    ///
    /// # Errors
    ///
    /// Returns an error when stream headers or stream bytes cannot be read, or
    /// when the required `#~` stream is missing/invalid.
    pub fn get_all_streams(
        &self,
    ) -> Result<(
        StringsReader<'a>,
        BlobReader<'a>,
        GUIDReader<'a>,
        UserStringReader<'a>,
        metadata::header::Header,
    )> {
        let meta = self.get_cli_metadata()?;

        let mut strings = None;
        let mut blobs = None;
        let mut guids = None;
        let mut userstrings = None;
        let mut logical = None;

        for header in &meta.stream_headers {
            let data = self.raw_rva(self.cli.metadata.rva + header.offset)?;
            let stream = &data[..header.size as usize];

            if header.name == <StringsReader<'a> as Reader<'a>>::NAME && strings.is_none() {
                strings = Some(stream);
            } else if header.name == <BlobReader<'a> as Reader<'a>>::NAME && blobs.is_none() {
                blobs = Some(stream);
            } else if header.name == <GUIDReader<'a> as Reader<'a>>::NAME && guids.is_none() {
                guids = Some(stream);
            } else if header.name == <UserStringReader<'a> as Reader<'a>>::NAME && userstrings.is_none() {
                userstrings = Some(stream);
            } else if header.name == "#~" && logical.is_none() {
                logical = Some(stream);
            }
        }

        Ok((
            StringsReader::new(strings.unwrap_or(&[])),
            BlobReader::new(blobs.unwrap_or(&[])),
            GUIDReader::new(guids.unwrap_or(&[])),
            UserStringReader::new(userstrings.unwrap_or(&[])),
            logical
                .ok_or(ParseError::BadStructure("unable to find metadata stream"))?
                .pread(0)?,
        ))
    }

    /// Reads the CLI metadata root (`Metadata`) from the CLI header RVA.
    ///
    /// # Errors
    ///
    /// Returns an error when the metadata RVA is invalid or the metadata root
    /// cannot be decoded.
    pub fn get_cli_metadata(&self) -> Result<Metadata<'a>> {
        self.at_rva(&self.cli.metadata)?.pread(0).map_err(Decode)
    }

    /// Reads and parses the logical metadata tables header from the `#~` stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the `#~` stream is absent or its header is invalid.
    pub fn get_logical_metadata(&self) -> Result<metadata::header::Header> {
        self.get_stream("#~")?
            .ok_or(ParseError::BadStructure("unable to find metadata stream"))?
            .pread(0)
    }

    /// Reads and decodes one raw method body from a `MethodDef` row.
    ///
    /// # Errors
    ///
    /// Returns an error when the method RVA is invalid or the body encoding is
    /// malformed.
    #[allow(clippy::nonminimal_bool)]
    pub fn get_method(&self, def: &metadata::table::MethodDef) -> Result<method::Method> {
        let bytes = self.raw_rva(def.rva)?;
        let mut offset = 0;
        // if we don't see a method header at the beginning, we need to align
        if !check_bitmask!(bytes[0], 0x2) {
            offset = 4 - (def.rva as usize % 4);
        }
        bytes.pread(offset).map_err(Decode)
    }

    /// Returns the raw bytes and alignment offset for a method body without parsing.
    /// Used by the lazy-decode path to defer `binary::method::Method` parsing until first access.
    pub(crate) fn method_bytes(&self, def: &metadata::table::MethodDef) -> Result<(&'a [u8], usize)> {
        let bytes = self.raw_rva(def.rva)?;
        let offset = if !check_bitmask!(bytes[0], 0x2) {
            4 - (def.rva as usize % 4)
        } else {
            0
        };
        Ok((bytes, offset))
    }

    /// Resolves the CLI metadata within the DLL into a high-level [`Resolution`] struct.
    ///
    /// # Errors
    ///
    /// Returns an error if metadata streams are missing/malformed or if
    /// cross-table resolution/validity checks fail.
    pub fn resolve(&self, opts: read::Options) -> Result<Resolution<'a>> {
        read::read_impl(self, opts)
    }
}
