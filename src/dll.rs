use super::{
    binary::{
        cli::{Header, Metadata, RVASize},
        heap::Reader,
        metadata, method,
    },
    resolution::{read, Resolution},
};
use object::{
    endian::{LittleEndian, U32Bytes},
    pe::{self, ImageDataDirectory},
    read::{
        pe::{PeFile32, PeFile64, SectionTable},
        Error as ObjectReadError, FileKind,
    },
};
use scroll::{Error as ScrollError, Pread};
use thiserror::Error;
use DLLError::*;

/// Represents a binary DLL file. Used for binary introspection, metadata resolution, and resolution compilation.
#[derive(Debug)]
pub struct DLL<'a> {
    buffer: &'a [u8],
    /// The CLI header of the DLL, read from the 15th PE data directory. See ECMA-335, II.25.3.3 for more information.
    pub cli: Header,
    sections: SectionTable<'a>,
}

// TODO: now that Resolution is the typical entry point, move this into maybe its own module
// TODO: also, eventually we need to expand CLI and the ScrollError into our own meaningful variants
/// The general error type for all dotnetdll operations.
#[derive(Debug, Error)]
pub enum DLLError {
    /// Errors from parsing the PE binary format.
    /// This might happen if you try to load an invalid DLL with [`DLL::parse`].
    #[error("PE parsing: {0}")]
    PERead(#[from] ObjectReadError),
    /// Errors from CLI metadata reading or writing.
    /// Messages are communicated through the [`ScrollError::Custom`] enum variant.
    #[error("CLI metadata: {0}")]
    CLI(#[from] ScrollError),
    /// Errors from DLL parsing that are not PE format errors, such as .NET metadata and method bodies.
    /// This might happen if you try to load an invalid DLL with [`DLL::parse`].
    #[error("Other parsing: {0}")]
    Other(&'static str),
}

pub type Result<T> = std::result::Result<T, DLLError>;

impl<'a> DLL<'a> {
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
            _ => return Err(Other("invalid object type, must be PE32 or PE64")),
        };

        let cli_b = dir
            .ok_or(Other("missing CLI metadata data directory in PE image"))?
            .data(bytes, &sections)?;
        Ok(DLL {
            buffer: bytes,
            cli: cli_b.pread_with(0, scroll::LE)?,
            sections,
        })
    }

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
            .ok_or(Other("bad stream offset"))
    }

    fn get_stream(&self, name: &'static str) -> Result<Option<&'a [u8]>> {
        let meta = self.get_cli_metadata()?;
        let header = match meta.stream_headers.iter().find(|h| h.name == name) {
            Some(h) => h,
            None => return Ok(None),
        };
        let data = self.raw_rva(self.cli.metadata.rva + header.offset)?;
        Ok(Some(&data[..header.size as usize]))
    }

    pub fn get_heap<T: Reader<'a>>(&self) -> Result<T> {
        // heap names from the traits are known to be good
        // so if we can't find them, assume they are empty
        Ok(T::new(self.get_stream(T::NAME)?.unwrap_or(&[])))
    }

    pub fn get_cli_metadata(&self) -> Result<Metadata<'a>> {
        self.at_rva(&self.cli.metadata)?.pread(0).map_err(CLI)
    }

    pub fn get_logical_metadata(&self) -> Result<metadata::header::Header> {
        self.get_stream("#~")?
            .ok_or(Other("unable to find metadata stream"))?
            .pread(0)
            .map_err(CLI)
    }

    #[allow(clippy::nonminimal_bool)]
    pub fn get_method(&self, def: &metadata::table::MethodDef) -> Result<method::Method> {
        let bytes = self.raw_rva(def.rva)?;
        let mut offset = 0;
        // if we don't see a method header at the beginning, we need to align
        if !check_bitmask!(bytes[0], 0x2) {
            offset = 4 - (def.rva as usize % 4);
        }
        bytes.pread(offset).map_err(CLI)
    }

    pub fn resolve(&self, opts: read::Options) -> Result<Resolution<'a>> {
        read::read_impl(self, opts)
    }
}
