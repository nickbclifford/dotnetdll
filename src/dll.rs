use super::{
    binary::{
        cli::{Header, Metadata, RVASize},
        heap::Heap,
        metadata, method,
    },
    context::Context,
};
use object::{
    endian::{LittleEndian, U32Bytes},
    pe::{ImageDataDirectory, ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64},
    read::{
        pe::{ImageNtHeaders, SectionTable},
        Error as ObjectError,
    },
};
use scroll::{Error as ScrollError, Pread};

#[derive(Debug)]
pub struct DLL<'a> {
    buffer: &'a [u8],
    pub cli: Header,
    sections: SectionTable<'a>,
}

#[derive(Debug)]
pub enum DLLError {
    PE(ObjectError),
    CLI(ScrollError),
    Other(&'static str),
}
impl std::fmt::Display for DLLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PE(o) => write!(f, "PE parsing: {}", o),
            CLI(s) => write!(f, "CLI parsing: {}", s),
            Other(s) => write!(f, "Other parsing: {}", s),
        }
    }
}
impl std::error::Error for DLLError {}

use DLLError::*;

type Result<T> = std::result::Result<T, DLLError>;

impl<'a> DLL<'a> {
    pub fn parse(bytes: &[u8]) -> Result<DLL> {
        let dos = ImageDosHeader::parse(bytes).map_err(PE)?;
        let dirs: &[ImageDataDirectory];
        let sections: SectionTable;

        // PE vs PE32+ format detection
        let original_offset = dos.nt_headers_offset() as u64;
        let mut offset = original_offset;
        match ImageNtHeaders32::parse(bytes, &mut offset) {
            Ok((nt, dirs32)) => {
                sections = nt.sections(bytes, offset).map_err(PE)?;
                dirs = dirs32;
            }
            Err(_) => {
                offset = original_offset;
                match ImageNtHeaders64::parse(bytes, &mut offset) {
                    Ok((nt, dirs64)) => {
                        sections = nt.sections(bytes, offset).map_err(PE)?;
                        dirs = dirs64;
                    }
                    Err(e) => return Err(PE(e)),
                }
            }
        }
        let cli_b = dirs[14].data(bytes, &sections).map_err(PE)?;
        Ok(DLL {
            buffer: bytes,
            cli: cli_b.pread_with(0, scroll::LE).map_err(CLI)?,
            sections,
        })
    }

    pub fn at_rva(&self, rva: &RVASize) -> Result<&[u8]> {
        let dir = ImageDataDirectory {
            virtual_address: U32Bytes::new(LittleEndian, rva.rva),
            size: U32Bytes::new(LittleEndian, rva.size),
        };
        dir.data(self.buffer, &self.sections).map_err(PE)
    }

    fn raw_rva(&self, rva: u32) -> Result<&'a [u8]> {
        self.sections
            .pe_data_at(self.buffer, rva)
            .ok_or(Other("bad stream offset"))
    }

    fn get_stream(&self, name: &'static str) -> Result<&'a [u8]> {
        let meta = self.get_cli_metadata()?;
        let header = meta
            .stream_headers
            .iter()
            .find(|h| h.name == name)
            .ok_or(Other("unable to find stream"))?;
        let data = self.raw_rva(self.cli.metadata.rva + header.offset)?;
        Ok(&data[..header.size as usize])
    }

    pub fn get_heap<T: Heap<'a>>(&self, name: &'static str) -> Result<T> {
        Ok(T::new(self.get_stream(name)?))
    }

    pub fn get_cli_metadata(&self) -> Result<Metadata> {
        self.at_rva(&self.cli.metadata)?.pread(0).map_err(CLI)
    }

    pub fn get_logical_metadata(&self) -> Result<metadata::header::Header> {
        self.get_stream("#~")?.pread(0).map_err(CLI)
    }

    pub fn get_method(&self, def: &metadata::table::MethodDef) -> Result<method::Method> {
        self.raw_rva(def.rva)?.pread(0).map_err(CLI)
    }

    pub fn get_context(&self) -> Result<Context<'a>> {
        Ok(Context {
            strings: self.get_heap("#Strings")?,
            blobs: self.get_heap("#Blob")?,
            guids: self.get_heap("#GUID")?,
            userstrings: self.get_heap("#US")?,
            tables: self.get_logical_metadata()?.tables,
        })
    }
}
