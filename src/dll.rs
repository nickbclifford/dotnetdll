use super::{
    binary::{
        cli::{Header, Metadata, RVASize},
        heap::*,
        metadata, method,
    },
    resolved,
};
use crate::utils::check_bitmask;
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

// allows for clean usage with ? operator
impl From<ObjectError> for DLLError {
    fn from(e: ObjectError) -> Self {
        PE(e)
    }
}
impl From<ScrollError> for DLLError {
    fn from(e: ScrollError) -> Self {
        CLI(e)
    }
}

use DLLError::*;

type Result<T> = std::result::Result<T, DLLError>;

impl<'a> DLL<'a> {
    pub fn parse(bytes: &[u8]) -> Result<DLL> {
        let dos = ImageDosHeader::parse(bytes)?;
        let dirs: &[ImageDataDirectory];
        let sections: SectionTable;

        // PE vs PE32+ format detection
        let original_offset = dos.nt_headers_offset() as u64;
        let mut offset = original_offset;
        match ImageNtHeaders32::parse(bytes, &mut offset) {
            Ok((nt, dirs32)) => {
                sections = nt.sections(bytes, offset)?;
                dirs = dirs32;
            }
            Err(_) => {
                offset = original_offset;

                let (nt, dirs64) = ImageNtHeaders64::parse(bytes, &mut offset)?;

                sections = nt.sections(bytes, offset)?;
                dirs = dirs64;
            }
        }
        let cli_b = dirs
            .get(14)
            .ok_or(Other("missing CLI metadata data directory in PE image"))?
            .data(bytes, &sections)?;
        Ok(DLL {
            buffer: bytes,
            cli: cli_b.pread_with(0, scroll::LE)?,
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

    // TODO: return type?
    pub fn resolve(&self) -> Result<()> {
        let strings: Strings = self.get_heap("#Strings")?;
        let blobs: Blob = self.get_heap("#Blob")?;
        let guids: GUID = self.get_heap("#GUID")?;
        let userstrings: UserString = self.get_heap("#US")?;
        let tables = self.get_logical_metadata()?.tables;

        use resolved::*;

        macro_rules! heap_idx {
            ($heap:ident, $idx:expr) => {
                $heap.at_index($idx)?
            };
        }

        macro_rules! optional_idx {
            ($heap:ident, $idx:expr) => {
                if $idx.is_null() {
                    None
                } else {
                    Some(heap_idx!($heap, $idx))
                }
            };
        }

        macro_rules! build_version {
            ($src:ident) => {
                Version {
                    major: $src.major_version,
                    minor: $src.minor_version,
                    build: $src.build_number,
                    revision: $src.revision_number,
                }
            };
        }

        let mut assembly = None;
        if let Some(a) = tables.assembly.first() {
            use assembly::*;

            assembly = Some(Assembly {
                attributes: vec![],
                hash_algorithm: match a.hash_alg_id {
                    0x0000 => HashAlgorithm::None,
                    0x8003 => HashAlgorithm::ReservedMD5,
                    0x8004 => HashAlgorithm::SHA1,
                    other => {
                        return Err(CLI(scroll::Error::Custom(format!(
                            "unrecognized assembly hash algorithm {:#06x}",
                            other
                        ))))
                    }
                },
                version: build_version!(a),
                flags: Flags::new(a.flags),
                public_key: optional_idx!(blobs, a.public_key),
                name: heap_idx!(strings, a.name),
                culture: optional_idx!(strings, a.culture),
                security: None,
            });
        }

        let mut assembly_refs = Vec::with_capacity(tables.assembly_ref.len());
        for a in tables.assembly_ref.iter() {
            use assembly::*;

            assembly_refs.push(ExternalAssemblyReference {
                attributes: vec![],
                version: build_version!(a),
                flags: Flags::new(a.flags),
                public_key_or_token: optional_idx!(blobs, a.public_key_or_token),
                name: heap_idx!(strings, a.name),
                culture: optional_idx!(strings, a.culture),
                hash_value: None,
            });
        }

        let mut types = Vec::with_capacity(tables.type_def.len());
        for (idx, t) in tables.type_def.iter().enumerate() {
            use types::*;

            let layout_flags = t.flags & 0x18;

            let name = heap_idx!(strings, t.type_name);

            let mut new_type = TypeDefinition {
                attributes: vec![],
                flags: TypeFlags::new(
                    t.flags,
                    if layout_flags == 0x00 {
                        Layout::Automatic
                    } else {
                        let layout = tables
                            .class_layout
                            .iter()
                            .find(|c| c.parent.0 - 1 == idx)
                            .ok_or(scroll::Error::Custom(format!(
                                "could not find layout for type {}",
                                name
                            )))?;

                        match layout_flags {
                            0x08 => Layout::Sequential {
                                packing_size: layout.packing_size as usize,
                                class_size: layout.class_size as usize,
                            },
                            0x10 => Layout::Explicit {
                                class_size: layout.class_size as usize,
                            },
                            _ => unreachable!(),
                        }
                    },
                ),
                name,
                namespace: optional_idx!(strings, t.type_namespace),
                fields: vec![],
                properties: vec![],
                methods: vec![],
                events: vec![],
                nested_types: vec![],
                overrides: vec![],
                extends: None,
                implements: vec![],
                generic_parameters: vec![],
                security: None,
            };

            // TODO: everything that's owned

            types.push(new_type);
        }

        let mut files = Vec::with_capacity(tables.file.len());
        for f in tables.file.iter() {
            use module::*;

            files.push(File {
                attributes: vec![],
                has_metadata: !check_bitmask(f.flags, 0x0001),
                name: heap_idx!(strings, f.name),
                hash_value: heap_idx!(blobs, f.hash_value),
            });
        }

        let module_row = tables.module.first().ok_or(scroll::Error::Custom(
            "missing required module metadata table".to_string(),
        ))?;
        let module = module::Module {
            attributes: vec![],
            name: heap_idx!(strings, module_row.name),
            mvid: heap_idx!(guids, module_row.mvid),
        };

        let mut module_refs = Vec::with_capacity(tables.module_ref.len());
        for r in tables.module_ref.iter() {
            module_refs.push(module::ExternalModuleReference {
                attributes: vec![],
                name: heap_idx!(strings, r.name),
            });
        }

        Ok(())
    }
}
