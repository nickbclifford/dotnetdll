use goblin::{
    error,
    pe::{data_directories::DataDirectory, options::ParseOptions, utils, PE},
    Object,
};
use scroll::Pread;

use super::{metadata, stream};

const ALIGNMENT: u32 = 0x200;

#[derive(Debug)]
pub struct DLL<'a> {
    buffer: &'a [u8],
    pub object: PE<'a>,
}

#[derive(Debug, Pread)]
pub struct CLIHeader {
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata: DataDirectory,
    pub flags: u32,
    pub entry_point_token: u32,
    pub resources: DataDirectory,
    pub strong_name_signature: DataDirectory,
    pub code_manager_table: DataDirectory,
    pub vtable_fixups: DataDirectory,
    pub export_address_table_jumps: DataDirectory,
    pub managed_native_header: DataDirectory,
}

impl DLL<'_> {
    pub fn parse(bytes: &[u8]) -> error::Result<DLL> {
        match Object::parse(bytes) {
            Ok(Object::PE(pe)) => Ok(DLL {
                buffer: bytes,
                object: pe,
            }),
            Ok(_) => Err(error::Error::Malformed(
                "Object is not a PE DLL".to_string(),
            )),
            Err(e) => Err(e),
        }
    }

    pub fn get_cli_header(&self) -> error::Result<CLIHeader> {
        let header = self
            .object
            .header
            .optional_header
            .ok_or(error::Error::Malformed(
                "Missing PE optional header".to_string(),
            ))?;
        let dir = header
            .data_directories
            .get_clr_runtime_header()
            .ok_or(error::Error::Malformed("Missing CLI header".to_string()))?;
        utils::get_data(self.buffer, &self.object.sections, dir, ALIGNMENT)
    }

    pub fn get_metadata(&self) -> error::Result<stream::Metadata> {
        utils::get_data(
            self.buffer,
            &self.object.sections,
            self.get_cli_header()?.metadata,
            ALIGNMENT,
        )
    }

    // TODO
    pub fn get_stream_offset(&self, name: &str) -> Result<usize, String> {
        let metadata = self.get_metadata().map_err(|e| e.to_string())?;
        let header = metadata.stream_headers.iter().find(|h| h.name == name).ok_or("bad stream name".to_string())?;
        let m_offset = utils::find_offset(
            self.get_cli_header().map_err(|e| e.to_string())?.metadata.virtual_address as usize,
            &self.object.sections,
            ALIGNMENT,
            &ParseOptions::default(),
        ).ok_or("bad offset".to_string())?;
        Ok(m_offset + header.offset as usize)
    }
}
