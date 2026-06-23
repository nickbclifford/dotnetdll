use super::stream;
use scroll::{
    Pread, Pwrite,
    ctx::{StrCtx, TryFromCtx, TryIntoCtx},
};

/// A relative virtual address (RVA) paired with a byte size.
///
/// CLI headers use this pair to point at data regions inside the PE image.
/// See ECMA-335, II.25.3.3 (page 283).
#[derive(Debug, Default, Pread, Pwrite)]
pub struct RVASize {
    /// Relative virtual address of the target data.
    pub rva: u32,
    /// Size of the target data in bytes.
    pub size: u32,
}

/// The CLI header (`IMAGE_COR20_HEADER`) stored in PE data directory entry 15.
///
/// This header has a fixed size of 72 bytes and describes where managed metadata
/// and other CLI-related data directories live in the file. See ECMA-335,
/// II.25.3.3 (page 283).
#[derive(Debug, Pread, Pwrite)]
pub struct Header {
    /// Size of this header in bytes (72 for current CLI images).
    pub cb: u32,
    /// Required major CLR runtime version.
    pub major_runtime_version: u16,
    /// Required minor CLR runtime version.
    pub minor_runtime_version: u16,
    /// RVA/size of the metadata root header.
    pub metadata: RVASize,
    /// CLI runtime flags (for example `ILONLY` and `32BITREQUIRED`).
    pub flags: u32,
    /// Managed entry-point metadata token (typically the `Main` method).
    pub entry_point_token: u32,
    /// RVA/size of managed resources.
    pub resources: RVASize,
    /// RVA/size of the strong-name signature blob.
    pub strong_name_signature: RVASize,
    /// RVA/size of the code manager table (reserved, normally zero).
    pub code_manager_table: RVASize,
    /// RVA/size of vtable fixups.
    pub vtable_fixups: RVASize,
    /// RVA/size of export address table jumps.
    pub export_address_table_jumps: RVASize,
    /// RVA/size of the managed native header.
    pub managed_native_header: RVASize,
}

/// The CLI metadata root header at [`Header::metadata`].
///
/// This structure begins with the metadata signature/version block and is followed
/// by one header per stream (`#~`, `#Strings`, `#Blob`, and others). See
/// ECMA-335, II.24.2.1.
#[derive(Debug)]
pub struct Metadata<'a> {
    /// Metadata signature (`0x424A_5342`, "BSJB").
    pub signature: u32,
    /// Major metadata version number.
    pub major_version: u16,
    /// Minor metadata version number.
    pub minor_version: u16,
    /// Reserved field; should be zero.
    pub reserved: u32,
    /// Null-terminated metadata version string with trailing padding removed.
    pub version: &'a str,
    /// Metadata root flags.
    pub flags: u16,
    /// Per-stream headers declaring stream name, offset, and size.
    pub stream_headers: Vec<stream::Header<'a>>,
}

impl<'a> TryFromCtx<'a> for Metadata<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let sig = from.gread_with(offset, scroll::LE)?;
        let maj = from.gread_with(offset, scroll::LE)?;
        let min = from.gread_with(offset, scroll::LE)?;
        let res = from.gread_with(offset, scroll::LE)?;
        let len: u32 = from.gread_with(offset, scroll::LE)?;

        let version: &str = from.gread_with(offset, StrCtx::Length(len as usize))?;

        let flags = from.gread_with(offset, scroll::LE)?;
        let n_streams: u16 = from.gread_with(offset, scroll::LE)?;

        let headers = (0..n_streams).map(|_| from.gread(offset)).collect::<Result<_, _>>()?;

        Ok((
            Metadata {
                signature: sig,
                major_version: maj,
                minor_version: min,
                reserved: res,
                version: version.trim_matches('\0'),
                flags,
                stream_headers: headers,
            },
            *offset,
        ))
    }
}
impl TryIntoCtx for Metadata<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(self.signature, offset, scroll::LE)?;
        into.gwrite_with(self.major_version, offset, scroll::LE)?;
        into.gwrite_with(self.minor_version, offset, scroll::LE)?;
        into.gwrite_with(self.reserved, offset, scroll::LE)?;

        let (len, rem) = crate::utils::round_up_to_4(self.version.len() + 1);
        into.gwrite_with(len as u32, offset, scroll::LE)?;

        into.gwrite(self.version, offset)?;
        into.gwrite_with(0_u8, offset, scroll::LE)?;

        // pad out to 4 bytes
        *offset += rem;

        into.gwrite_with(self.flags, offset, scroll::LE)?;

        into.gwrite_with(self.stream_headers.len() as u16, offset, scroll::LE)?;
        for h in self.stream_headers {
            into.gwrite(h, offset)?;
        }

        Ok(*offset)
    }
}
