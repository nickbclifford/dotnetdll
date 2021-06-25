pub mod binary;
pub mod dll;
pub mod resolved;

mod utils {
    pub fn check_bitmask<T: num_traits::PrimInt>(mask: T, value: T) -> bool {
        mask & value == value
    }
}

#[cfg(test)]
mod tests {
    use scroll::Pread;

    use super::{binary::*, dll};
    use heap::Heap;
    use metadata::table::Kind;
    use signature::{compressed::*, encoded::TypeDefOrRefOrSpec};

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.204/System.Text.Json.dll")?;
        let dll = dll::DLL::parse(&file)?;
        let blobs: heap::Blob = dll.get_heap("#Blob")?;
        let meta = dll.get_logical_metadata()?;

        for attr in meta.tables.custom_attribute.iter() {
            println!("idx {:?}", attr.parent);
            println!("{:x?}", blobs.at_index(attr.value)?)
        }

        Ok(())
    }

    #[test]
    fn decompress() {
        let Unsigned(u1) = [0x03].pread(0).unwrap();
        assert_eq!(u1, 0x03);
        let Unsigned(u2) = [0xBF, 0xFF].pread(0).unwrap();
        assert_eq!(u2, 0x3FFF);
        let Unsigned(u4) = [0xC0, 0x00, 0x40, 0x00].pread(0).unwrap();
        assert_eq!(u4, 0x4000);
        let Signed(sp1) = [0x06].pread(0).unwrap();
        assert_eq!(sp1, 3);
        let Signed(sn1) = [0x7B].pread(0).unwrap();
        assert_eq!(sn1, -3);
        let Signed(sp2) = [0x80, 0x80].pread(0).unwrap();
        assert_eq!(sp2, 64);
        let Signed(sn2) = [0x80, 0x01].pread(0).unwrap();
        assert_eq!(sn2, -8192);
        let Signed(sp4) = [0xDF, 0xFF, 0xFF, 0xFE].pread(0).unwrap();
        assert_eq!(sp4, 268435455);
        let Signed(sn4) = [0xC0, 0x00, 0x00, 0x01].pread(0).unwrap();
        assert_eq!(sn4, -268435456);
    }

    #[test]
    fn def_ref_spec() {
        let TypeDefOrRefOrSpec(t) = [0x49].pread(0).unwrap();
        assert_eq!(t.target, metadata::index::TokenTarget::Table(Kind::TypeRef));
        assert_eq!(t.index, 0x12);
    }

    #[test]
    fn disassemble() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.204/System.Text.Json.dll")?;
        let dll = dll::DLL::parse(&file)?;
        let meta = dll.get_logical_metadata()?;

        for row in meta.tables.method_def.iter() {
            if row.rva == 0 {
                continue;
            }
            let meth = dll.get_method(&row)?;

            println!("{:#?}", meth.body);
        }

        Ok(())
    }
}
