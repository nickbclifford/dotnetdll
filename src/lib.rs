#[macro_use]
mod utils {
    macro_rules! check_bitmask {
        ($mask:expr, $val:literal) => {
            $mask & $val == $val
        };
    }

    macro_rules! opt_map_try {
        ($var:expr, |$capt: ident| $res:expr) => {
            match $var {
                Some($capt) => Some($res?),
                None => None,
            }
        };
    }
}

pub mod binary;
mod convert;
pub mod dll;
pub mod resolved;

#[cfg(test)]
mod tests {
    use scroll::Pread;

    use super::{binary::*, dll::DLL};

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.204/Newtonsoft.Json.dll")?;
        let dll = DLL::parse(&file)?;

        let r = dll.resolve()?;

        for t in r.type_definitions {
            use super::resolved::types::Kind;

            print!(
                "{} ",
                match t.flags.kind {
                    Kind::Class => "class",
                    Kind::Interface => "interface",
                }
            );

            println!("{} {{", t.type_name());

            for f in t.fields {
                print!("\t");
                if f.static_member {
                    print!("static ");
                }
                println!("field {}", f.name);
            }
            for p in t.properties {
                print!("\t");

                if [p.getter, p.setter]
                    .iter()
                    .filter_map(|m| m.as_ref())
                    .chain(p.other.iter())
                    .any(|m| m.static_member)
                {
                    print!("static ");
                }

                println!("property {}", p.name);
            }
            for e in t.events {
                print!("\t");
                if matches!(e.raise_event, Some(m) if m.static_member)
                    || [e.add_listener, e.remove_listener]
                        .iter()
                        .chain(e.other.iter())
                        .any(|m| m.static_member)
                {
                    print!("static ");
                }
                println!("event {}", e.name);
            }
            for m in t.methods {
                print!("\t");
                if m.static_member {
                    print!("static ");
                }
                println!("method {}", m.name);
            }

            println!("}}\n");
        }

        Ok(())
    }

    #[test]
    fn decompress() {
        use signature::compressed::*;

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
        use metadata::table::Kind;
        use signature::encoded::TypeDefOrRefOrSpec;
        let TypeDefOrRefOrSpec(t) = [0x49].pread(0).unwrap();
        assert_eq!(t.target, metadata::index::TokenTarget::Table(Kind::TypeRef));
        assert_eq!(t.index, 0x12);
    }

    #[test]
    fn disassemble() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.204/System.Text.Json.dll")?;
        let dll = DLL::parse(&file)?;
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
