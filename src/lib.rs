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
pub mod resolution;
pub mod resolved;

#[cfg(test)]
mod tests {
    use scroll::Pread;

    use super::{binary::*, dll::{DLL, DLLError}, resolved::ResolvedDebug};

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/home/nick/Desktop/test/bin/Debug/net5.0/test.dll")?;
        let dll = DLL::parse(&file)?;

        let r = dll.resolve()?;

        use super::{resolution::EntryPoint, resolved::members::UserMethod};

        print!("assembly entry point: ");
        match &r.entry_point {
            EntryPoint::Method(m) => println!("{}", UserMethod::Definition(*m).show(&r)),
            EntryPoint::File(f) => println!("external file {}", f.borrow().name)
        }

        for t in r.type_definitions.iter() {
            println!("{} {{", t.show(&r));

            for m in t.methods.iter() {
                print!("\t{}", m.show(&r));

                if let Some(b) = &m.body {
                    println!(" {{");

                    if b.header.initialize_locals {
                        println!("\t\tinit locals")
                    }
                    println!("\t\tmaximum stack size {}", b.header.maximum_stack_size);
                    let locals = &b.header.local_variables;
                    if !locals.is_empty() {
                        println!("\t\tlocal variables:");

                        let max_size = ((locals.len() - 1) as f32).log10().ceil() as usize;

                        for (idx, v) in locals.iter().enumerate() {
                            println!("\t\t\t{:1$}: {2}", idx, max_size, v.show(&r));
                        }
                    }

                    let max_size = ((b.body.len() - 1) as f32).log10().ceil() as usize;

                    println!("\t\t---");

                    for (idx, instr) in b.body.iter().enumerate() {
                        println!("\t\t{:1$}: {2}", idx, max_size, instr.show(&r))
                    }

                    println!("\t}}");
                } else {
                    println!(";");
                }
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

    #[test]
    fn attributes() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/home/nick/Desktop/test/bin/Debug/net5.0/test.dll")?;
        let dll = DLL::parse(&file)?;

        let r = dll.resolve()?;

        use crate::{resolved::types::*, resolution::Resolution};

        struct SingleAssemblyResolver<'a>(&'a Resolution<'a>);
        impl<'a> Resolver<'a> for SingleAssemblyResolver<'a> {
            type Error = DLLError;

            fn find_type(&self, name: &str) -> Result<(&'a TypeDefinition<'a>, &'a Resolution<'a>), Self::Error> {
                println!("looking for type {}", name);

                match self.0.type_definitions.iter().find(|t| t.type_name() == name) {
                    Some(t) => Ok((t, self.0)),
                    None => Err(DLLError::Other("couldn't find type"))
                }
            }
        }

        let resolver = SingleAssemblyResolver(&r);

        if let Some(a) = &r.assembly {
            for a in a.attributes.iter() {
                println!("assembly attribute {} ({:x?})", a.constructor.show(&r), a.value.unwrap());
                match a.instantiation_data(&resolver, &r) {
                    Ok(d) => println!("data {:#?}", d),
                    Err(e) => println!("failed to parse data {}", e)
                }
            }
        }

        for t in r.type_definitions.iter() {
            for a in t.attributes.iter() {
                println!("type attribute {}", a.constructor.show(&r));
                println!("data {:#?}", a.instantiation_data(&resolver, &r)?);
            }

            for m in t.methods.iter() {
                for a in m.attributes.iter() {
                    println!("method attribute {}", a.constructor.show(&r));
                    println!("data {:#?}", a.instantiation_data(&resolver, &r)?);
                }
            }
        }

        Ok(())
    }
}
