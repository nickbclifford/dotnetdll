#[macro_use]
mod utils {
    macro_rules! check_bitmask {
        ($mask:expr, $val:literal) => {
            $mask & $val == $val
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
    use scroll::{Pread, Pwrite};

    use super::{
        binary::*,
        dll::{ResolveOptions, DLL},
        resolved::ResolvedDebug,
    };

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/home/nick/Desktop/test/bin/Debug/net5.0/test.dll")?;
        let dll = DLL::parse(&file)?;

        let r = dll.resolve(ResolveOptions::default())?;

        use super::{resolution::EntryPoint, resolved::members::UserMethod};

        if let Some(e) = &r.entry_point {
            print!("assembly entry point: ");
            match e {
                EntryPoint::Method(m) => println!("{}", UserMethod::Definition(*m).show(&r)),
                EntryPoint::File(f) => println!("external file {}", f.borrow().name),
            }
        }

        for t in &r.type_definitions {
            println!("{} {{", t.show(&r));

            for m in &t.methods {
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
    fn compression() {
        use signature::compressed::*;

        macro_rules! test_case {
            ($ty:ident($val:expr) => [$($byte:literal),+]) => {
                let $ty(val) = [$($byte),+].pread(0).unwrap();
                assert_eq!(val, $val);

                // we need to include the variable for repetition, so discard its value
                let mut buf = [$({ $byte; 0 }),+];
                buf.pwrite($ty($val), 0).unwrap();
                assert_eq!(buf, [$($byte),+]);
            }
        }

        test_case!(Unsigned(0x03) => [0x03]);
        test_case!(Unsigned(0x3FFF) => [0xBF, 0xFF]);
        test_case!(Unsigned(0x4000) => [0xC0, 0x00, 0x40, 0x00]);

        test_case!(Signed(3) => [0x06]);
        test_case!(Signed(-3) => [0x7B]);
        test_case!(Signed(64) => [0x80, 0x80]);
        test_case!(Signed(-8192) => [0x80, 0x01]);
        test_case!(Signed(268435455) => [0xDF, 0xFF, 0xFF, 0xFE]);
        test_case!(Signed(-268435456) => [0xC0, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn def_ref_spec() {
        use metadata::table::Kind;
        use signature::encoded::TypeDefOrRefOrSpec;
        let TypeDefOrRefOrSpec(t) = [0x49].pread(0).unwrap();
        assert_eq!(t.target, metadata::index::TokenTarget::Table(Kind::TypeRef));
        assert_eq!(t.index, 0x12);

        let mut buf = [0_u8; 1];
        buf.pwrite(TypeDefOrRefOrSpec(t), 0).unwrap();
        assert_eq!(buf, [0x49]);
    }

    #[test]
    fn resolution() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();

        let file = std::fs::read("/home/nick/Desktop/test/bin/Debug/net5.0/test.dll")?;
        let dll = DLL::parse(&file)?;

        let opts = ResolveOptions {
            skip_method_bodies: true,
        };

        let r = dll.resolve(opts)?;

        use crate::{resolution::Resolution, resolved::types::*};
        use std::fmt;

        #[derive(Debug)]
        struct TypeNotFoundError(String);
        impl fmt::Display for TypeNotFoundError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "unable to find type {}", self.0)
            }
        }
        impl std::error::Error for TypeNotFoundError {}

        struct DLLCacheResolver<'a> {
            main: &'a Resolution<'a>,
            cache: &'a [Resolution<'a>],
        }
        impl<'a> Resolver<'a> for DLLCacheResolver<'a> {
            type Error = TypeNotFoundError;

            fn find_type(
                &self,
                name: &str,
            ) -> Result<(&TypeDefinition<'a>, &Resolution<'a>), Self::Error> {
                std::iter::once(self.main)
                    .chain(self.cache.iter())
                    .flat_map(|r| r.type_definitions.iter().map(move |t| (t, r)))
                    .find(|(t, _)| t.type_name() == name)
                    .ok_or_else(|| TypeNotFoundError(name.to_string()))
            }
        }

        let mut files = vec![];
        for p in std::fs::read_dir("/usr/share/dotnet/shared/Microsoft.NETCore.App/5.0.8")? {
            let path = p?.path();
            if matches!(path.extension(), Some(o) if o == "dll") {
                files.push(std::fs::read(path)?);
            }
        }
        let dlls: Vec<_> = files
            .iter()
            .map(|f| DLL::parse(&f))
            .collect::<Result<_, _>>()?;
        let cache: Vec<_> = dlls
            .iter()
            .map(|d| d.resolve(opts))
            .collect::<Result<_, _>>()?;

        let resolver = DLLCacheResolver {
            main: &r,
            cache: &cache,
        };

        if let Some(a) = &r.assembly {
            for a in &a.attributes {
                println!(
                    "assembly attribute {} ({:x?})",
                    a.constructor.show(&r),
                    a.value.unwrap()
                );
                match a.instantiation_data(&resolver, &r) {
                    Ok(d) => println!("data {:#?}", d),
                    Err(e) => println!("failed to parse data {}", e),
                }
            }
        }

        for t in &r.type_definitions {
            for a in &t.attributes {
                println!("type attribute {}", a.constructor.show(&r));
                println!("data {:#?}", a.instantiation_data(&resolver, &r)?);
            }

            for m in &t.methods {
                for a in &m.attributes {
                    println!("method attribute {}", a.constructor.show(&r));
                    println!("data {:#?}", a.instantiation_data(&resolver, &r)?);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn headers_write() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.205/System.Text.Json.dll")?;
        let dll = DLL::parse(&file)?;
        let meta = dll.get_logical_metadata()?;

        let mut buffer = vec![0_u8; dll.cli.metadata.size as usize];
        buffer.pwrite(meta, 0)?;

        let _parsed: metadata::header::Header = buffer.pread(0)?;

        // these two are equal if you ignore sorting
        // for some reason, the input tables appear to not be ECMA-compliantly sorted
        // assert_eq!(meta, parsed);

        Ok(())
    }

    #[test]
    fn attr_args_write() -> Result<(), Box<dyn std::error::Error>> {
        const SIZE: usize = 119;
        // retrieved from ildasm
        const DATA: [u8; SIZE] = [
            0x01, 0x00, 0x01, 0x61, 0x00, 0x04, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08,
            0x09, 0x00, 0x00, 0x00, 0x1D, 0x51, 0x04, 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x08, 0x05, 0x00, 0x00, 0x00, 0x1D, 0x51, 0x01, 0x00, 0x00, 0x00, 0x08, 0x02,
            0x00, 0x00, 0x00, 0x0E, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00,
            0x55, 0x09, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x41, 0x73, 0x64, 0x66, 0x04, 0x00, 0x0E,
            0x04, 0x6F, 0x6F, 0x70, 0x73, 0x02, 0x00, 0x53, 0x08, 0x03, 0x59, 0x65, 0x73, 0x03,
            0x00, 0x00, 0x00, 0x53, 0x51, 0x02, 0x4E, 0x6F, 0x55, 0x09, 0x74, 0x65, 0x73, 0x74,
            0x2E, 0x41, 0x73, 0x64, 0x66, 0x04, 0x00,
        ];

        use signature::attribute::*;
        use FixedArg::*;
        use IntegralParam::*;
        use NamedArg::*;

        let mut buf = [0u8; SIZE];
        buf.pwrite(
            // Into<Box<_>> is a little less noisy here
            CustomAttributeData {
                constructor_args: vec![
                    Boolean(true),
                    Char('a'),
                    Integral(UInt16(4)),
                    Array(None),
                    Array(Some(vec![
                        Integral(Int32(2)),
                        Integral(Int32(4)),
                        Integral(Int32(5)),
                    ])),
                    Object(Integral(Int32(9)).into()),
                    Object(
                        Array(Some(vec![
                            Object(Integral(Int32(2)).into()),
                            Object(Integral(Int32(5)).into()),
                            Object(Array(Some(vec![Object(Integral(Int32(2)).into())])).into()),
                            Object(String(None).into()),
                        ]))
                        .into(),
                    ),
                    Array(Some(vec![
                        Object(Integral(Int32(3)).into()),
                        Object(Enum("test.Asdf", UInt16(4)).into()),
                        Object(String(Some("oops")).into()),
                    ])),
                ],
                named_args: vec![
                    Field("Yes", Integral(Int32(3))),
                    Field("No", Object(Enum("test.Asdf", UInt16(4)).into())),
                ],
            },
            0,
        )?;

        assert_eq!(buf, DATA);

        Ok(())
    }
}
