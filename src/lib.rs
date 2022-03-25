#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::enum_glob_use,
    clippy::items_after_statements,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::wildcard_imports
)]

#[macro_use]
mod utils {
    macro_rules! check_bitmask {
        ($mask:expr, $val:literal) => {
            $mask & $val == $val
        };
    }

    macro_rules! build_bitmask {
        ($target:expr, $($field:ident => $val:literal),+) => {{
            let mut mask = 0;
            $(
                if $target.$field {
                    mask |= $val;
                }
            )+
            mask
        }}
    }

    macro_rules! try_into_ctx {
        ($t:ty, |$s:ident, $buf:ident| $e:expr) => {
            try_into_ctx!(() => $t, |$s, $buf, _ctx| $e);
        };
        ($ctx:ty => $t:ty, |$s:ident, $buf:ident, $ctx_i:ident| $e:expr) => {
            impl TryIntoCtx<$ctx> for $t {
                type Error = scroll::Error;

                fn try_into_ctx(
                    $s,
                    $buf: &mut [u8],
                    $ctx_i: $ctx,
                ) -> std::result::Result<usize, Self::Error> {
                    $e
                }
            }

            impl TryIntoCtx<$ctx, scroll_buffer::DynamicBuffer> for $t {
                type Error = scroll::Error;

                fn try_into_ctx(
                    $s,
                    $buf: &mut scroll_buffer::DynamicBuffer,
                    $ctx_i: $ctx,
                ) -> std::result::Result<usize, Self::Error> {
                    $e
                }
            }
        };
    }

    use std::hash::*;

    pub fn hash(val: impl Hash) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    pub fn round_up_to_4(mut val: usize) -> (usize, usize) {
        let rem = val % 4;
        if rem != 0 {
            val += 4 - rem;
        }
        (val, rem)
    }
}

pub mod binary;
mod convert;
pub mod dll;
pub mod resolution;
pub mod resolved;

pub mod prelude {
    pub use crate::{
        dll::DLL,
        resolution::*,
        resolved::{
            assembly::*,
            body,
            il::*,
            members::{Accessibility as MAccess, *},
            module::*,
            signature::*,
            types::{Accessibility as TAccess, *},
            Accessibility,
        },
    };
}

#[cfg(test)]
mod tests {
    use super::{
        binary::*,
        dll::{ResolveOptions, DLL},
        resolved::ResolvedDebug,
    };
    use scroll::{Pread, Pwrite};

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/home/nick/Desktop/test/bin/Debug/net6.0/test.dll")?;
        let dll = DLL::parse(&file)?;

        let r = dll.resolve(ResolveOptions::default())?;

        use super::{resolution::EntryPoint, resolved::members::UserMethod};

        if let Some(e) = &r.entry_point {
            print!("assembly entry point: ");
            match e {
                EntryPoint::Method(m) => println!("{}", UserMethod::Definition(*m).show(&r)),
                EntryPoint::File(f) => println!("external file {}", r[*f].name),
            }
        }

        for t in &r.type_definitions {
            println!("{} {{", t.show(&r));

            for f in &t.fields {
                println!("\t{};", f.show(&r));
            }
            for p in &t.properties {
                println!("\t{};", p.show(&r));
            }

            for m in &t.methods {
                print!("\t{}", m.show(&r));

                if let Some(b) = &m.body {
                    println!(" {{");

                    if b.header.initialize_locals {
                        println!("\t\tinit locals");
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

                    let max_size = ((b.instructions.len() - 1) as f32).log10().ceil() as usize;

                    println!("\t\t---");

                    for (idx, instr) in b.instructions.iter().enumerate() {
                        println!("\t\t{:1$}: {2}", idx, max_size, instr.show(&r));
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

        macro_rules! case {
            ($ty:ident($val:expr) => [$($byte:literal),+]) => {
                let $ty(val) = [$($byte),+].pread(0).unwrap();
                assert_eq!(val, $val);

                // we need to include the variable for repetition, so discard its value
                let mut buf = [$({ let _x = $byte; 0 }),+];
                buf.pwrite($ty($val), 0).unwrap();
                assert_eq!(buf, [$($byte),+]);
            }
        }

        case!(Unsigned(0x03) => [0x03]);
        case!(Unsigned(0x3FFF) => [0xBF, 0xFF]);
        case!(Unsigned(0x4000) => [0xC0, 0x00, 0x40, 0x00]);

        case!(Signed(3) => [0x06]);
        case!(Signed(-3) => [0x7B]);
        case!(Signed(64) => [0x80, 0x80]);
        case!(Signed(-8192) => [0x80, 0x01]);
        case!(Signed(268_435_455) => [0xDF, 0xFF, 0xFF, 0xFE]);
        case!(Signed(-268_435_456) => [0xC0, 0x00, 0x00, 0x01]);
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
    fn time_resolve() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();
        let opts = ResolveOptions {
            skip_method_bodies: true,
        };

        let start = std::time::Instant::now();

        for p in std::fs::read_dir("/usr/share/dotnet/shared/Microsoft.NETCore.App/6.0.2")? {
            let path = p?.path();
            if matches!(path.extension(), Some(o) if o == "dll") {
                let file = std::fs::read(path)?;
                let dll = DLL::parse(&file)?;
                dll.resolve(opts)?;
            }
        }

        println!("total time: {:?}", start.elapsed());

        Ok(())
    }

    #[test]
    fn attr_args_write() -> Result<(), Box<dyn std::error::Error>> {
        const SIZE: usize = 119;
        // retrieved from ildasm
        const DATA: [u8; SIZE] = [
            0x01, 0x00, 0x01, 0x61, 0x00, 0x04, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x09, 0x00, 0x00, 0x00, 0x1D, 0x51, 0x04, 0x00,
            0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x00, 0x1D, 0x51, 0x01, 0x00, 0x00, 0x00,
            0x08, 0x02, 0x00, 0x00, 0x00, 0x0E, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x55, 0x09,
            0x74, 0x65, 0x73, 0x74, 0x2E, 0x41, 0x73, 0x64, 0x66, 0x04, 0x00, 0x0E, 0x04, 0x6F, 0x6F, 0x70, 0x73, 0x02,
            0x00, 0x53, 0x08, 0x03, 0x59, 0x65, 0x73, 0x03, 0x00, 0x00, 0x00, 0x53, 0x51, 0x02, 0x4E, 0x6F, 0x55, 0x09,
            0x74, 0x65, 0x73, 0x74, 0x2E, 0x41, 0x73, 0x64, 0x66, 0x04, 0x00,
        ];

        use signature::attribute::*;
        use FixedArg::*;
        use IntegralParam::*;
        use NamedArg::*;

        let mut buf = [0_u8; SIZE];
        buf.pwrite(
            // Into<Box<_>> is a little less noisy here
            CustomAttributeData {
                constructor_args: vec![
                    Boolean(true),
                    Char('a'),
                    Integral(UInt16(4)),
                    Array(None),
                    Array(Some(vec![Integral(Int32(2)), Integral(Int32(4)), Integral(Int32(5))])),
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

    #[test]
    pub fn constructor_macros() {
        use super::resolved::{signature::*, types::*};

        let m: MethodType = ctype! { string[] };
        println!("{:?}", m);
        let m: MethodType = ctype! { bool };
        println!("{:?}", m);
        let m: MethodType = ctype! { char[]* };
        println!("{:?}", m);
        let m: MethodType = ctype! { void*[] };
        println!("{:?}", m);

        println!("{:?}", msig! { static void (string[]) });
        println!("{:?}", msig! { string (int, ref #m) });
    }
}
