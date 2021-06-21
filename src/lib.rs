pub mod binary;
pub mod dll;
pub mod resolved;

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use regex::{Captures, Regex};
    use scroll::Pread;

    use super::{binary::*, dll};

    use context::*;
    use heap::Heap;
    use metadata::table::*;
    use signature::{compressed::*, encoded::*, kinds::*};

    impl ToCtxString for signature::encoded::Param {
        fn to_string(&self, ctx: Context) -> String {
            match &self.1 {
                ParamType::Type(t) => t.to_string(ctx),
                ParamType::ByRef(t) => format!("ref {}", t.to_string(ctx)),
                ParamType::TypedByRef => "wtf".to_string(),
            }
        }
    }

    impl MethodDef {
        pub fn access_mod(&self) -> &str {
            match self.flags & 0x7 {
                1 => "private",
                2 => "private protected",
                3 => "internal",
                4 => "protected",
                5 => "protected internal",
                6 => "public",
                _ => "",
            }
        }
    }

    impl ToCtxString for MethodDef {
        fn to_string(&self, ctx: Context) -> String {
            let sig = ctx
                .blobs
                .at_index(self.signature)
                .and_then(|d| d.pread_with::<MethodDefSig>(0, ()))
                .unwrap();

            let mut buf = String::new();

            buf.push_str(self.access_mod());

            buf.push(' ');

            if self.flags & 0x10 == 0x10 {
                buf.push_str("static ");
            }

            if self.flags & 0x400 == 0x400 {
                buf.push_str("abstract ");
            }

            buf.push_str(&match sig.ret_type.1 {
                RetTypeType::Type(t) => t.to_string(ctx),
                RetTypeType::ByRef(t) => format!("ref {}", t.to_string(ctx)),
                RetTypeType::TypedByRef => "wtf".to_string(),
                RetTypeType::Void => "void".to_string(),
            });

            buf.push(' ');

            buf.push_str(ctx.strs.at_index(self.name).unwrap());

            if let CallingConvention::Generic(num) = sig.calling_convention {
                buf.push('<');
                buf.push_str(
                    &(0..num)
                        .into_iter()
                        .map(|i| format!("M{}", i))
                        .collect::<Vec<String>>()
                        .join(", "),
                );
                buf.push('>');
            }

            buf.push('(');

            buf.push_str(
                &sig.params
                    .iter()
                    .map(|p| p.to_string(ctx))
                    .collect::<Vec<String>>()
                    .join(", "),
            );

            buf.push(')');

            buf
        }
    }

    impl ToCtxString for Field {
        fn to_string(&self, ctx: Context) -> String {
            let mut buf = String::new();

            let FieldSig(_, field_type) = ctx
                .blobs
                .at_index(self.signature)
                .and_then(|b| b.pread(0))
                .unwrap();

            buf.push_str(match self.flags & 0x7 {
                1 => "private ",
                2 => "private protected ",
                3 => "internal ",
                4 => "protected ",
                5 => "protected internal ",
                6 => "public ",
                _ => "",
            });

            if self.flags & 0x10 == 0x10 {
                buf.push_str("static ");
            }

            buf.push_str(&field_type.to_string(ctx));

            buf.push(' ');

            buf.push_str(&ctx.strs.at_index(self.name).unwrap());

            buf
        }
    }

    impl ToCtxString for Property {
        fn to_string(&self, ctx: Context) -> String {
            let mut buf = String::new();

            let sig: PropertySig = ctx
                .blobs
                .at_index(self.property_type)
                .and_then(|b| b.pread(0))
                .unwrap();

            if !sig.has_this {
                buf.push_str("static ")
            }

            buf.push_str(&sig.ret_type.to_string(ctx));

            buf.push(' ');

            buf.push_str(&ctx.strs.at_index(self.name).unwrap());

            if !sig.params.is_empty() {
                buf.push('[');
                buf.push_str(
                    &sig.params
                        .iter()
                        .map(|p| p.to_string(ctx))
                        .collect::<Vec<String>>()
                        .join(", "),
                );
                buf.push(']');
            }

            buf
        }
    }

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.204/Newtonsoft.Json.dll")?;
        let dll = dll::DLL::parse(&file)?;
        let strs: heap::Strings = dll.get_heap("#Strings")?;
        let blobs: heap::Blob = dll.get_heap("#Blob")?;
        let meta = dll.get_logical_metadata()?;

        let ctx = Context {
            strs: &strs,
            blobs: &blobs,
            tables: &meta.tables,
        };

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
        let strs: heap::Strings = dll.get_heap("#Strings")?;
        let blobs: heap::Blob = dll.get_heap("#Blob")?;
        let meta = dll.get_logical_metadata()?;

        let ctx = Context {
            strs: &strs,
            blobs: &blobs,
            tables: &meta.tables,
        };

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
