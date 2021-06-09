pub mod binary;

#[cfg(test)]
mod tests {
    use crate::binary::*;
    use context::*;
    use heap::Heap;
    use metadata::table::*;
    use signature::{compressed::*, encoded::*, kinds::*};

    use regex::{Captures, Regex};
    use scroll::Pread;
    use std::collections::{HashMap, HashSet};

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
        let file = std::fs::read("/home/nick/Desktop/test/bin/Debug/net5.0/test.dll")?;
        let dll = dll::DLL::parse(&file)?;
        let strs: heap::Strings = dll.get_heap("#Strings")?;
        let blobs: heap::Blob = dll.get_heap("#Blob")?;
        let meta = dll.get_logical_metadata()?;

        let ctx = Context {
            strs: &strs,
            blobs: &blobs,
            tables: &meta.tables,
        };

        for attr in meta.tables.custom_attribute.iter() {
            use metadata::index::*;
            let sig = match attr.attr_type {
                CustomAttributeType(idx, Kind::MethodDef) => blobs
                    .at_index(meta.tables.method_def[idx - 1].signature)?
                    .pread_with::<MethodDefSig>(0, ())?,
                CustomAttributeType(idx, Kind::MemberRef) => {
                    let member_ref = meta.tables.member_ref[idx - 1];
                    let sig = blobs
                        .at_index(member_ref.signature)?
                        .pread::<MethodRefSig>(0)?;
                    sig.method_def
                }
                _ => unreachable!(),
            };
            println!(
                "({}): {:x?}",
                sig.params
                    .iter()
                    .map(|p| p.to_string(ctx))
                    .collect::<Vec<_>>()
                    .join(", "),
                blobs.at_index(attr.value)?
            );
        }

        let field_len = meta.tables.field.len();
        let method_len = meta.tables.method_def.len();
        let prop_len = meta.tables.property.len();

        let property_map: HashMap<_, _> = meta
            .tables
            .property_map
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let last_prop = match meta.tables.property_map.get(idx + 1) {
                    Some(n) => n.property_list.0,
                    None => prop_len + 1,
                } - 1;
                (
                    p.parent.0 - 1,
                    &meta.tables.property[p.property_list.0 - 1..last_prop],
                )
            })
            .collect();

        let semantic_methods: HashSet<_> = meta
            .tables
            .method_semantics
            .iter()
            .map(|s| s.method.0 - 1)
            .collect();

        #[derive(Debug)]
        struct PropSemantics {
            get: Option<MethodDef>,
            set: Option<MethodDef>,
        }
        let mut prop_semantics: HashMap<usize, PropSemantics> = HashMap::new();
        for s in meta.tables.method_semantics.iter() {
            let metadata::index::HasSemantics(idx, kind) = s.association;
            if kind == Kind::Property {
                let sem = prop_semantics.entry(idx - 1).or_insert(PropSemantics {
                    get: None,
                    set: None,
                });
                let method = meta.tables.method_def[s.method.0 - 1];
                if s.semantics & 0x1 == 0x1 {
                    sem.set = Some(method);
                }
                if s.semantics & 0x2 == 0x2 {
                    sem.get = Some(method);
                }
            }
        }

        for (t_idx, row) in meta.tables.type_def.iter().enumerate() {
            let name = row.to_string(ctx);

            let gen_name = Regex::new(r"`(\d+)")
                .unwrap()
                .replace(&name, |c: &Captures| {
                    let mut buf = String::new();
                    let num_gen: usize = c[1].parse().unwrap();
                    buf.push('<');
                    buf.push_str(
                        &(0..num_gen)
                            .into_iter()
                            .map(|i| format!("T{}", i))
                            .collect::<Vec<String>>()
                            .join(", "),
                    );
                    buf.push('>');
                    buf
                });

            match row.flags & 0x7 {
                0 => print!("internal "),
                1 => print!("public "),
                _ => {}
            }

            if row.flags & 0x80 == 0x80 {
                print!("abstract ");
            }

            if row.flags & 0x100 == 0x100 {
                print!("sealed ");
            }

            let mut ext_name: Option<String> = None;
            let mut is_value_type = false;
            if row.extends.0 != 0 {
                let name = row.extends.to_string(ctx);
                is_value_type = name == "System.ValueType";
                ext_name = Some(name);
            }

            if is_value_type {
                print!("struct ");
            } else {
                match row.flags & 0x20 {
                    0x00 => print!("class "),
                    0x20 => print!("interface "),
                    _ => {}
                }
            }

            print!("{} ", gen_name);

            match ext_name {
                Some(n) if !is_value_type && n != "System.Object" => print!(": {} ", n),
                _ => {}
            }

            println!("{{");

            let field_idx = row.field_list.0;
            if field_idx != 0 {
                let last_field = match meta.tables.type_def.get(t_idx + 1) {
                    Some(t) => t.field_list.0,
                    None => field_len + 1,
                } - 1;

                for field in &meta.tables.field[field_idx - 1..last_field] {
                    println!("\t{};", field.to_string(ctx));
                }
            }

            if let Some(props) = property_map.get(&t_idx) {
                for (p_idx, prop) in props.iter().enumerate() {
                    print!("\t{} {{ ", prop.to_string(ctx));
                    let sem = &prop_semantics[&p_idx];
                    if let Some(m) = sem.get {
                        print!("{} get; ", m.access_mod())
                    }
                    if let Some(m) = sem.set {
                        print!("{} set; ", m.access_mod())
                    }
                    println!("}}")
                }
            }

            let method_idx = row.method_list.0;
            if method_idx != 0 {
                let last_method = match meta.tables.type_def.get(t_idx + 1) {
                    Some(t) => t.method_list.0,
                    None => method_len + 1,
                } - 1;

                for (m_idx, method) in meta.tables.method_def[method_idx - 1..last_method]
                    .iter()
                    .enumerate()
                {
                    if semantic_methods.contains(&(m_idx + method_idx - 1)) {
                        continue;
                    }
                    println!("\t{};", method.to_string(ctx));
                }
            }

            println!("}}");
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
}
