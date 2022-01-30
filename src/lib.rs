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
                println!("{:#?}", m);

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

        macro_rules! case {
            ($ty:ident($val:expr) => [$($byte:literal),+]) => {
                let $ty(val) = [$($byte),+].pread(0).unwrap();
                assert_eq!(val, $val);

                // we need to include the variable for repetition, so discard its value
                let mut buf = [$({ $byte; 0 }),+];
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
        case!(Signed(268435455) => [0xDF, 0xFF, 0xFF, 0xFE]);
        case!(Signed(-268435456) => [0xC0, 0x00, 0x00, 0x01]);
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

            fn find_type(&self, name: &str) -> Result<(&TypeDefinition<'a>, &Resolution<'a>), Self::Error> {
                std::iter::once(self.main)
                    .chain(self.cache.iter())
                    .flat_map(|r| r.type_definitions.iter().map(move |t| (t, r)))
                    .find(|(t, _)| t.type_name() == name)
                    .ok_or_else(|| TypeNotFoundError(name.to_string()))
            }
        }

        let mut files = vec![];
        for p in std::fs::read_dir("/usr/share/dotnet/shared/Microsoft.NETCore.App/6.0.0")? {
            let path = p?.path();
            if matches!(path.extension(), Some(o) if o == "dll") {
                files.push(std::fs::read(path)?);
            }
        }
        let dlls: Vec<_> = files.iter().map(|f| DLL::parse(f)).collect::<Result<_, _>>()?;
        let cache: Vec<_> = dlls.iter().map(|d| d.resolve(opts)).collect::<Result<_, _>>()?;

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
    fn write_all() {
        use super::{
            binary::signature::kinds::CallingConvention,
            resolution::{EntryPoint, Resolution},
            resolved::{
                assembly::*,
                body, il,
                members::{Accessibility as MAccess, *},
                module::Module,
                signature::*,
                types::{Accessibility as TAccess, *},
                Accessibility,
            },
        };

        const TOKEN: &[u8] = &[0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A];

        let mut res = Resolution::new(Module {
            attributes: vec![],
            name: "test.dll",
            mvid: [
                0x7d, 0xca, 0x02, 0xcd, 0xba, 0xd1, 0x4e, 0x45, 0xbf, 0x5f, 0x1b, 0x7d, 0xf1, 0x93, 0xce, 0x36,
            ],
        });
        res.assembly = Some(Assembly {
            attributes: vec![],
            hash_algorithm: HashAlgorithm::SHA1,
            version: Version {
                major: 1,
                minor: 0,
                build: 0,
                revision: 0,
            },
            flags: Flags::default(),
            public_key: None,
            name: "test",
            culture: None,
            security: None,
        });

        // global module type
        res.push_type_definition(TypeDefinition {
            attributes: vec![],
            name: "<Module>",
            namespace: None,
            fields: vec![],
            properties: vec![],
            methods: vec![],
            events: vec![],
            encloser: None,
            overrides: vec![],
            extends: None,
            implements: vec![],
            generic_parameters: vec![],
            flags: TypeFlags {
                accessibility: TAccess::NotPublic,
                layout: Layout::Automatic,
                kind: Kind::Class,
                abstract_type: false,
                sealed: false,
                special_name: false,
                imported: false,
                serializable: false,
                string_formatting: StringFormatting::ANSI,
                before_field_init: false,
                runtime_special_name: false,
            },
            security: None,
        });

        let console_asm_ref = res.push_assembly_reference(ExternalAssemblyReference {
            attributes: vec![],
            version: Version {
                major: 6,
                minor: 0,
                build: 0,
                revision: 0,
            },
            flags: Default::default(),
            public_key_or_token: Some(TOKEN),
            name: "System.Console",
            culture: None,
            hash_value: None,
        });
        let runtime_ref = res.push_assembly_reference(ExternalAssemblyReference {
            attributes: vec![],
            version: Version {
                major: 6,
                minor: 0,
                build: 0,
                revision: 0,
            },
            flags: Default::default(),
            public_key_or_token: Some(TOKEN),
            name: "System.Runtime",
            culture: None,
            hash_value: None,
        });
        let object_ref = res.push_type_reference(ExternalTypeReference {
            attributes: vec![],
            name: "Object",
            namespace: Some("System"),
            scope: ResolutionScope::Assembly(runtime_ref),
        });
        let ctor_sig = MethodSignature {
            instance: true,
            explicit_this: false,
            calling_convention: CallingConvention::Default,
            parameters: vec![],
            return_type: ReturnType(vec![], None),
            varargs: None,
        };
        let ctor_ref = res.push_method_reference(ExternalMethodReference {
            attributes: vec![],
            parent: MethodReferenceParent::Type(
                BaseType::Type(TypeSource::User(UserType::Reference(object_ref))).into(),
            ),
            name: ".ctor",
            signature: ctor_sig.clone(),
        });
        let console_type_ref = res.push_type_reference(ExternalTypeReference {
            attributes: vec![],
            name: "Console",
            namespace: Some("System"),
            scope: ResolutionScope::Assembly(console_asm_ref),
        });
        let write_line_ref = res.push_method_reference(ExternalMethodReference {
            attributes: vec![],
            parent: MethodReferenceParent::Type(
                BaseType::Type(TypeSource::User(UserType::Reference(console_type_ref))).into(),
            ),
            name: "WriteLine",
            signature: MethodSignature {
                instance: false,
                explicit_this: false,
                calling_convention: CallingConvention::Default,
                parameters: vec![Parameter(
                    vec![],
                    ParameterType::Value(BaseType::String.into()),
                )],
                return_type: ReturnType(vec![], None),
                varargs: None,
            },
        });

        let class = res.push_type_definition(TypeDefinition {
            attributes: vec![],
            name: "Foo",
            namespace: None,
            fields: vec![],
            properties: vec![],
            methods: vec![Method {
                attributes: vec![],
                name: ".ctor",
                body: Some(body::Method {
                    header: body::Header {
                        initialize_locals: false,
                        maximum_stack_size: 0,
                        local_variables: vec![],
                    },
                    body: vec![
                        il::Instruction::LoadArgument(0),
                        il::Instruction::Call {
                            tail_call: false,
                            method: MethodSource::User(UserMethod::Reference(ctor_ref)),
                        },
                        il::Instruction::Return,
                    ],
                    data_sections: vec![],
                }),
                signature: ctor_sig,
                accessibility: MAccess::Access(Accessibility::Public),
                generic_parameters: vec![],
                parameter_metadata: vec![None],
                static_member: false,
                sealed: false,
                virtual_member: false,
                hide_by_sig: true,
                vtable_layout: VtableLayout::ReuseSlot,
                strict: false,
                abstract_member: false,
                special_name: true,
                pinvoke: None,
                runtime_special_name: true,
                security: None,
                require_sec_object: false,
                body_format: BodyFormat::IL,
                body_management: BodyManagement::Managed,
                forward_ref: false,
                preserve_sig: false,
                synchronized: false,
                no_inlining: false,
                no_optimization: false,
            }],
            events: vec![],
            encloser: None,
            overrides: vec![],
            extends: Some(TypeSource::User(UserType::Reference(object_ref))),
            implements: vec![],
            generic_parameters: vec![],
            flags: TypeFlags {
                accessibility: TAccess::Public,
                layout: Layout::Automatic,
                kind: Kind::Class,
                abstract_type: false,
                sealed: false,
                special_name: false,
                imported: false,
                serializable: false,
                string_formatting: StringFormatting::ANSI,
                before_field_init: true,
                runtime_special_name: false,
            },
            security: None,
        });
        let method_idx = res.push_method(
            class,
            Method {
                attributes: vec![],
                name: "Main",
                body: Some(body::Method {
                    header: body::Header {
                        initialize_locals: false,
                        maximum_stack_size: 0,
                        local_variables: vec![],
                    },
                    body: vec![
                        il::Instruction::LoadString("Hello, world!".encode_utf16().collect()),
                        il::Instruction::Call {
                            tail_call: false,
                            method: MethodSource::User(UserMethod::Reference(write_line_ref)),
                        },
                        il::Instruction::Return,
                    ],
                    data_sections: vec![],
                }),
                signature: MethodSignature {
                    instance: false,
                    explicit_this: false,
                    calling_convention: CallingConvention::Default,
                    parameters: vec![Parameter(
                        vec![],
                        ParameterType::Value(
                            BaseType::Vector(vec![], BaseType::String.into()).into(),
                        ),
                    )],
                    return_type: ReturnType(vec![], None),
                    varargs: None,
                },
                accessibility: MAccess::Access(Accessibility::Public),
                generic_parameters: vec![],
                parameter_metadata: vec![
                    None,
                    Some(ParameterMetadata {
                        attributes: vec![],
                        name: "args",
                        is_in: false,
                        is_out: false,
                        optional: false,
                        default: None,
                        marshal: None,
                    }),
                ],
                static_member: true,
                sealed: false,
                virtual_member: false,
                hide_by_sig: true,
                vtable_layout: VtableLayout::ReuseSlot,
                strict: false,
                abstract_member: false,
                special_name: false,
                pinvoke: None,
                runtime_special_name: false,
                security: None,
                require_sec_object: false,
                body_format: BodyFormat::IL,
                body_management: BodyManagement::Managed,
                forward_ref: false,
                preserve_sig: false,
                synchronized: false,
                no_inlining: false,
                no_optimization: false,
            },
        );
        res.entry_point = Some(EntryPoint::Method(method_idx));

        let v = DLL::write(&res, false, true).unwrap();

        std::fs::write("test.dll", v).unwrap();
    }
}
