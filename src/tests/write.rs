use crate::dll::DLL;
use std::process::Command;
use tempfile::TempDir;

macro_rules! test {
    ($name:ident, $res:expr, $expect:expr) => {
        #[test]
        fn $name() -> Result<(), Box<dyn std::error::Error>> {
            let res = $res;

            let written = DLL::write(&res, false, true)?;

            let dir = TempDir::new()?;

            let dll_path = dir.path().join(format!("{}.dll", stringify!(name)));
            std::fs::write(&dll_path, written)?;

            std::fs::copy(
                "src/tests/test.runtimeconfig.json",
                dir.path()
                    .join(format!("{}.runtimeconfig.json", stringify!(name))),
            )?;

            let output = Command::new("dotnet").arg(dll_path).output()?;

            println!("{}", String::from_utf8(output.stderr)?);

            assert_eq!(output.stdout, $expect);

            Ok(())
        }
    };
}

test!(
    hello_world,
    {
        use crate::{
            resolution::Resolution,
            resolved::{
                assembly::*,
                body, il,
                members::*,
                module::Module,
                signature::*,
                types::{Accessibility as TAccess, *},
                Accessibility,
            },
        };

        const TOKEN: &[u8] = &[0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A];

        let mut res = Resolution::new(Module {
            attributes: vec![],
            name: "test.dll".into(),
            mvid: [
                0x7d, 0xca, 0x02, 0xcd, 0xba, 0xd1, 0x4e, 0x45, 0xbf, 0x5f, 0x1b, 0x7d, 0xf1, 0x93, 0xce, 0x36,
            ],
        });
        let mut assembly = Assembly::new("test".into());
        assembly.version.major = 1;
        res.assembly = Some(assembly);

        // global module type
        let mut module = TypeDefinition::new(None, "<Module>".into());
        module.flags.before_field_init = false;
        res.push_type_definition(module);

        let console_asm_ref = res.push_assembly_reference({
            let mut val = ExternalAssemblyReference::new("System.Console".into());
            val.version.major = 6;
            val.public_key_or_token = Some(TOKEN.into());
            val
        });
        let runtime_ref = res.push_assembly_reference({
            let mut val = ExternalAssemblyReference::new("System.Runtime".into());
            val.version.major = 6;
            val.public_key_or_token = Some(TOKEN.into());
            val
        });
        let object_ref = res.push_type_reference(ExternalTypeReference::new(
            Some("System".into()),
            "Object".into(),
            ResolutionScope::Assembly(runtime_ref),
        ));
        let ctor_sig = MethodSignature::instance(ReturnType::VOID, vec![]);
        let ctor_ref = res.push_method_reference(ExternalMethodReference::new(
            MethodReferenceParent::Type(
                BaseType::Type {
                    value_kind: ValueKind::Class,
                    source: object_ref.into(),
                }
                .into(),
            ),
            ".ctor".into(),
            ctor_sig.clone(),
        ));
        let console_type_ref = res.push_type_reference(ExternalTypeReference::new(
            Some("System".into()),
            "Console".into(),
            ResolutionScope::Assembly(console_asm_ref),
        ));
        let write_line_ref = res.push_method_reference(ExternalMethodReference::new(
            MethodReferenceParent::Type(
                BaseType::Type {
                    value_kind: ValueKind::Class,
                    source: console_type_ref.into(),
                }
                .into(),
            ),
            "WriteLine".into(),
            msig! { static void (string) },
        ));

        let mut foo_def = TypeDefinition::new(None, "Foo".into());
        foo_def.flags.accessibility = TAccess::Public;
        foo_def.extends = Some(object_ref.into());
        let mut method = Method::new(
            Accessibility::Public,
            ctor_sig,
            ".ctor".into(),
            Some(body::Method {
                header: body::Header {
                    initialize_locals: false,
                    maximum_stack_size: 0,
                    local_variables: vec![],
                },
                instructions: vec![
                    il::Instruction::LoadArgument(0),
                    il::Instruction::Call {
                        tail_call: false,
                        method: ctor_ref.into(),
                    },
                    il::Instruction::Return,
                ],
                data_sections: vec![],
            }),
        );
        method.special_name = true;
        method.runtime_special_name = true;
        foo_def.methods.push(method);

        let class = res.push_type_definition(foo_def);

        let mut main = Method::new(
            Accessibility::Public,
            msig! { static void (string[]) },
            "Main".into(),
            Some(body::Method {
                header: body::Header {
                    initialize_locals: false,
                    maximum_stack_size: 0,
                    local_variables: vec![],
                },
                instructions: vec![
                    il::Instruction::LoadString("Hello, world!".encode_utf16().collect()),
                    il::Instruction::Call {
                        tail_call: false,
                        method: write_line_ref.into(),
                    },
                    il::Instruction::Return,
                ],
                data_sections: vec![],
            }),
        );
        main.parameter_metadata
            .push(Some(ParameterMetadata::name("args".into())));

        let main_idx = res.push_method(class, main);

        res.entry_point = Some(main_idx.into());

        res
    },
    b"Hello, world!\n"
);
