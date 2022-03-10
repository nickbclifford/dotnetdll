use crate::prelude::*;
use std::process::Command;
use tempfile::TempDir;

struct Context<'a> {
    resolution: Resolution<'a>,
    console: TypeRefIndex,
    object_ctor: MethodRefIndex,
    class: TypeIndex,
    default_ctor: MethodIndex,
    main: MethodIndex,
}

macro_rules! test {
    ($name:ident, |$ctx:ident| $body:expr, $expect:expr) => {
        #[test]
        fn $name() -> Result<(), Box<dyn std::error::Error>> {
            let dll_name = format!("{}.dll", stringify!($name));

            let mut res = Resolution::new(Module::new((&dll_name).into()));
            res.assembly = Some(Assembly::new(stringify!($name).into()));
            res.push_global_module_type();

            let mscorlib = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib".into()));

            let console = res.push_type_reference(type_ref! { System.Console in #mscorlib });

            let object = res.push_type_reference(type_ref! { System.Object in #mscorlib });

            let class = res.push_type_definition(TypeDefinition::new(None, "Program".into()));
            res[class].extends = Some(object.into());

            let object_type = BaseType::class(object.into()).into();
            let object_ctor = res.push_method_reference(method_ref! { void #object_type::.ctor() });

            let default_ctor = res.push_method(
                class,
                Method::new(
                    Accessibility::Public,
                    msig! { void () },
                    ".ctor".into(),
                    Some(body::Method {
                        instructions: vec![
                            Instruction::LoadArgument(0),
                            Instruction::Call {
                                tail_call: false,
                                method: object_ctor.into(),
                            },
                            Instruction::Return,
                        ],
                        ..Default::default()
                    }),
                ),
            );
            res[default_ctor].special_name = true;
            res[default_ctor].runtime_special_name = true;

            let main = res.push_method(
                class,
                Method::new(
                    Accessibility::Public,
                    msig! { static void (string[]) },
                    "Main".into(),
                    Some(Default::default()),
                ),
            );

            res.entry_point = Some(main.into());

            let mut $ctx = Context {
                resolution: res,
                console,
                class,
                default_ctor,
                object_ctor,
                main,
            };

            $body;

            let written = DLL::write(&$ctx.resolution, false, true)?;

            let dir = TempDir::new()?;

            let dll_path = dir.path().join(&dll_name);
            std::fs::write(&dll_path, written)?;

            std::fs::copy(
                "src/tests/test.runtimeconfig.json",
                dir.path()
                    .join(format!("{}.runtimeconfig.json", stringify!($name))),
            )?;

            let output = Command::new("dotnet").arg(&dll_path).output()?;

            let stderr = String::from_utf8(output.stderr)?;

            println!("{}", stderr);
            if stderr.contains("invalid program") {
                let ilverify = Command::new("ilverify")
                    .arg(dll_path)
                    .arg("-r")
                    .arg("/usr/share/dotnet/shared/Microsoft.NETCore.App/6.0.2/*.dll")
                    .output()?;
                println!("{}", String::from_utf8(ilverify.stdout)?);
            }

            assert_eq!(output.stdout, $expect);

            Ok(())
        }
    };
}

test!(
    hello_world,
    |ctx| {
        let console_type = BaseType::class(ctx.console.into()).into();
        let write_line = ctx
            .resolution
            .push_method_reference(method_ref! { static void #console_type::WriteLine(string) });
        ctx.resolution[ctx.main].body.as_mut().unwrap().instructions.extend([
            Instruction::LoadString("Hello, world!".encode_utf16().collect()),
            Instruction::Call {
                tail_call: false,
                method: write_line.into(),
            },
            Instruction::Return,
        ]);
    },
    b"Hello, world!\n"
);

test!(
    fields,
    |ctx| {
        let console_type = BaseType::class(ctx.console.into()).into();
        let write_line = ctx
            .resolution
            .push_method_reference(method_ref! { static void #console_type::WriteLine(string, object, object) });

        let static_field = ctx.resolution.push_field(
            ctx.class,
            Field::static_member(Accessibility::Public, "static_field".into(), ctype! { int }),
        );
        let instance_field = ctx.resolution.push_field(
            ctx.class,
            Field::instance(Accessibility::Public, "instance_field".into(), ctype! { uint }),
        );

        let main_body = ctx.resolution[ctx.main].body.as_mut().unwrap();
        main_body
            .header
            .local_variables
            .push(LocalVariable::new(BaseType::class(ctx.class.into()).into()));
        main_body.instructions.extend([
            // init static
            Instruction::LoadConstantInt32(-1),
            Instruction::StoreStaticField {
                volatile: false,
                field: static_field.into(),
            },
            // init instance
            Instruction::NewObject(ctx.default_ctor.into()),
            Instruction::Duplicate,
            Instruction::StoreLocal(0),
            Instruction::LoadConstantInt32(1),
            Instruction::StoreField {
                unaligned: None,
                volatile: false,
                field: instance_field.into(),
            },
            // increment static
            Instruction::LoadStaticField {
                volatile: false,
                field: static_field.into(),
            },
            Instruction::LoadConstantInt32(1),
            Instruction::Add,
            Instruction::StoreStaticField {
                volatile: false,
                field: static_field.into(),
            },
            // increment instance
            Instruction::LoadLocalVariable(0),
            Instruction::Duplicate,
            Instruction::LoadField {
                unaligned: None,
                volatile: false,
                field: instance_field.into(),
            },
            Instruction::LoadConstantInt32(1),
            Instruction::Add,
            Instruction::StoreField {
                unaligned: None,
                volatile: false,
                field: instance_field.into(),
            },
            // print
            Instruction::LoadString("{0}, {1}".encode_utf16().collect()),
            Instruction::LoadStaticField {
                volatile: false,
                field: static_field.into(),
            },
            Instruction::Box(ctype! { int }),
            Instruction::LoadLocalVariable(0),
            Instruction::LoadField {
                unaligned: None,
                volatile: false,
                field: instance_field.into(),
            },
            Instruction::Box(ctype! { uint }),
            Instruction::Call {
                tail_call: false,
                method: write_line.into(),
            },
            Instruction::Return,
        ]);
    },
    b"0, 2\n"
);
