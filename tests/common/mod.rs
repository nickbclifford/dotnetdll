use dotnetdll::prelude::*;
use std::process::Command;
use tempfile::TempDir;

pub struct WriteContext<'a> {
    pub resolution: Resolution<'a>,
    pub console: TypeRefIndex,
    pub object_ctor: MethodRefIndex,
    pub class: TypeIndex,
    pub default_ctor: MethodIndex,
    pub main: MethodIndex,
}

pub fn write_fixture(
    name: &str,
    test: impl FnOnce(&mut WriteContext),
    expect: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let dll_name = format!("{}.dll", name);

    let mut res = Resolution::new(Module::new((&dll_name).into()));
    res.assembly = Some(Assembly::new(name.into()));
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

    let mut ctx = WriteContext {
        resolution: res,
        console,
        class,
        default_ctor,
        object_ctor,
        main,
    };

    test(&mut ctx);

    let written = DLL::write(&ctx.resolution, false, true)?;

    let dir = TempDir::new()?;

    let dll_path = dir.path().join(&dll_name);
    std::fs::write(&dll_path, written)?;

    std::fs::copy(
        "tests/common/test.runtimeconfig.json",
        dir.path().join(format!("{}.runtimeconfig.json", name)),
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

    assert_eq!(output.stdout, expect);

    Ok(())
}
