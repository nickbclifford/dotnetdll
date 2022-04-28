use dotnetdll::prelude::*;
use std::process::Command;
use tempfile::TempDir;

pub struct WriteContext<'a> {
    pub resolution: Resolution<'a>,
    pub mscorlib: AssemblyRefIndex,
    pub console: TypeRefIndex,
    pub class: TypeIndex,
    pub default_ctor: MethodIndex,
    pub object: TypeRefIndex,
}

#[allow(dead_code)]
pub fn read_fixture(name: &str, source: &str, test: impl FnOnce(Resolution)) -> Result<(), Box<dyn std::error::Error>> {
    let ilasm_path: &str = "/home/nick/Desktop/runtime/artifacts/bin/coreclr/Linux.x64.Debug/ilasm";

    let dir = TempDir::new()?;

    let il_path = dir.path().join(format!("{}.il", name));

    std::fs::write(&il_path, source)?;

    Command::new(ilasm_path)
        .current_dir(dir.path())
        .arg("-DLL")
        .arg(name)
        .spawn()?
        .wait()?;

    let dll_file = std::fs::read(dir.path().join(format!("{}.dll", name)))?;
    let dll = DLL::parse(&dll_file)?;

    test(dll.resolve(ResolveOptions::default())?);

    Ok(())
}

pub fn write_fixture(
    name: &str,
    test: impl FnOnce(&mut WriteContext) -> (Vec<body::Exception>, Vec<LocalVariable>, Vec<Instruction>),
    expect: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let dll_name = format!("{}.dll", name);

    let mut res = Resolution::new(Module::new(&dll_name));
    res.assembly = Some(Assembly::new(name));

    let mscorlib = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"));

    let console = res.push_type_reference(type_ref! { System.Console in #mscorlib });

    let object = res.push_type_reference(type_ref! { System.Object in #mscorlib });

    let class = res.push_type_definition(TypeDefinition::new(None, "Program"));
    res[class].extends = Some(object.into());
    let default_ctor = res.add_default_ctor(class);

    let mut ctx = WriteContext {
        resolution: res,
        mscorlib,
        console,
        class,
        default_ctor,
        object,
    };

    let (exceptions, vars, ins) = test(&mut ctx);

    let main = ctx.resolution.push_method(
        class,
        Method::new(
            Accessibility::Public,
            msig! { static void (string[]) },
            "Main",
            Some(body::Method {
                data_sections: vec![body::DataSection::ExceptionHandlers(exceptions)],
                ..body::Method::with_locals(vars, ins)
            }),
        ),
    );
    ctx.resolution.entry_point = Some(main.into());

    let written = DLL::write(&ctx.resolution, false, true)?;

    let dir = TempDir::new()?;

    let dll_path = dir.path().join(&dll_name);
    std::fs::write(&dll_path, written)?;

    std::fs::copy(
        "tests/common/test.runtimeconfig.json",
        dir.path().join(format!("{}.runtimeconfig.json", name)),
    )?;

    let output = Command::new("dotnet").arg(&dll_path).output()?;

    eprintln!("{}", std::str::from_utf8(&output.stdout)?);

    let stderr = String::from_utf8(output.stderr)?;

    if stderr.contains("Unhandled exception") {
        if let Ok(i) = std::env::var("ILDASM") {
            Command::new(i).arg(&dll_path).spawn()?.wait()?;
        }

        if let Ok(r) = std::env::var("RUNTIME") {
            Command::new("gdb")
                .arg("-ex")
                .arg(format!("set substitute-path /runtime {}", r))
                .arg("--args")
                .arg(if let Ok(i) = std::env::var("ILDASM") {
                    i
                } else {
                    format!(
                        "{}/artifacts/bin/testhost/net7.0-Linux-Debug-x64/shared/Microsoft.NETCore.App/7.0.0/corerun",
                        r
                    )
                })
                .arg(&dll_path)
                .spawn()?
                .wait()?;
        }

        if let Ok(i) = std::env::var("ILVERIFY") {
            let ilverify = Command::new(i)
                .arg(&dll_path)
                .arg("-r")
                .arg("/usr/share/dotnet/shared/Microsoft.NETCore.App/6.0.2/*.dll")
                .output()?;
            println!("{}", String::from_utf8(ilverify.stdout)?);
        }

        if let Ok(path) = std::env::var("OUTFILE") {
            std::fs::copy(dll_path, path).unwrap();
        }

        panic!("{}", stderr);
    }

    assert_eq!(output.stdout, expect);

    Ok(())
}
