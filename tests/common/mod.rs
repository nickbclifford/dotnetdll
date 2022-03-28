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

pub fn write_fixture(
    name: &str,
    test: impl FnOnce(&mut WriteContext) -> (Vec<LocalVariable>, Vec<Instruction>),
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

    let (vars, ins) = test(&mut ctx);

    let main = ctx.resolution.push_method(
        class,
        Method::new(
            Accessibility::Public,
            msig! { static void (string[]) },
            "Main",
            Some(body::Method::with_locals(vars, ins)),
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

    let stderr = String::from_utf8(output.stderr)?;

    println!("{}", stderr);
    if stderr.contains("Unhandled exception") {
        if let Ok(i) = std::env::var("ILDASM") {
            let ildasm = Command::new(i).arg(&dll_path).output()?;
            println!("{}", String::from_utf8(ildasm.stdout)?);
        }

        if let Ok(r) = std::env::var("RUNTIME") {
            Command::new("gdb")
                .arg("-ex")
                .arg(format!("set substitute-path /runtime {}", r))
                .arg("--args")
                .arg(format!(
                    "{}/artifacts/bin/testhost/net7.0-Linux-Debug-x64/shared/Microsoft.NETCore.App/7.0.0/corerun",
                    r
                ))
                .arg(&dll_path)
                .spawn()?
                .wait()?;
        }

        if let Ok(i) = std::env::var("ILVERIFY") {
            let ilverify = Command::new(i)
                .arg(dll_path)
                .arg("-r")
                .arg("/usr/share/dotnet/shared/Microsoft.NETCore.App/6.0.2/*.dll")
                .output()?;
            println!("{}", String::from_utf8(ilverify.stdout)?);
        }
    }

    assert_eq!(output.stdout, expect);

    Ok(())
}
