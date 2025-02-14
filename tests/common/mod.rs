#![allow(dead_code)]

use dotnetdll::prelude::*;
use regex::Regex;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

pub mod env;

#[allow(unused_macros)]
macro_rules! assert_inner_eq {
    ($val:expr, { $($field_name:ident $(: $rhs:expr)? $(=> $pat:pat $(if $guard:expr)?)?),+ }) => {
        let val = &$val;
        $(
            assert_inner_eq!(@inner val.$field_name, $(: $rhs)? $(=> $pat $(if $guard)?)?);
        )+
    };
    (@inner $lhs:expr, : true) => {
        assert!($lhs);
    };
    (@inner $lhs:expr, : $rhs:expr) => {
        assert_eq!($lhs, $rhs);
    };
    (@inner $lhs:expr, => $pat:pat $(if $guard:expr)?) => {
        assert!(matches!($lhs, $pat $(if $guard)?))
    }
}

pub struct WriteContext<'a> {
    pub resolution: Resolution<'a>,
    pub mscorlib: AssemblyRefIndex,
    pub console: TypeRefIndex,
    pub class: TypeIndex,
    pub ctor_cache: ConstructorCache,
    pub default_ctor: MethodIndex,
    pub object: TypeRefIndex,
}

pub fn read_fixture(name: &str, source: &str, test: impl FnOnce(Resolution)) -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;

    let il_path = dir.path().join(format!("{}.il", name));

    std::fs::write(
        &il_path,
        format!(
            r".assembly {} {{ }}
            .assembly extern mscorlib {{ }}
            {}",
            name, source
        ),
    )?;

    Command::new(env::ILASM.clone())
        .current_dir(dir.path())
        .arg("-DLL")
        .arg(name)
        .spawn()?
        .wait()?;

    let dll_file = std::fs::read(dir.path().join(format!("{}.dll", name)))?;

    test(Resolution::parse(&dll_file, ReadOptions::default())?);

    Ok(())
}

pub enum MainMethod {
    Body(Vec<Instruction>),
    WithVariables {
        body: Vec<Instruction>,
        locals: Vec<LocalVariable>,
    },
    WithExceptions {
        body: Vec<Instruction>,
        locals: Vec<LocalVariable>,
        exceptions: Vec<body::Exception>,
    },
}

pub fn write_fixture(
    name: &str,
    test: impl FnOnce(&mut WriteContext) -> MainMethod,
    expect: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let dll_name = format!("{}.dll", name);

    let mut res = Resolution::new(Module::new(&dll_name));
    res.assembly = Some(Assembly::new(name));

    let mscorlib = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"));

    let console = res.push_type_reference(type_ref! { System.Console in #mscorlib });

    let object = res.push_type_reference(type_ref! { System.Object in #mscorlib });

    let class = res.push_type_definition(TypeDefinition::new(None, "Program"));
    res[class].set_extends(object);

    let mut cache = ConstructorCache::new();
    let default_ctor = cache.define_default_ctor(&mut res, class);

    let mut ctx = WriteContext {
        resolution: res,
        mscorlib,
        console,
        class,
        ctor_cache: cache,
        default_ctor,
        object,
    };

    let (exceptions, vars, ins) = match test(&mut ctx) {
        MainMethod::Body(ins) => (vec![], vec![], ins),
        MainMethod::WithVariables {
            body: main_body,
            locals,
        } => (vec![], locals, main_body),
        MainMethod::WithExceptions {
            body: main_body,
            locals,
            exceptions,
        } => (exceptions, locals, main_body),
    };

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
    ctx.resolution.set_entry_point(main);

    let written = ctx.resolution.write(WriteOptions {
        is_32_bit: false,
        is_executable: true,
    })?;

    let dir = TempDir::new()?;

    let dll_path = dir.path().join(&dll_name);
    std::fs::write(&dll_path, written)?;

    // introspect installed .NET for available runtimes
    let versions = Command::new(env::DOTNET_SDK.clone())
        .arg("--list-runtimes")
        .output()?
        .stdout;
    let versions = String::from_utf8(versions)?;
    let regex = Regex::new(r"^(?<sdkname>[\w.]+) (?<version>(?<major>\d+\.\d+)\.\d+)")?;
    let Some(caps) = regex.captures(&versions) else {
        panic!("Could not automatically determine installed .NET runtime")
    };

    // substitute first available runtime into our config template
    let template = include_str!("./template.runtimeconfig.json");
    let config = template
        .replace("{{name}}", &caps["sdkname"])
        .replace("{{target}}", &caps["major"])
        .replace("{{version}}", &caps["version"]);
    std::fs::write(dir.path().join(format!("{}.runtimeconfig.json", name)), config)?;

    let output = Command::new(env::DOTNET_SDK.clone()).arg(&dll_path).output()?;

    eprintln!("{}", std::str::from_utf8(&output.stdout)?);

    let stderr = String::from_utf8(output.stderr)?;

    if stderr.contains("Unhandled exception") {
        if let Some(path) = env::optional("ILDASM") {
            Command::new(path).arg(&dll_path).spawn()?.wait()?;
        }

        if let Some(r) = env::optional("RUNTIME") {
            Command::new("gdb")
                .arg("-ex")
                .arg(format!("set substitute-path /runtime {}", r))
                .arg("--args")
                .arg(if let Some(path) = env::optional("ILDASM") {
                    PathBuf::from(path)
                } else {
                    env::LIBRARIES.join("corerun")
                })
                .arg(&dll_path)
                .spawn()?
                .wait()?;
        }

        if let Some(i) = env::optional("ILVERIFY") {
            let ilverify = Command::new(i)
                .arg(&dll_path)
                .arg("-r")
                .arg(env::LIBRARIES.join("*.dll"))
                .output()?;
            println!("{}", String::from_utf8(ilverify.stdout)?);
        }

        if let Some(path) = env::optional("OUTFILE") {
            std::fs::copy(dll_path, path).unwrap();
        }

        panic!("{}", stderr);
    }

    if &output.stdout != expect {
        panic!(
            "--- EXPECTED ---\n{}\n--- ACTUAL ---\n{}\n--- STDERR ---\n{}",
            String::from_utf8(expect.into())?,
            String::from_utf8(output.stdout)?,
            stderr
        );
    }

    Ok(())
}
