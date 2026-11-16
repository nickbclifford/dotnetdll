use dotnetdll::{
    binary::{cli::RVASize, heap::Reader, il::Instruction as BinaryInstruction, method::Header},
    prelude::*,
};
use scroll::Pread;

fn fixture() -> Vec<u8> {
    let mut res = Resolution::new(Module::new("constrained-tail.dll"));
    res.assembly = Some(Assembly::new("constrained-tail"));
    let core = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"));
    let object = res.push_type_reference(type_ref! { System.Object in #core });
    let console = res.push_type_reference(type_ref! { System.Console in #core });
    let object_type: MethodType = BaseType::class(object).into();
    let console_type: MethodType = BaseType::class(console).into();
    let to_string = res.push_method_reference(method_ref! { string #object_type::ToString() });
    let write_line = res.push_method_reference(method_ref! { static void #console_type::WriteLine(string) });
    let subject = res.push_type_definition(TypeDefinition::new(None, "Subject"));
    res[subject].set_extends(object);
    let field = res.push_field(
        subject,
        Field::static_member(Accessibility::Public, "Value", ctype! { int }),
    );
    let int: MethodType = BaseType::Int32.into();

    let probe = res.push_method(
        subject,
        Method::new(
            Accessibility::Public,
            msig! { static string () },
            "Probe",
            Some(body::Method::new(vec![
                Instruction::LoadStaticFieldAddress(field.into()),
                Instruction::CallVirtualConstrainedTail(int.clone(), to_string.into()),
                Instruction::Return,
            ])),
        ),
    );
    for (name, instruction) in [
        (
            "Constrained",
            Instruction::CallVirtualConstrained(int.clone(), to_string.into()),
        ),
        ("Tail", Instruction::CallVirtualTail(to_string.into())),
    ] {
        res.push_method(
            subject,
            Method::new(
                Accessibility::Public,
                msig! { static string () },
                name,
                Some(body::Method::new(vec![
                    Instruction::LoadStaticFieldAddress(field.into()),
                    instruction,
                    Instruction::Return,
                ])),
            ),
        );
    }
    // Both branches cross the combined instruction; another targets its first prefix.
    res.push_method(
        subject,
        Method::new(
            Accessibility::Public,
            msig! { static void () },
            "Branches",
            Some(body::Method::new(vec![
                Instruction::Branch(4),
                Instruction::Branch(3),
                Instruction::LoadStaticFieldAddress(field.into()),
                Instruction::CallVirtualConstrainedTail(int, to_string.into()),
                Instruction::Return,
                Instruction::Branch(1),
            ])),
        ),
    );
    let main = res.push_method(
        subject,
        Method::new(
            Accessibility::Public,
            msig! { static void () },
            "Main",
            Some(body::Method::new(vec![
                Instruction::LoadConstantInt32(42),
                Instruction::store_static_field(field),
                Instruction::call(probe),
                Instruction::call(write_line),
                Instruction::Return,
            ])),
        ),
    );
    res.set_entry_point(main);
    res.write(WriteOptions {
        is_32_bit: false,
        is_executable: true,
    })
    .unwrap()
}

fn method_il_range(bytes: &[u8], name: &str) -> std::ops::Range<usize> {
    let dll = DLL::parse(bytes).unwrap();
    let (strings, _, _, _, logical) = dll.get_all_streams().unwrap();
    let row = logical
        .tables
        .method_def
        .iter()
        .find(|m| strings.at_index(m.name).unwrap() == name)
        .unwrap();
    let raw = dll.at_rva(&RVASize { rva: row.rva, size: 1 }).unwrap();
    let start = raw.as_ptr().addr() - bytes.as_ptr().addr();
    let mut offset = start;
    let header: Header = bytes.gread(&mut offset).unwrap();
    let size = match header {
        Header::Tiny { size } | Header::Fat { size, .. } => size,
    };
    offset..offset + size
}

fn instructions<'a>(res: &'a Resolution<'_>, name: &str) -> &'a [Instruction] {
    let idx = res
        .enumerate_type_definitions()
        .flat_map(|(t, _)| res.enumerate_methods(t))
        .find(|(_, m)| m.name == name)
        .unwrap()
        .0;
    &res.method_body(idx).unwrap().instructions
}

fn assert_resolved(bytes: &[u8]) {
    for lazy in [false, true] {
        let res = Resolution::parse(bytes, ReadOptions::new().with_lazy_method_bodies(lazy)).unwrap();
        assert!(
            matches!(&instructions(&res, "Probe")[1], Instruction::CallVirtualConstrainedTail(t, _) if *t == BaseType::Int32.into())
        );
        assert!(
            matches!(&instructions(&res, "Constrained")[1], Instruction::CallVirtualConstrained(t, _) if *t == BaseType::Int32.into())
        );
        assert!(matches!(
            &instructions(&res, "Tail")[1],
            Instruction::CallVirtualTail(_)
        ));
        let Instruction::CallVirtualConstrainedTail(_, combined_method) = &instructions(&res, "Probe")[1] else {
            unreachable!()
        };
        let Instruction::CallVirtualConstrained(_, constrained_method) = &instructions(&res, "Constrained")[1] else {
            unreachable!()
        };
        let Instruction::CallVirtualTail(tail_method) = &instructions(&res, "Tail")[1] else {
            unreachable!()
        };
        assert_eq!(combined_method, constrained_method);
        assert_eq!(combined_method, tail_method);
        let body = instructions(&res, "Branches");
        assert!(matches!(body[0], Instruction::Branch(4)));
        assert!(matches!(body[1], Instruction::Branch(3)));
        assert!(matches!(body[3], Instruction::CallVirtualConstrainedTail(_, _)));
        assert!(matches!(body[5], Instruction::Branch(1)));
    }
}

#[test]
fn reads_and_writes_prefixes_and_branch_offsets() {
    let bytes = fixture();
    assert_resolved(&bytes);
    for (name, is_constrained) in [("Constrained", true), ("Tail", false)] {
        let code = &bytes[method_il_range(&bytes, name)];
        let mut offset = 0;
        let _: BinaryInstruction = code.gread(&mut offset).unwrap();
        let ins: BinaryInstruction = code.gread(&mut offset).unwrap();
        if is_constrained {
            assert!(matches!(ins, BinaryInstruction::ConstrainedCallvirt(_, _)));
        } else {
            assert!(matches!(ins, BinaryInstruction::TailCallvirt(_)));
        }
    }
    let code = &bytes[method_il_range(&bytes, "Branches")];
    let mut offset = 0;
    let mut decoded = Vec::new();
    while offset < code.len() {
        let start = offset;
        let ins: BinaryInstruction = code.gread(&mut offset).unwrap();
        assert_eq!(offset - start, ins.bytesize());
        decoded.push((start, offset, ins));
    }
    assert_eq!(decoded[3].1 - decoded[3].0, 13);
    assert!(matches!(decoded[3].2, BinaryInstruction::ConstrainedTailCallvirt(_, _)));
    for (branch, target) in [(0, 4), (1, 3), (5, 1)] {
        let displacement = match decoded[branch].2 {
            BinaryInstruction::Br(d) => d as isize,
            BinaryInstruction::BrS(d) => d as isize,
            ref other => panic!("unexpected branch {other:?}"),
        };
        assert_eq!((decoded[branch].1 as isize + displacement) as usize, decoded[target].0);
    }

    // Change both combined calls to the other legal prefix order, without changing lengths.
    let mut reversed = bytes.clone();
    for name in ["Probe", "Branches"] {
        let range = method_il_range(&reversed, name);
        let code = &mut reversed[range];
        let at = code.windows(2).position(|w| w == [0xfe, 0x16]).unwrap();
        assert_eq!(&code[at + 6..at + 8], &[0xfe, 0x14]);
        let constrained: [u8; 6] = code[at..at + 6].try_into().unwrap();
        code[at..at + 2].copy_from_slice(&[0xfe, 0x14]);
        code[at + 2..at + 8].copy_from_slice(&constrained);
    }
    assert_resolved(&reversed);
    let parsed = Resolution::parse(&reversed, ReadOptions::new()).unwrap();
    let rewritten = parsed
        .write(WriteOptions {
            is_32_bit: false,
            is_executable: true,
        })
        .unwrap();
    assert_resolved(&rewritten);
    let code = &rewritten[method_il_range(&rewritten, "Probe")];
    assert!(code.windows(2).any(|w| w == [0xfe, 0x16]));
}

#[test]
fn combined_prefix_executes_on_dotnet_10_when_available() {
    use std::process::Command;
    let Ok(runtimes) = Command::new("dotnet").arg("--list-runtimes").output() else {
        return;
    };
    if !String::from_utf8_lossy(&runtimes.stdout)
        .lines()
        .any(|s| s.starts_with("Microsoft.NETCore.App 10."))
    {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dll = dir.path().join("constrained-tail.dll");
    std::fs::write(&dll, fixture()).unwrap();
    std::fs::write(
        dir.path().join("constrained-tail.runtimeconfig.json"),
        r#"{"runtimeOptions":{"tfm":"net10.0","framework":{"name":"Microsoft.NETCore.App","version":"10.0.0"}}}"#,
    )
    .unwrap();
    let result = Command::new("dotnet").arg(dll).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(result.stdout, b"42\n");
}

fn static_fixture() -> Vec<u8> {
    use dotnetdll::resolved::types::{ExternalTypeReference, ResolutionScope};
    let mut res = Resolution::new(Module::new("static-tail.dll"));
    res.assembly = Some(Assembly::new("static-tail"));
    let support = res.push_assembly_reference(ExternalAssemblyReference::new("Support"));
    let core = res.push_assembly_reference(ExternalAssemblyReference::new("System.Private.CoreLib"));
    let object = res.push_type_reference(type_ref! { System.Object in #core });
    let iface = res.push_type_reference(ExternalTypeReference::new(
        None,
        "IValue",
        ResolutionScope::Assembly(support),
    ));
    let value = res.push_type_reference(ExternalTypeReference::new(
        None,
        "Value",
        ResolutionScope::Assembly(support),
    ));
    let iface_type: MethodType = BaseType::class(iface).into();
    let get = res.push_method_reference(method_ref! { static int #iface_type::Get() });
    let owner = res.push_type_definition(TypeDefinition::new(None, "Subject"));
    res[owner].set_extends(object);
    let constraint: MethodType = BaseType::valuetype(value).into();
    let main = res.push_method(
        owner,
        Method::new(
            Accessibility::Public,
            msig! { static int () },
            "Main",
            Some(body::Method::new(vec![
                Instruction::CallConstrainedTail(constraint.clone(), get.into()),
                Instruction::Return,
            ])),
        ),
    );
    res.push_method(
        owner,
        Method::new(
            Accessibility::Public,
            msig! { static void () },
            "Branches",
            Some(body::Method::new(vec![
                Instruction::Branch(3),
                Instruction::Branch(2),
                Instruction::CallConstrainedTail(constraint.clone(), get.into()),
                Instruction::Return,
                Instruction::Branch(1),
            ])),
        ),
    );
    res.push_method(
        owner,
        Method::new(
            Accessibility::Public,
            msig! { static int () },
            "Constrained",
            Some(body::Method::new(vec![
                Instruction::CallConstrained(constraint, get.into()),
                Instruction::Return,
            ])),
        ),
    );
    res.set_entry_point(main);
    res.write(WriteOptions {
        is_32_bit: false,
        is_executable: true,
    })
    .unwrap()
}

#[test]
fn static_constrained_tail_binary_and_resolved_roundtrips() {
    use scroll::Pwrite;
    use scroll_buffer::DynamicBuffer;
    let bytes = static_fixture();
    let check = |bytes: &[u8]| {
        for lazy in [false, true] {
            let res = Resolution::parse(bytes, ReadOptions::new().with_lazy_method_bodies(lazy)).unwrap();
            assert!(matches!(
                instructions(&res, "Main")[0],
                Instruction::CallConstrainedTail(_, _)
            ));
            assert!(matches!(
                instructions(&res, "Constrained")[0],
                Instruction::CallConstrained(_, _)
            ));
            let b = instructions(&res, "Branches");
            assert!(matches!(b[0], Instruction::Branch(3)));
            assert!(matches!(b[1], Instruction::Branch(2)));
            assert!(matches!(b[2], Instruction::CallConstrainedTail(_, _)));
            assert!(matches!(b[4], Instruction::Branch(1)));
        }
    };
    check(&bytes);
    let mut reversed = bytes.clone();
    for name in ["Main", "Branches"] {
        let range = method_il_range(&reversed, name);
        let code = &mut reversed[range];
        let at = code.windows(2).position(|w| w == [0xfe, 0x16]).unwrap();
        let (decoded, len) = <BinaryInstruction as scroll::ctx::TryFromCtx>::try_from_ctx(&code[at..], ()).unwrap();
        assert!(matches!(decoded, BinaryInstruction::ConstrainedTailCall(_, _)));
        assert_eq!(decoded.bytesize(), 13);
        let mut output = DynamicBuffer::new();
        output.pwrite(decoded, 0).unwrap();
        assert_eq!(output.get(), &code[at..at + len]);
        assert_eq!(&code[at + 6..at + 8], &[0xfe, 0x14]);
        let prefix: [u8; 6] = code[at..at + 6].try_into().unwrap();
        code[at..at + 2].copy_from_slice(&[0xfe, 0x14]);
        code[at + 2..at + 8].copy_from_slice(&prefix);
        let (decoded, len) = <BinaryInstruction as scroll::ctx::TryFromCtx>::try_from_ctx(&code[at..], ()).unwrap();
        assert!(matches!(decoded, BinaryInstruction::TailConstrainedCall(_, _)));
        let mut output = DynamicBuffer::new();
        output.pwrite(decoded, 0).unwrap();
        assert_eq!(output.get(), &code[at..at + len]);
    }
    check(&reversed);
    let res = Resolution::parse(&reversed, ReadOptions::new()).unwrap();
    let rewritten = res
        .write(WriteOptions {
            is_32_bit: false,
            is_executable: true,
        })
        .unwrap();
    check(&rewritten);
}

#[test]
fn serialized_static_constrained_tail_executes_on_dotnet_10_when_available() {
    use std::process::Command;
    let Ok(sdks) = Command::new("dotnet").arg("--list-sdks").output() else {
        return;
    };
    if !String::from_utf8_lossy(&sdks.stdout)
        .lines()
        .any(|s| s.starts_with("10."))
    {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Support.csproj"), r#"<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><NuGetAudit>false</NuGetAudit></PropertyGroup></Project>"#).unwrap();
    std::fs::write(dir.path().join("Support.cs"), "public interface IValue { static abstract int Get(); } public struct Value : IValue { public static int Get() => 42; }").unwrap();
    let build = Command::new("dotnet")
        .args([
            "build",
            "Support.csproj",
            "--nologo",
            "--verbosity",
            "quiet",
            "--ignore-failed-sources",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let out = dir.path().join("bin/Debug/net10.0");
    std::fs::write(out.join("static-tail.dll"), static_fixture()).unwrap();
    std::fs::write(
        out.join("static-tail.runtimeconfig.json"),
        r#"{"runtimeOptions":{"tfm":"net10.0","framework":{"name":"Microsoft.NETCore.App","version":"10.0.0"}}}"#,
    )
    .unwrap();
    let result = Command::new("dotnet")
        .arg(out.join("static-tail.dll"))
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
