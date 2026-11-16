use dotnetdll::{
    binary::{
        cli::RVASize,
        il::Instruction as BinaryInstruction,
        method::{Header, Method as BinaryMethod, SectionKind},
    },
    prelude::*,
    resolved::body::{DataSection, Exception, ExceptionKind},
};
use scroll::Pread;

fn write_body(body: body::Method) -> Vec<u8> {
    let mut res = Resolution::new(Module::new("probe.dll"));
    res.assembly = Some(Assembly::new("probe"));
    let owner = res.push_type_definition(TypeDefinition::new(None, "Subject"));
    res.push_method(
        owner,
        Method::new(Accessibility::Public, msig! { static void () }, "Probe", Some(body)),
    );
    res.write(WriteOptions::default()).unwrap()
}
fn binary_body(bytes: &[u8]) -> BinaryMethod {
    let dll = DLL::parse(bytes).unwrap();
    let (_, _, _, _, logical) = dll.get_all_streams().unwrap();
    let row = logical.tables.method_def.last().unwrap();
    let raw = dll.at_rva(&RVASize { rva: row.rva, size: 1 }).unwrap();
    let start = raw.as_ptr().addr() - bytes.as_ptr().addr();
    bytes.pread(start).unwrap()
}
fn assert_roundtrip(bytes: &[u8], verify: impl Fn(&body::Method)) {
    for lazy in [false, true] {
        let res = Resolution::parse(bytes, ReadOptions::new().with_lazy_method_bodies(lazy)).unwrap();
        let idx = res
            .enumerate_type_definitions()
            .flat_map(|(t, _)| res.enumerate_methods(t))
            .next()
            .unwrap()
            .0;
        verify(res.method_body(idx).unwrap());
        if !lazy {
            let again = res.write(WriteOptions::default()).unwrap();
            let loaded = Resolution::parse(&again, ReadOptions::new()).unwrap();
            verify(loaded.method_body(idx).unwrap());
        }
    }
}

#[test]
fn branch_displacements_at_short_limits() {
    for (n, is_short) in [(126, true), (127, true), (128, false)] {
        let mut instructions = vec![Instruction::Branch(n + 1)];
        instructions.extend((0..n).map(|_| Instruction::NoOperation));
        instructions.push(Instruction::Return);
        let bytes = write_body(body::Method::new(instructions));
        assert_eq!(
            matches!(binary_body(&bytes).body[0], BinaryInstruction::BrS(_)),
            is_short
        );
        assert_roundtrip(&bytes, |m| {
            assert!(matches!(m.instructions[0], Instruction::Branch(t) if t == n + 1))
        });
    }
    for (n, is_short) in [(125, true), (126, true), (127, false)] {
        let mut instructions = vec![Instruction::NoOperation; n];
        instructions.push(Instruction::Branch(0));
        instructions.push(Instruction::Return);
        let bytes = write_body(body::Method::new(instructions));
        assert_eq!(
            matches!(binary_body(&bytes).body[n], BinaryInstruction::BrS(_)),
            is_short
        );
        assert_roundtrip(&bytes, |m| assert!(matches!(m.instructions[n], Instruction::Branch(0))));
    }
}

#[test]
fn relaxation_crosses_branches_switches_and_exception_regions() {
    let mut instructions = vec![Instruction::Branch(125), Instruction::Branch(125)];
    instructions.extend((0..123).map(|_| Instruction::NoOperation));
    instructions.push(Instruction::Return);
    let bytes = write_body(body::Method::new(instructions));
    let binary = binary_body(&bytes);
    assert!(matches!(binary.body[0], BinaryInstruction::BrS(125)));
    assert!(matches!(binary.body[1], BinaryInstruction::BrS(123)));
    assert_roundtrip(&bytes, |m| {
        assert!(matches!(m.instructions[0], Instruction::Branch(125)));
        assert!(matches!(m.instructions[1], Instruction::Branch(125)));
    });

    let mut instructions = vec![
        Instruction::Branch(136),
        Instruction::Switch(vec![0, 3, 135, 136]),
        Instruction::Branch(135),
    ];
    instructions.extend((0..132).map(|_| Instruction::NoOperation));
    instructions.push(Instruction::Leave(136));
    instructions.push(Instruction::Rethrow);
    let mut body = body::Method::new(instructions);
    body.data_sections.push(DataSection::ExceptionHandlers(vec![Exception {
        kind: ExceptionKind::Filter { offset: 3 },
        try_offset: 0,
        try_length: 3,
        handler_offset: 3,
        handler_length: 134,
    }]));
    let bytes = write_body(body);
    assert_roundtrip(&bytes, |m| {
        assert!(matches!(m.instructions[0], Instruction::Branch(136)));
        assert!(matches!(&m.instructions[1], Instruction::Switch(v) if v == &[0, 3, 135, 136]));
        assert!(matches!(m.instructions[2], Instruction::Branch(135)));
        assert!(matches!(m.instructions[135], Instruction::Leave(136)));
        let DataSection::ExceptionHandlers(es) = &m.data_sections[0] else {
            panic!()
        };
        assert!(matches!(es[0].kind, ExceptionKind::Filter { offset: 3 }));
        assert_eq!(
            (
                es[0].try_offset,
                es[0].try_length,
                es[0].handler_offset,
                es[0].handler_length
            ),
            (0, 3, 3, 134)
        );
    });
}

#[test]
fn exception_section_sizes_and_endpoints() {
    for count in [20, 21] {
        let mut instructions = vec![Instruction::LoadNull, Instruction::Throw];
        let mut clauses = vec![];
        for i in 0..count {
            let start = instructions.len();
            instructions.push(Instruction::Pop);
            instructions.push(Instruction::Rethrow);
            clauses.push(Exception {
                kind: if i == 0 {
                    ExceptionKind::Filter { offset: 0 }
                } else {
                    ExceptionKind::Fault
                },
                try_offset: 0,
                try_length: 2,
                handler_offset: start,
                handler_length: 2,
            });
        }
        let mut body = body::Method::new(instructions);
        body.data_sections.push(DataSection::ExceptionHandlers(clauses));
        let bytes = write_body(body);
        let binary = binary_body(&bytes);
        let SectionKind::Exceptions(clauses) = &binary.data_sections[0].section else {
            panic!()
        };
        assert_eq!(clauses.len(), count);
        assert_eq!(
            clauses.last().unwrap().handler_offset + clauses.last().unwrap().handler_length,
            match binary.header {
                Header::Tiny { size } | Header::Fat { size, .. } => size as u32,
            }
        );
        assert_roundtrip(&bytes, |m| {
            let DataSection::ExceptionHandlers(es) = &m.data_sections[0] else {
                panic!()
            };
            assert_eq!(es.len(), count);
            assert!(matches!(es[0].kind, ExceptionKind::Filter { offset: 0 }));
            assert!(matches!(es[count - 1].kind, ExceptionKind::Fault));
            assert_eq!(
                es[count - 1].handler_offset + es[count - 1].handler_length,
                m.instructions.len()
            );
        });
        // The first section byte follows the aligned method body.
        let dll = DLL::parse(&bytes).unwrap();
        let (_, _, _, _, logical) = dll.get_all_streams().unwrap();
        let raw = dll
            .at_rva(&RVASize {
                rva: logical.tables.method_def.last().unwrap().rva,
                size: 1,
            })
            .unwrap();
        let offset = raw.as_ptr().addr() - bytes.as_ptr().addr();
        let mut cursor = offset;
        let header: Header = bytes.gread(&mut cursor).unwrap();
        let size = match header {
            Header::Tiny { size } | Header::Fat { size, .. } => size,
        };
        let section_at = (cursor + size + 3) & !3;
        assert_eq!(bytes[section_at] & 0x40 != 0, count == 21);
    }

    let mut instructions = vec![
        Instruction::LoadNull,
        Instruction::Throw,
        Instruction::Pop,
        Instruction::Rethrow,
    ];
    instructions.extend((0..256).map(|_| Instruction::NoOperation));
    instructions.push(Instruction::Rethrow);
    let mut body = body::Method::new(instructions);
    body.data_sections.push(DataSection::ExceptionHandlers(vec![
        Exception {
            kind: ExceptionKind::Filter { offset: 0 },
            try_offset: 0,
            try_length: 2,
            handler_offset: 2,
            handler_length: 2,
        },
        Exception {
            kind: ExceptionKind::Fault,
            try_offset: 0,
            try_length: 2,
            handler_offset: 4,
            handler_length: 257,
        },
    ]));
    let bytes = write_body(body);
    let binary = binary_body(&bytes);
    let SectionKind::Exceptions(es) = &binary.data_sections[0].section else {
        panic!()
    };
    assert_eq!((es[0].flags, es[1].flags), (1, 4));
    assert_eq!(es[1].handler_length, 258); // 256 nops plus two-byte rethrow
    assert_roundtrip(&bytes, |m| {
        let DataSection::ExceptionHandlers(es) = &m.data_sections[0] else {
            panic!()
        };
        assert_eq!((es[0].handler_length, es[1].handler_length), (2, 257));
        assert_eq!(es[1].handler_offset + es[1].handler_length, m.instructions.len());
    });
}

#[test]
fn malformed_short_exception_length_is_an_error() {
    use dotnetdll::binary::method::DataSection as RawSection;
    for b in [[1, 0, 0, 0], [1, 5, 0, 0]] {
        assert!(b.pread::<RawSection>(0).is_err());
    }
}

#[test]
fn callvirt_null_check_prefix_roundtrips() {
    let mut res = Resolution::new(Module::new("callvirt.dll"));
    res.assembly = Some(Assembly::new("callvirt"));
    let core = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"));
    let object = res.push_type_reference(type_ref! { System.Object in #core });
    let object_type: MethodType = BaseType::class(object).into();
    let to_string = res.push_method_reference(method_ref! { string #object_type::ToString() });
    let owner = res.push_type_definition(TypeDefinition::new(None, "Subject"));
    res.push_method(
        owner,
        Method::new(
            Accessibility::Public,
            msig! { static void () },
            "Probe",
            Some(body::Method::new(vec![
                Instruction::CallVirtual {
                    skip_null_check: true,
                    param0: to_string.into(),
                },
                Instruction::CallVirtual {
                    skip_null_check: false,
                    param0: to_string.into(),
                },
                Instruction::Return,
            ])),
        ),
    );
    let bytes = res.write(WriteOptions::default()).unwrap();
    let raw = binary_body(&bytes);
    assert!(matches!(raw.body[0], BinaryInstruction::NocheckCallvirt(0x04, _)));
    assert!(matches!(raw.body[1], BinaryInstruction::Callvirt(_)));
    assert_roundtrip(&bytes, |m| {
        assert!(matches!(
            m.instructions[0],
            Instruction::CallVirtual {
                skip_null_check: true,
                ..
            }
        ));
        assert!(matches!(
            m.instructions[1],
            Instruction::CallVirtual {
                skip_null_check: false,
                ..
            }
        ));
    });
}

#[test]
fn branch_index_is_not_a_byte_distance() {
    let mut far = vec![Instruction::Branch(121)];
    for _ in 0..60 {
        far.push(Instruction::LoadConstantInt64(1));
        far.push(Instruction::Pop);
    }
    far.push(Instruction::Return);
    let bytes = write_body(body::Method::new(far));
    assert!(matches!(binary_body(&bytes).body[0], BinaryInstruction::Br(_)));
    assert_roundtrip(&bytes, |m| {
        assert!(matches!(m.instructions[0], Instruction::Branch(121)))
    });
    let mut nearby = vec![Instruction::Branch(203)];
    nearby.extend((0..200).map(|_| Instruction::NoOperation));
    nearby.push(Instruction::Branch(200));
    nearby.push(Instruction::NoOperation);
    nearby.push(Instruction::Return);
    let bytes = write_body(body::Method::new(nearby));
    assert!(matches!(binary_body(&bytes).body[201], BinaryInstruction::BrS(_)));
    assert_roundtrip(&bytes, |m| {
        assert!(matches!(m.instructions[0], Instruction::Branch(203)));
        assert!(matches!(m.instructions[201], Instruction::Branch(200)));
    });
}

#[test]
fn typed_exception_handler_ends_after_multibyte_instruction() {
    let mut res = Resolution::new(Module::new("typed.dll"));
    res.assembly = Some(Assembly::new("typed"));
    let core = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"));
    let exception = res.push_type_reference(type_ref! { System.Exception in #core });
    let owner = res.push_type_definition(TypeDefinition::new(None, "Subject"));
    let mut body = body::Method::new(vec![
        Instruction::LoadNull,
        Instruction::Throw,
        Instruction::Pop,
        Instruction::Rethrow,
    ]);
    body.data_sections.push(DataSection::ExceptionHandlers(vec![Exception {
        kind: ExceptionKind::TypedException(BaseType::class(exception).into()),
        try_offset: 0,
        try_length: 2,
        handler_offset: 2,
        handler_length: 2,
    }]));
    res.push_method(
        owner,
        Method::new(Accessibility::Public, msig! { static void () }, "Probe", Some(body)),
    );
    let bytes = res.write(WriteOptions::default()).unwrap();
    assert_roundtrip(&bytes, |m| {
        let DataSection::ExceptionHandlers(es) = &m.data_sections[0] else {
            panic!()
        };
        assert!(matches!(es[0].kind, ExceptionKind::TypedException(_)));
        assert_eq!((es[0].handler_offset, es[0].handler_length), (2, 2));
    });
}

#[test]
fn emitted_exception_sections_execute_on_dotnet_10_when_available() {
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
    for (name, count, long_handler) in [("many", 21, false), ("mixed", 2, true)] {
        let mut res = Resolution::new(Module::new(format!("{name}.dll")));
        res.assembly = Some(Assembly::new(name));
        let core = res.push_assembly_reference(ExternalAssemblyReference::new("System.Private.CoreLib"));
        let object = res.push_type_reference(type_ref! { System.Object in #core });
        let exception = res.push_type_reference(type_ref! { System.Exception in #core });
        let exception_type: MethodType = BaseType::class(exception).into();
        let ctor = res.push_method_reference(method_ref! { void @exception_type::.ctor() });
        let owner = res.push_type_definition(TypeDefinition::new(None, "Subject"));
        res[owner].set_extends(object);
        let mut instrs = vec![Instruction::NewObject(ctor.into()), Instruction::Throw];
        let mut clauses = vec![];
        for i in 0..count {
            let start = instrs.len();
            if long_handler && i == 1 {
                instrs.extend((0..256).map(|_| Instruction::NoOperation));
            }
            instrs.push(Instruction::Pop);
            instrs.push(Instruction::Leave(0));
            clauses.push(Exception {
                kind: ExceptionKind::TypedException(exception_type.clone()),
                try_offset: 0,
                try_length: 2,
                handler_offset: start,
                handler_length: instrs.len() - start,
            });
        }
        let after = instrs.len();
        for ins in &mut instrs {
            if let Instruction::Leave(target) = ins {
                *target = after;
            }
        }
        instrs.push(Instruction::LoadConstantInt32(42));
        instrs.push(Instruction::Return);
        let mut body = body::Method::new(instrs);
        body.data_sections.push(DataSection::ExceptionHandlers(clauses));
        let main = res.push_method(
            owner,
            Method::new(Accessibility::Public, msig! { static int () }, "Main", Some(body)),
        );
        res.set_entry_point(main);
        let bytes = res
            .write(WriteOptions {
                is_32_bit: false,
                is_executable: true,
            })
            .unwrap();
        assert_roundtrip(&bytes, |m| {
            let DataSection::ExceptionHandlers(es) = &m.data_sections[0] else {
                panic!()
            };
            assert_eq!(es.len(), count);
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{name}.dll"));
        std::fs::write(&path, bytes).unwrap();
        std::fs::write(
            dir.path().join(format!("{name}.runtimeconfig.json")),
            r#"{"runtimeOptions":{"tfm":"net10.0","framework":{"name":"Microsoft.NETCore.App","version":"10.0.0"}}}"#,
        )
        .unwrap();
        let output = Command::new("dotnet").arg(path).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(42),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn standalone_binary_exception_uses_fat_layout() {
    use dotnetdll::binary::method::Exception as RawException;
    use scroll::Pwrite;
    let clause = RawException {
        flags: 4,
        try_offset: 0,
        try_length: 2,
        handler_offset: 2,
        handler_length: 3,
        class_token_or_filter: 0,
    };
    let mut buf = scroll_buffer::DynamicBuffer::new();
    assert_eq!(buf.pwrite(clause, 0).unwrap(), 24);
    let decoded: RawException = buf.get().pread(0).unwrap();
    assert_eq!(
        (
            decoded.flags,
            decoded.try_offset,
            decoded.try_length,
            decoded.handler_offset,
            decoded.handler_length
        ),
        (4, 0, 2, 2, 3)
    );
}
