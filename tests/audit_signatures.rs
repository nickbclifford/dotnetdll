use dotnetdll::{
    binary::signature::{
        encoded::{Param, ParamType, RetType, RetTypeType, Type},
        kinds::{
            CallingConvention, MethodDefSig, MethodRefSig, StandAloneCallingConvention as Conv, StandAloneMethodSig,
        },
    },
    prelude::*,
};
use scroll::{Pread, Pwrite};
use scroll_buffer::DynamicBuffer;

fn int() -> Param {
    Param(vec![], ParamType::Type(Type::Int32))
}
fn stand(conv: Conv, extra: bool) -> StandAloneMethodSig {
    StandAloneMethodSig {
        has_this: false,
        explicit_this: false,
        calling_convention: conv,
        ret_type: RetType(vec![], RetTypeType::Void),
        params: vec![int()],
        varargs: if extra { vec![int()] } else { vec![] },
    }
}
fn reference(conv: CallingConvention, extra: bool) -> MethodRefSig {
    MethodRefSig {
        method_def: MethodDefSig {
            has_this: false,
            explicit_this: false,
            calling_convention: conv,
            ret_type: RetType(vec![], RetTypeType::Void),
            params: vec![int()],
        },
        varargs: if extra { vec![int()] } else { vec![] },
    }
}
#[test]
fn signatures_encode_sentinels_and_reject_bad_tails() {
    for (conv, tag) in [(Conv::Cdecl, 1), (Conv::Vararg, 5)] {
        for extra in [false, true] {
            let expected = if extra {
                vec![tag, 2, 1, 8, 0x41, 8]
            } else {
                vec![tag, 1, 1, 8]
            };
            let mut bytes = [0; 64];
            let len = bytes.pwrite(stand(conv, extra), 0).unwrap();
            assert_eq!(&bytes[..len], expected);
            let parsed: StandAloneMethodSig = bytes[..len].pread(0).unwrap();
            assert_eq!((parsed.params.len(), parsed.varargs.len()), (1, usize::from(extra)));
            let mut dynbuf = DynamicBuffer::new();
            let written = dynbuf.pwrite(stand(conv, extra), 0).unwrap();
            assert_eq!(&dynbuf.get()[..written], expected);
        }
    }
    for extra in [false, true] {
        let expected = if extra {
            vec![5, 2, 1, 8, 0x41, 8]
        } else {
            vec![5, 1, 1, 8]
        };
        let mut bytes = [0; 64];
        let len = bytes.pwrite(reference(CallingConvention::Vararg, extra), 0).unwrap();
        assert_eq!(&bytes[..len], expected);
        let parsed: MethodRefSig = bytes[..len].pread(0).unwrap();
        assert_eq!(
            (parsed.method_def.params.len(), parsed.varargs.len()),
            (1, usize::from(extra))
        );
        let mut dynbuf = DynamicBuffer::new();
        let n = dynbuf.pwrite(reference(CallingConvention::Vararg, extra), 0).unwrap();
        assert_eq!(&dynbuf.get()[..n], expected);
    }
    for conv in [
        Conv::DefaultManaged,
        Conv::Stdcall,
        Conv::Thiscall,
        Conv::Fastcall,
        Conv::DefaultUnmanaged,
    ] {
        assert!([0u8; 64].pwrite(stand(conv, true), 0).is_err());
        assert!(DynamicBuffer::new().pwrite(stand(conv, true), 0).is_err());
        let tag = match conv {
            Conv::DefaultManaged => 0,
            Conv::Stdcall => 2,
            Conv::Thiscall => 3,
            Conv::Fastcall => 4,
            Conv::DefaultUnmanaged => 9,
            _ => unreachable!(),
        };
        assert!([tag, 2, 1, 8, 0x41, 8].pread::<StandAloneMethodSig>(0).is_err());
    }
    for conv in [CallingConvention::Default, CallingConvention::Generic(1)] {
        assert!([0u8; 64].pwrite(reference(conv, true), 0).is_err());
        assert!(DynamicBuffer::new().pwrite(reference(conv, true), 0).is_err());
    }
    assert!([0, 2, 1, 8, 0x41, 8].pread::<MethodRefSig>(0).is_err());
}

#[test]
fn truncated_signatures_return_errors() {
    for bytes in [
        &[1, 2, 1, 8, 0x41, 8][..],
        &[5, 2, 1, 8, 0x41, 8][..],
        &[1, 2, 1, 8, 0x41, 0x0f, 8][..],
    ] {
        for n in 0..bytes.len() {
            assert!(
                bytes[..n].pread::<StandAloneMethodSig>(0).is_err(),
                "{bytes:02x?} at {n}"
            );
        }
    }
    // A large compressed parameter count with no payload must fail without
    // reserving memory in proportion to the untrusted count.
    for tail in [
        &[1, 0xdf, 0xff, 0xff, 0xff, 1][..],
        &[1, 0xdf, 0xff, 0xff, 0xff, 1, 0x41][..],
    ] {
        assert!(tail.pread::<StandAloneMethodSig>(0).is_err());
    }
    let bytes = [5, 2, 1, 8, 0x41, 8];
    for n in 0..bytes.len() {
        assert!(bytes[..n].pread::<MethodRefSig>(0).is_err());
    }
}

#[test]
fn nested_function_pointers_and_calli_keep_varargs() {
    for conv in [Conv::Vararg, Conv::Cdecl] {
        for extra in [false, true] {
            let mut res = Resolution::new(Module::new("fnptr.dll"));
            res.assembly = Some(Assembly::new("fnptr"));
            let owner = res.push_type_definition(TypeDefinition::new(None, "Subject"));
            let int: MethodType = BaseType::Int32.into();
            let sig = MethodSignature {
                instance: false,
                explicit_this: false,
                calling_convention: conv,
                parameters: vec![Parameter::value(int.clone())],
                return_type: ReturnType::VOID,
                varargs: Some(if extra { vec![Parameter::value(int)] } else { vec![] }),
            };
            let mut method_sig = msig! { static void () };
            method_sig
                .parameters
                .push(Parameter::value(BaseType::FunctionPointer(sig.clone()).into()));
            res.push_method(
                owner,
                Method::new(
                    Accessibility::Public,
                    method_sig,
                    "Probe",
                    Some(body::Method::new(vec![
                        Instruction::CallIndirect {
                            tail_call: false,
                            param0: sig.clone(),
                        },
                        Instruction::Return,
                    ])),
                ),
            );
            let bytes = res.write(WriteOptions::default()).unwrap();
            for lazy in [false, true] {
                let loaded = Resolution::parse(&bytes, ReadOptions::new().with_lazy_method_bodies(lazy)).unwrap();
                let method = &loaded[owner].methods[0];
                assert_eq!(
                    method.signature.parameters[0],
                    Parameter::value(BaseType::FunctionPointer(sig.clone()).into())
                );
                let method_idx = loaded.enumerate_methods(owner).next().unwrap().0;
                assert!(
                    matches!(&loaded.method_body(method_idx).unwrap().instructions[0], Instruction::CallIndirect { param0, .. } if *param0 == sig)
                );
            }
        }
    }
}

#[test]
fn managed_method_reference_varargs_roundtrip_eager_and_lazy() {
    for extra in [false, true] {
        let mut res = Resolution::new(Module::new("refs.dll"));
        res.assembly = Some(Assembly::new("refs"));
        let core = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"));
        let object = res.push_type_reference(type_ref! { System.Object in #core });
        let object_type: MethodType = BaseType::class(object).into();
        let idx = res.push_method_reference(method_ref! { static void #object_type::Probe(int) });
        let int: MethodType = BaseType::Int32.into();
        res[idx].signature.calling_convention = CallingConvention::Vararg;
        res[idx].signature.varargs = Some(if extra { vec![Parameter::value(int)] } else { vec![] });
        let expected = res[idx].signature.clone();
        let bytes = res.write(WriteOptions::default()).unwrap();
        for lazy in [false, true] {
            let parsed = Resolution::parse(&bytes, ReadOptions::new().with_lazy_method_signatures(lazy)).unwrap();
            assert_eq!(*parsed.method_ref_signature(idx).unwrap(), expected);
            if !lazy {
                let rewritten = parsed.write(WriteOptions::default()).unwrap();
                let parsed_again = Resolution::parse(&rewritten, ReadOptions::new()).unwrap();
                assert_eq!(*parsed_again.method_ref_signature(idx).unwrap(), expected);
            }
        }
        res[idx].signature.calling_convention = CallingConvention::Default;
        if extra {
            assert!(res.write(WriteOptions::default()).is_err());
        }
    }
}
