//! Range, error, and option-precedence checks without a .NET SDK dependency.
use dotnetdll::{
    binary::{cli::RVASize, heap::Reader},
    dll::{DLLError, ParseError, ResolveError},
    prelude::*,
};
use object::read::pe::PeFile64;
use scroll::Pwrite;
use scroll_buffer::DynamicBuffer;

fn fixture(is_32_bit: bool) -> Vec<u8> {
    let mut r = Resolution::new(Module::new("deferred-bodies.dll"));
    let subject = r.push_type_definition(TypeDefinition::new(None, "Subject"));
    r.push_method(
        subject,
        Method::new(
            Accessibility::Public,
            msig! { static void () },
            "Tiny",
            Some(body::Method::new(asm! { Return; })),
        ),
    );
    let mut fat = body::Method::new(asm! { LoadArgument 0; Return; });
    fat.header.maximum_stack_size = 16;
    r.push_method(
        subject,
        Method::new(Accessibility::Public, msig! { static int (int) }, "Fat", Some(fat)),
    );
    let mut abstract_method = Method::new(Accessibility::Public, msig! { void () }, "Abstract", None);
    abstract_method.abstract_member = true;
    abstract_method.virtual_member = true;
    r.push_method(subject, abstract_method);
    r.write(WriteOptions {
        is_32_bit,
        ..Default::default()
    })
    .unwrap()
}

fn method_index(r: &Resolution<'_>, name: &str) -> MethodIndex {
    r.enumerate_type_definitions()
        .flat_map(|(ti, _)| r.enumerate_methods(ti))
        .find(|(_, m)| m.name == name)
        .unwrap()
        .0
}

fn method_location(bytes: &[u8], name: &str) -> (u32, usize) {
    let dll = DLL::parse(bytes).unwrap();
    let (strings, _, _, _, logical) = dll.get_all_streams().unwrap();
    let rva = logical
        .tables
        .method_def
        .iter()
        .find(|m| strings.at_index(m.name).unwrap() == name)
        .unwrap()
        .rva;
    let body = dll.at_rva(&RVASize { rva, size: 1 }).unwrap();
    (rva, body.as_ptr().addr() - bytes.as_ptr().addr())
}

/// Rewrite the table stream at the same location so all other RVAs remain valid.
fn set_method_rva(bytes: &mut [u8], name: &str, rva: u32) {
    let dll = DLL::parse(bytes).unwrap();
    let stream = dll
        .get_cli_metadata()
        .unwrap()
        .stream_headers
        .into_iter()
        .find(|s| s.name == "#~")
        .unwrap();
    let raw = dll
        .at_rva(&RVASize {
            rva: dll.cli.metadata.rva + stream.offset,
            size: stream.size,
        })
        .unwrap();
    let start = raw.as_ptr().addr() - bytes.as_ptr().addr();
    let (strings, _, _, _, mut logical) = dll.get_all_streams().unwrap();
    logical
        .tables
        .method_def
        .iter_mut()
        .find(|m| strings.at_index(m.name).unwrap() == name)
        .unwrap()
        .rva = rva;
    let mut encoded = DynamicBuffer::with_increment(32);
    let size = encoded.pwrite(logical, 0).unwrap();
    assert_eq!(size, stream.size as usize);
    bytes[start..start + size].copy_from_slice(encoded.get());
}

fn assert_deferred_decode_error(bytes: &[u8], name: &str) {
    for own in [false, true] {
        let opts = ReadOptions::new().with_own_heap_values(own);
        assert!(matches!(Resolution::parse(bytes, opts), Err(DLLError::Decode(_))));
        let original = Resolution::parse(bytes, opts.with_lazy_method_bodies(true)).unwrap();
        let idx = method_index(&original, name);
        let cloned = original.clone();
        drop(original);
        let first = cloned.method_body(idx).unwrap_err();
        assert!(matches!(first, DLLError::Decode(_)));
        // A failed decode must remain an error on subsequent calls, including another clone.
        assert_eq!(first.to_string(), cloned.method_body(idx).unwrap_err().to_string());
        assert_eq!(
            first.to_string(),
            cloned.clone().method_body(idx).unwrap_err().to_string()
        );
    }
}

#[test]
fn cold_clones_decode_tiny_and_fat_bodies_and_share_the_cache() {
    for is_32_bit in [false, true] {
        let bytes = fixture(is_32_bit);
        let eager = Resolution::parse(&bytes, ReadOptions::new()).unwrap();
        for own in [false, true] {
            let original = Resolution::parse(
                &bytes,
                ReadOptions::new()
                    .with_lazy_method_bodies(true)
                    .with_lazy_method_signatures(true)
                    .with_own_heap_values(own),
            )
            .unwrap();
            let cloned = original.clone();
            drop(original);
            let sibling = cloned.clone();
            for name in ["Tiny", "Fat"] {
                let idx = method_index(&cloned, name);
                assert!(cloned[idx].body.is_none());
                let body = cloned.method_body(idx).unwrap();
                assert_eq!(format!("{body:?}"), format!("{:?}", eager.method_body(idx).unwrap()));
                assert!(std::ptr::eq(body, sibling.method_body(idx).unwrap()));
            }
            assert!(matches!(
                cloned.method_body(method_index(&cloned, "Abstract")),
                Err(DLLError::Resolve(ResolveError::LazyLookupFailed(_)))
            ));
        }
    }
}

#[test]
fn deferred_bodies_preserve_alignment_padding() {
    for is_32_bit in [false, true] {
        let original = fixture(is_32_bit);
        let expected = Resolution::parse(&original, ReadOptions::new()).unwrap();
        let mut bytes = original.clone();
        let idx = method_index(&expected, "Fat");
        let (rva, start) = method_location(&bytes, "Fat");
        assert_eq!(rva % 4, 0);
        assert_eq!(bytes[start - 1], 0, "fixture has padding before its fat header");
        set_method_rva(&mut bytes, "Fat", rva - 1);
        for lazy in [false, true] {
            let parsed = Resolution::parse(&bytes, ReadOptions::new().with_lazy_method_bodies(lazy)).unwrap();
            assert_eq!(
                format!("{:?}", parsed.method_body(idx).unwrap()),
                format!("{:?}", expected.method_body(idx).unwrap())
            );
        }
    }
}

#[test]
fn malformed_il_is_deferred_and_retried() {
    let mut bytes = fixture(false);
    let (_, start) = method_location(&bytes, "Tiny");
    bytes[start + 1] = 0xff; // No CIL instruction has this opcode.
    assert_deferred_decode_error(&bytes, "Tiny");
}

#[test]
fn truncated_instruction_and_body_are_deferred_and_retried() {
    let mut bytes = fixture(false);
    let (_, start) = method_location(&bytes, "Tiny");
    bytes[start] = (1 << 2) | 2; // Tiny header declaring exactly one IL byte.
    bytes[start + 1] = 0x28; // call requires a four-byte operand outside that body.
    assert_deferred_decode_error(&bytes, "Tiny");

    let mut bytes = fixture(false);
    let (_, start) = method_location(&bytes, "Fat");
    bytes[start + 4..start + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_deferred_decode_error(&bytes, "Fat");
}

#[test]
fn invalid_body_rvas_fail_during_parse() {
    let bytes = fixture(false);
    let (rva, _) = method_location(&bytes, "Tiny");
    let (_, remaining) = PeFile64::parse(bytes.as_slice())
        .unwrap()
        .section_table()
        .pe_file_range_at(rva)
        .unwrap();
    for bad_rva in [rva + remaining, u32::MAX] {
        let mut bytes = bytes.clone();
        set_method_rva(&mut bytes, "Tiny", bad_rva);
        for lazy in [false, true] {
            assert!(matches!(
                Resolution::parse(&bytes, ReadOptions::new().with_lazy_method_bodies(lazy)),
                Err(DLLError::Parse(ParseError::BadStructure("bad stream offset")))
            ));
        }
    }
}

#[test]
fn skipping_bodies_overrides_lazy_bodies_without_disabling_other_lazy_options() {
    let bytes = fixture(false);
    let expected = Resolution::parse(&bytes, ReadOptions::new()).unwrap();
    let mut invalid_rva = bytes.clone();
    set_method_rva(&mut invalid_rva, "Tiny", u32::MAX);
    for bytes in [&bytes, &invalid_rva] {
        for own in [false, true] {
            for lazy_bodies in [false, true] {
                for other_lazy in [false, true] {
                    let parsed = Resolution::parse(
                        bytes,
                        ReadOptions::new()
                            .with_skip_method_bodies(true)
                            .with_lazy_method_bodies(lazy_bodies)
                            .with_lazy_method_signatures(other_lazy)
                            .with_lazy_property_signatures(other_lazy)
                            .with_lazy_attributes(other_lazy)
                            .with_own_heap_values(own),
                    )
                    .unwrap();
                    for name in ["Tiny", "Fat", "Abstract"] {
                        let idx = method_index(&parsed, name);
                        assert!(parsed[idx].body.is_none());
                        assert!(parsed.method_body(idx).is_err());
                        assert_eq!(
                            parsed.method_signature(idx).unwrap(),
                            expected.method_signature(idx).unwrap()
                        );
                    }
                }
            }
        }
    }
}
