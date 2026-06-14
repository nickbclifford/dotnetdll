use dotnetdll::{dll::DLLError, prelude::*};

mod common;

static OOP_DLL: &[u8] = include_bytes!("../examples/smolasm/oop.dll");

fn debug_digest<T: std::fmt::Debug>(value: &T) -> (u64, usize) {
    use std::fmt::Write;
    use std::hash::Hasher;

    struct DigestWriter {
        hasher: std::collections::hash_map::DefaultHasher,
        len: usize,
    }

    impl std::fmt::Write for DigestWriter {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.hasher.write(s.as_bytes());
            self.len += s.len();
            Ok(())
        }
    }

    let mut writer = DigestWriter {
        hasher: std::collections::hash_map::DefaultHasher::new(),
        len: 0,
    };
    write!(&mut writer, "{value:?}").expect("formatting debug output failed");
    (writer.hasher.finish(), writer.len)
}

fn assert_debug_eq<T: std::fmt::Debug>(field_name: &str, expected: &T, actual: &T) {
    assert_eq!(debug_digest(expected), debug_digest(actual), "{field_name} mismatch");
}

fn assert_resolution_public_fields_eq(expected: &Resolution<'_>, actual: &Resolution<'_>) {
    assert_debug_eq("assembly", &expected.assembly, &actual.assembly);
    assert_debug_eq(
        "assembly_references",
        &expected.assembly_references,
        &actual.assembly_references,
    );
    assert_debug_eq("entry_point", &expected.entry_point, &actual.entry_point);
    assert_debug_eq("exported_types", &expected.exported_types, &actual.exported_types);
    assert_debug_eq("field_references", &expected.field_references, &actual.field_references);
    assert_debug_eq("files", &expected.files, &actual.files);
    assert_debug_eq(
        "manifest_resources",
        &expected.manifest_resources,
        &actual.manifest_resources,
    );
    assert_debug_eq(
        "method_references",
        &expected.method_references,
        &actual.method_references,
    );
    assert_debug_eq("module", &expected.module, &actual.module);
    assert_debug_eq(
        "module_references",
        &expected.module_references,
        &actual.module_references,
    );
    assert_debug_eq("type_definitions", &expected.type_definitions, &actual.type_definitions);
    assert_debug_eq("type_references", &expected.type_references, &actual.type_references);
}

fn materialize_lazy_method_state(mut resolution: Resolution<'_>) -> Result<Resolution<'_>, Box<dyn std::error::Error>> {
    let type_indices: Vec<_> = resolution
        .enumerate_type_definitions()
        .map(|(type_idx, _)| type_idx)
        .collect();

    let mut method_indices = Vec::new();

    for type_idx in type_indices {
        method_indices.extend(resolution.enumerate_methods(type_idx).map(|(method_idx, _)| method_idx));

        let property_indices: Vec<_> = resolution
            .enumerate_properties(type_idx)
            .map(|(property_idx, _)| property_idx)
            .collect();
        for property_idx in property_indices {
            if let Some(getter_idx) = resolution.property_getter_index(property_idx) {
                method_indices.push(getter_idx);
            }
            if let Some(setter_idx) = resolution.property_setter_index(property_idx) {
                method_indices.push(setter_idx);
            }
            let other_len = resolution[property_idx].other.len();
            for other_idx in 0..other_len {
                method_indices.push(
                    resolution
                        .property_other_index(property_idx, other_idx)
                        .expect("valid property other index"),
                );
            }
        }

        let event_indices: Vec<_> = resolution
            .enumerate_events(type_idx)
            .map(|(event_idx, _)| event_idx)
            .collect();
        for event_idx in event_indices {
            method_indices.push(resolution.event_add_index(event_idx));
            method_indices.push(resolution.event_remove_index(event_idx));
            if let Some(raise_idx) = resolution.event_raise_index(event_idx) {
                method_indices.push(raise_idx);
            }
            let other_len = resolution[event_idx].other.len();
            for other_idx in 0..other_len {
                method_indices.push(
                    resolution
                        .event_other_index(event_idx, other_idx)
                        .expect("valid event other index"),
                );
            }
        }
    }

    for method_idx in method_indices {
        let signature = resolution.method_signature(method_idx)?.clone();
        resolution[method_idx].signature = signature;

        let body = match resolution.method_body(method_idx) {
            Ok(body) => Some(body.clone()),
            Err(DLLError::Other("method has no body (abstract or rva == 0)")) => None,
            Err(other) => return Err(Box::new(other)),
        };

        if let Some(body) = body {
            resolution[method_idx].body = Some(body);
        }
    }

    let method_ref_indices: Vec<_> = resolution
        .enumerate_method_references()
        .map(|(method_ref_idx, _)| method_ref_idx)
        .collect();

    for method_ref_idx in method_ref_indices {
        let signature = resolution.method_ref_signature(method_ref_idx)?.clone();
        resolution[method_ref_idx].signature = signature;
    }

    Ok(resolution)
}

fn assert_eager_and_lazy_all_public_fields_match(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let eager = Resolution::parse(bytes, ReadOptions::default())?;
    let lazy = Resolution::parse(
        bytes,
        ReadOptions {
            lazy_method_bodies: true,
            lazy_method_signatures: true,
            ..ReadOptions::default()
        },
    )?;
    let lazy = materialize_lazy_method_state(lazy)?;

    assert_resolution_public_fields_eq(&eager, &lazy);

    Ok(())
}

#[test]
fn oop_fixture_public_resolution_fields_match() -> Result<(), Box<dyn std::error::Error>> {
    assert_eager_and_lazy_all_public_fields_match(OOP_DLL)
}

#[test]
fn system_private_corelib_public_resolution_fields_match() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("RUNTIME_ARTIFACTS").is_none() {
        eprintln!("skipping system_private_corelib_public_resolution_fields_match: RUNTIME_ARTIFACTS not set");
        return Ok(());
    }

    let bytes = std::fs::read(common::env::LIBRARIES.join("System.Private.CoreLib.dll"))?;
    assert_eager_and_lazy_all_public_fields_match(&bytes)
}
