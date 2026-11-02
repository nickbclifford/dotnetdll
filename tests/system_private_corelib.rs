use dotnetdll::prelude::*;

#[macro_use]
mod common;

/// Verify that `lazy_method_signatures` produces the same decoded signatures as eager mode.
#[test]
fn lazy_signatures_match_eager() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::read(common::env::LIBRARIES.join("System.Private.CoreLib.dll"))?;

    let eager = Resolution::parse(&file, ReadOptions::default())?;
    let lazy = Resolution::parse(&file, ReadOptions::default().with_lazy_method_signatures(true))?;

    let method_checks = {
        let mut checked = 0;
        for (type_idx, typedef) in eager.enumerate_type_definitions() {
            for (method_idx, eager_method) in eager.enumerate_methods(type_idx) {
                let eager_sig = &eager_method.signature;
                let lazy_sig = lazy.method_signature(method_idx)?;
                assert_eq!(
                    eager_sig, lazy_sig,
                    "signature mismatch for method {}::{}",
                    typedef.name, eager_method.name
                );
                checked += 1;
            }
        }
        checked
    };

    let method_ref_checks = {
        let mut checked = 0;
        for (ref_idx, eager_ref) in eager.enumerate_method_references() {
            let eager_sig = &eager_ref.signature;
            let lazy_sig = lazy.method_ref_signature(ref_idx)?;
            assert_eq!(
                eager_sig, lazy_sig,
                "method ref signature mismatch for {}",
                eager_ref.name
            );
            checked += 1;
        }
        checked
    };

    // Run a second pass to exercise hot accessor/cache lookups after lazy map/cache initialization.
    let cache_pass = {
        let mut checked = 0;
        for (type_idx, _) in eager.enumerate_type_definitions() {
            for (method_idx, _) in eager.enumerate_methods(type_idx) {
                let _ = lazy.method_signature(method_idx)?;
                checked += 1;
            }
        }
        for (ref_idx, _) in eager.enumerate_method_references() {
            let _ = lazy.method_ref_signature(ref_idx)?;
            checked += 1;
        }
        checked
    };

    assert!(method_checks > 0, "no method defs checked");
    assert!(method_ref_checks > 0, "no method refs checked");
    assert!(cache_pass >= method_checks + method_ref_checks);
    Ok(())
}

#[test]
fn parse() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::read(common::env::LIBRARIES.join("System.Private.CoreLib.dll"))?;
    let r = Resolution::parse(&file, ReadOptions::default())?;

    if let Some(e) = &r.entry_point {
        print!("assembly entry point: ");
        match e {
            EntryPoint::Method(m) => println!("{}", UserMethod::Definition(*m).show(&r)),
            EntryPoint::File(f) => println!("external file {}", r[*f].name),
        }
    }

    for e in &r.exported_types {
        if let TypeImplementation::TypeForwarder(a) = e.implementation {
            println!("re-exports {} from {}", e.type_name(), r[a].name);
        }
    }

    for t in &r.type_definitions {
        println!("{} {{", t.show(&r));

        for f in &t.fields {
            println!("\t{};", f.show(&r));
        }
        for p in &t.properties {
            println!("\t{};", p.show(&r));
        }

        for m in &t.methods {
            print!("\t{}", m.show(&r));

            if let Some(b) = &m.body {
                println!(" {{");

                if b.header.initialize_locals {
                    println!("\t\tinit locals");
                }
                println!("\t\tmaximum stack size {}", b.header.maximum_stack_size);
                let locals = &b.header.local_variables;
                if !locals.is_empty() {
                    println!("\t\tlocal variables:");

                    let max_size = ((locals.len() - 1) as f32).log10().ceil() as usize;

                    for (idx, v) in locals.iter().enumerate() {
                        println!("\t\t\t{:1$}: {2}", idx, max_size, v.show(&r));
                    }
                }

                let max_size = ((b.instructions.len() - 1) as f32).log10().ceil() as usize;

                println!("\t\t---");

                for (idx, instr) in b.instructions.iter().enumerate() {
                    println!("\t\t{:1$}: {2}", idx, max_size, instr.show(&r));
                }

                println!("\t}}");
            } else {
                println!(";");
            }
        }

        println!("}}\n");
    }

    Ok(())
}

/// Cover framework metadata (including its large name heaps) in both ownership modes.
#[test]
fn owned_heap_metadata_matches_borrowed() -> Result<(), Box<dyn std::error::Error>> {
    use std::{borrow::Cow, fmt::Write, hash::Hasher};
    struct Digest(std::collections::hash_map::DefaultHasher);
    impl std::fmt::Write for Digest {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.0.write(s.as_bytes());
            Ok(())
        }
    }
    fn digest(value: &impl std::fmt::Debug) -> u64 {
        let mut d = Digest(Default::default());
        write!(d, "{value:?}").unwrap();
        d.0.finish()
    }
    let bytes = std::fs::read(common::env::LIBRARIES.join("System.Private.CoreLib.dll"))?;
    for lazy_attributes in [false, true] {
        let options = ReadOptions::default()
            .with_lazy_method_bodies(true)
            .with_lazy_attributes(lazy_attributes);
        let borrowed = Resolution::parse(&bytes, options)?;
        let owned = Resolution::parse(&bytes, options.with_own_heap_values(true))?;
        assert!(matches!(borrowed.module.name, Cow::Borrowed(_)));
        assert!(matches!(owned.module.name, Cow::Owned(_)));
        assert_eq!(borrowed.module.name, owned.module.name);
        assert_eq!(digest(&borrowed.assembly), digest(&owned.assembly));
        assert_eq!(digest(&borrowed.type_references), digest(&owned.type_references));
        assert_eq!(digest(&borrowed.method_references), digest(&owned.method_references));
        assert_eq!(
            digest(&borrowed.assembly_attributes()?),
            digest(&owned.assembly_attributes()?)
        );
        for (ti, ty) in owned.enumerate_type_definitions() {
            assert!(matches!(ty.name, Cow::Owned(_)));
            assert_eq!(borrowed[ti].name, ty.name);
            assert_eq!(borrowed[ti].namespace, ty.namespace);
            for (mi, method) in owned.enumerate_methods(ti) {
                assert_eq!(borrowed[mi].name, method.name);
                assert_eq!(borrowed[mi].signature, method.signature);
                assert_eq!(
                    digest(&borrowed.method_attributes(mi)?),
                    digest(&owned.method_attributes(mi)?)
                );
            }
            for (fi, field) in owned.enumerate_fields(ti) {
                assert_eq!(borrowed[fi].name, field.name);
                assert_eq!(borrowed[fi].return_type, field.return_type);
                assert_eq!(
                    digest(&borrowed.field_attributes(fi)?),
                    digest(&owned.field_attributes(fi)?)
                );
            }
            for (pi, _) in owned.enumerate_properties(ti) {
                assert_eq!(digest(&borrowed[pi]), digest(&owned[pi]));
            }
            assert_eq!(
                digest(&borrowed.type_attributes(ti)?),
                digest(&owned.type_attributes(ti)?)
            );
        }
    }
    Ok(())
}
