use dotnetdll::prelude::*;

#[macro_use]
mod common;

/// Verify that `lazy_method_signatures` produces the same decoded signatures as eager mode.
#[test]
fn lazy_signatures_match_eager() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::read(common::env::LIBRARIES.join("System.Private.CoreLib.dll"))?;

    let eager = Resolution::parse(&file, ReadOptions::default())?;
    let lazy = Resolution::parse(
        &file,
        ReadOptions {
            lazy_method_signatures: true,
            ..ReadOptions::default()
        },
    )?;

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
