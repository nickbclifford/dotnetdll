use dotnetdll::prelude::*;

#[macro_use]
mod common;

#[test]
fn parse() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::read(common::env::LIBRARIES.join("System.Private.CoreLib.dll"))?;
    let dll = DLL::parse(&file)?;

    let r = dll.resolve(ResolveOptions::default())?;

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
