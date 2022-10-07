use dotnetdll::prelude::*;
use std::collections::HashMap;

mod ast;
mod parse;

fn main() {
    let input_filename = std::env::args()
        .nth(1)
        .expect("missing required input filename");
    let input = std::fs::read_to_string(input_filename).expect("could not open input file");

    let ast = parse::assembly(&input).expect("could not parse input");

    let name = ast.assembly_decl.assembly.to_string();
    let dll = format!("{}.dll", &name);

    let mut resolution = Resolution::new(Module::new(&dll));

    let mut externs = HashMap::new();
    for ex_decl in ast.extern_decls {
        let name = ex_decl.assembly.to_string();
        externs.insert(
            name.clone(),
            resolution.push_assembly_reference(ExternalAssemblyReference::new(name)),
        );
    }

    let mut types = HashMap::new();
    for decl in ast.top_level_decls.iter() {
        use ast::TopLevelKind::*;

        let ast::Dotted(mut full_name) = match &decl.kind {
            Enum(e) => &e.name,
            Type(t) => &t.name,
        }
        .clone();
        let (namespace, name) = if full_name.len() > 1 {
            let name = full_name.pop().unwrap();
            (Some(full_name.join(".").into()), name)
        } else {
            (None, full_name[0].clone())
        };

        types.insert(
            full_name.join("."),
            resolution.push_type_definition(TypeDefinition::new(namespace, name)),
        );
    }

    // TODO: the important bits

    std::fs::write(
        &dll,
        DLL::write(&resolution, false, true).expect("could not assemble .NET module"),
    )
    .expect("could not write output file")
}
