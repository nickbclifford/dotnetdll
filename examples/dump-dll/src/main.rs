use dotnetdll::prelude::*;
use std::collections::HashMap;

macro_rules! auto_newlines {
    (for $var:ident in $iter:ident { $($inner:tt)* }) => {
        let last_idx = $iter.len().saturating_sub(1);
        for (i, $var) in $iter.into_iter().enumerate() {
            $($inner)*

            if i != last_idx {
                println!();
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::args().nth(1) else {
        panic!("missing DLL argument")
    };

    let data = std::fs::read(path)?;
    let dll = DLL::parse(&data)?;
    let res = dll.resolve(ReadOptions::default())?;

    let mut all_namespaces: HashMap<&str, _> = HashMap::new();
    let mut owners = HashMap::new();

    let (nested, nonnested): (Vec<_>, Vec<_>) = res
        .enumerate_type_definitions()
        .partition(|(_, t)| t.encloser.is_some());

    for (n_idx, n) in nested {
        owners
            .entry(n.encloser.unwrap())
            .or_insert(vec![])
            .push(n_idx);
    }
    for (n_idx, n) in nonnested {
        if let Some(ns) = &n.namespace {
            all_namespaces.entry(ns).or_insert(vec![]).push(n_idx);
        }
    }

    for (ns, types) in all_namespaces {
        println!("namespace {} {{", ns);
        auto_newlines! {
            for ty in types {
                print_type(ty, &res, 1, &owners);
            }
        }
        println!("}}");
    }

    Ok(())
}

fn print_type(
    t: TypeIndex,
    res: &Resolution,
    indent: usize,
    contains: &HashMap<TypeIndex, Vec<TypeIndex>>,
) {
    let ty = &res[t];
    let mut title = ty.show(res);
    if let Some(ns) = &ty.namespace {
        title = title.replace(&format!("{}.", ns), "");
    }
    if let Some(t) = ty.encloser {
        title = title.replace(&format!("{}/", res[t].type_name()), "");
    }

    println!("{}{} {{", "\t".repeat(indent), title);

    if let Some(c) = contains.get(&t) {
        auto_newlines! {
            for t in c {
                print_type(*t, res, indent + 1, contains);
            }
        }
    }
    
    let ms = ty.methods.clone();

    auto_newlines! {
        for m in ms {
            println!("{}{};", "\t".repeat(indent + 1), m.show(res));
        }
    }

    println!("{}}}", "\t".repeat(indent));
}
