use dotnetdll::resolved::ResolvedDebug;
use dotnetdll::{
    resolution::{AssemblyRefIndex, Resolution},
    resolved::{
        assembly::{Assembly, ExternalAssemblyReference, Version},
        members::{Constant, Field},
        module::Module,
        types::{Accessibility as TAccess, BaseType, ExternalTypeReference, ResolutionScope, TypeDefinition, UserType},
        Accessibility,
    },
};
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use std::collections::HashMap;

#[derive(Parser)]
#[grammar = "assembly.pest"]
pub struct AssemblyParser;

fn asm_spec(spec: Pair<Rule>) -> (&str, Version) {
    let mut iter = spec.into_inner();

    let assembly_name = iter.next().unwrap().as_str();
    let mut version = Version::ZERO;
    if let Some(v) = iter.next() {
        let mut v_iter = v.into_inner();
        version.major = v_iter.next().unwrap().as_str().parse().unwrap();
        macro_rules! next {
            ($name:ident) => {
                if let Some(nat) = v_iter.next() {
                    version.$name = nat.as_str().parse().unwrap();
                }
            };
        }
        next!(minor);
        next!(build);
        next!(revision);
    }

    (assembly_name, version)
}

fn dotted(s: &str) -> (Option<&str>, &str) {
    match s.rfind('.') {
        Some(i) => (Some(&s[..i]), &s[i + 1..]),
        None => (None, s),
    }
}

fn int_type<T>(t: &str) -> BaseType<T> {
    match t {
        "bool" => BaseType::Boolean,
        "char" => BaseType::Char,
        "sbyte" => BaseType::Int8,
        "byte" => BaseType::UInt8,
        "short" => BaseType::Int16,
        "ushort" => BaseType::UInt16,
        "int" => BaseType::Int32,
        "uint" => BaseType::UInt32,
        "long" => BaseType::Int64,
        "ulong" => BaseType::UInt64,
        "nint" => BaseType::IntPtr,
        "nuint" => BaseType::UIntPtr,
        _ => unreachable!(),
    }
}

fn type_ref(pair: Pair<Rule>) -> (Option<&str>, &str) {
    let pairs: Vec<_> = pair.into_inner().collect();
    match &pairs[..] {
        [t] => (None, t.as_str()),
        [a, t] => (Some(a.as_str()), t.as_str()),
        _ => unreachable!(),
    }
}

fn main() {
    let mut pairs = match AssemblyParser::parse(Rule::assembly, include_str!("test.il")) {
        Ok(a) => a,
        Err(e) => panic!("{}", e),
    };

    println!("{:#?}", pairs);

    let asm_decl = pairs.next().unwrap();
    let (assembly_name, version) = asm_spec(asm_decl);

    let module_name = format!("{}.dll", assembly_name);
    let mut res = Resolution::new(Module::new(&module_name));
    let mut assembly = Assembly::new(assembly_name);
    assembly.version = version;
    res.assembly = Some(assembly);

    let mut extern_map = HashMap::new();
    while matches!(pairs.peek(), Some(p) if p.as_rule() == Rule::extern_decl) {
        let (name, version) = asm_spec(pairs.next().unwrap());
        let mut asm_ref = ExternalAssemblyReference::new(name);
        asm_ref.version = version;
        extern_map.insert(name, res.push_assembly_reference(asm_ref));
    }

    // we always need an mscorlib reference, insert a default one if the user didn't specify a version
    let mscorlib = *extern_map
        .entry("mscorlib")
        .or_insert_with(|| res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib")));

    println!("{:#?}", extern_map);

    let mut ref_map: HashMap<(AssemblyRefIndex, &str), _> = HashMap::new();
    macro_rules! get_ref {
        ($asm_ref:expr, $typename:expr) => {{
            let a = $asm_ref;
            let t = $typename;
            match ref_map.get(&(a, t)) {
                Some(i) => *i,
                None => {
                    let (namespace, name) = dotted(t);
                    res.push_type_reference(ExternalTypeReference::new(
                        namespace,
                        name,
                        ResolutionScope::Assembly(a),
                    ))
                }
            }
        }};
    }

    enum TypeKind<'i> {
        Enum {
            raw_type: Option<&'i str>,
            name: &'i str,
            idents: Vec<&'i str>,
        },
        Class {
            kind: &'i str,
            name: &'i str,
            extends: Option<Pair<'i, Rule>>,
            implements: Option<Pair<'i, Rule>>,
            items: Vec<Pair<'i, Rule>>,
        },
    }

    // process all top-level declarations first so that items can reference any top-level type
    let mut types = HashMap::new();
    let mut kinds = vec![];
    for top_level_decl in pairs {
        if top_level_decl.as_rule() == Rule::EOI {
            break;
        }

        let access = if top_level_decl.as_str().starts_with("public") {
            TAccess::Public
        } else {
            TAccess::NotPublic
        };

        let decl = top_level_decl.into_inner().next().unwrap();
        let is_enum = decl.as_rule() == Rule::enum_decl;
        let mut pairs = decl.into_inner();

        let kind = if is_enum {
            TypeKind::Enum {
                raw_type: if pairs.peek().unwrap().as_rule() == Rule::int_type {
                    Some(pairs.next().unwrap().as_str())
                } else {
                    None
                },
                name: pairs.next().unwrap().as_str(),
                idents: pairs.map(|p| p.as_str()).collect(),
            }
        } else {
            TypeKind::Class {
                kind: pairs.next().unwrap().as_str(),
                name: pairs.next().unwrap().as_str(),
                extends: if matches!(pairs.peek(), Some(p) if p.as_rule() == Rule::extends) {
                    Some(pairs.next().unwrap().into_inner().next().unwrap())
                } else {
                    None
                },
                implements: if matches!(pairs.peek(), Some(p) if p.as_rule() == Rule::implements) {
                    Some(pairs.next().unwrap())
                } else {
                    None
                },
                items: pairs.collect(),
            }
        };

        let typename = match kind {
            TypeKind::Enum { name, .. } => name,
            TypeKind::Class { name, .. } => name,
        };
        let (namespace, name) = dotted(typename);

        let type_def = res.push_type_definition(TypeDefinition::new(namespace, name));
        types.insert(typename, type_def);

        res[type_def].flags.accessibility = access;
        kinds.push((type_def, kind));
    }

    macro_rules! user_type {
        ($r:expr) => {{
            let (asm, name) = type_ref($r);
            match asm {
                Some(a) => UserType::from(get_ref!(extern_map[a], name)),
                None => UserType::from(types[name]),
            }
        }};
    }

    // now start processing top-level bodies
    for (type_def, kind) in kinds {
        match kind {
            TypeKind::Enum { raw_type, idents, .. } => {
                res[type_def].extends = Some(get_ref!(mscorlib, "System.Enum").into());
                let mut value_field = Field::new(
                    Accessibility::Public,
                    "value__",
                    match raw_type {
                        Some(s) => int_type(s),
                        None => BaseType::Int32,
                    }
                    .into(),
                );
                value_field.special_name = true;
                value_field.runtime_special_name = true;
                res[type_def].fields.push(value_field);
                for (idx, i) in idents.into_iter().enumerate() {
                    let mut field = Field::new(Accessibility::Public, i, BaseType::Type(type_def.into()).into());
                    field.static_member = true;
                    field.literal = true;
                    // TODO: native ints
                    field.default = Some(match raw_type {
                        Some("bool") => Constant::Boolean(idx == 1),
                        Some("char") => Constant::Char(idx.try_into().unwrap()),
                        Some("sbyte") => Constant::Int8(idx.try_into().unwrap()),
                        Some("byte") => Constant::UInt8(idx.try_into().unwrap()),
                        Some("short") => Constant::Int16(idx.try_into().unwrap()),
                        Some("ushort") => Constant::UInt16(idx.try_into().unwrap()),
                        Some("int") | None => Constant::Int32(idx.try_into().unwrap()),
                        Some("uint") => Constant::UInt32(idx.try_into().unwrap()),
                        Some("long") => Constant::Int64(idx.try_into().unwrap()),
                        Some("ulong") => Constant::UInt64(idx.try_into().unwrap()),
                        _ => unreachable!(),
                    });
                    res[type_def].fields.push(field);
                }
            }
            TypeKind::Class {
                kind,
                extends,
                implements,
                ..
            } => {
                res[type_def].extends = if let Some(e) = extends {
                    Some(user_type!(e).into())
                } else if kind != "interface" {
                    Some(
                        get_ref!(
                            mscorlib,
                            if kind == "struct" {
                                "System.ValueType"
                            } else {
                                "System.Object"
                            }
                        )
                        .into(),
                    )
                } else {
                    None
                };

                if let Some(i) = implements {
                    for p in i.into_inner() {
                        let val = (vec![], user_type!(p).into());
                        res[type_def].implements.push(val)
                    }
                }
            }
        }
    }

    for t in &res.type_definitions {
        println!("{}", t.show(&res));

        for f in &t.fields {
            println!("\t{}", f.show(&res));
        }
    }
}
