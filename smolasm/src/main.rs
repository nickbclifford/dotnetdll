use dotnetdll::prelude::*;
use std::collections::HashMap;

mod ast;
mod parse;

fn type_reference(
    decl: ast::TypeRef,
    types: &HashMap<String, TypeIndex>,
    externs: &HashMap<String, AssemblyRefIndex>,
    resolution: &mut Resolution,
) -> UserType {
    match decl.parent {
        Some(parent) => {
            let asm_name = parent.to_string();
            let scope =
                ResolutionScope::Assembly(*externs.get(&asm_name).unwrap_or_else(|| {
                    panic!("external assembly {} has not been declared", asm_name)
                }));
            let (namespace, name) = decl.target.into_names();
            // shadow with Cow version
            let namespace = namespace.map(Into::into);

            let existing_ref = resolution
                .enumerate_type_references()
                .find(|(_, r)| r.scope == scope && r.namespace == namespace && r.name == name);
            UserType::Reference(match existing_ref {
                Some((idx, _)) => idx,
                None => resolution
                    .push_type_reference(ExternalTypeReference::new(namespace, name, scope)),
            })
        }
        None => {
            let name = decl.target.to_string();
            UserType::Definition(
                *types
                    .get(&name)
                    .unwrap_or_else(|| panic!("{} is not defined in the current assembly", name)),
            )
        }
    }
}

fn main() {
    let input_filename = std::env::args()
        .nth(1)
        .expect("missing required input filename");
    let input = std::fs::read_to_string(input_filename).expect("could not open input file");

    let ast = parse::assembly(&input).expect("could not parse input");

    let name = ast.assembly_decl.assembly.to_string();
    let dll = format!("{}.dll", &name);

    let mut resolution = Resolution::new(Module::new(&dll));

    let mut externs: HashMap<_, _> = ast
        .extern_decls
        .into_iter()
        .map(|decl| {
            let name = decl.assembly.to_string();
            (
                name.clone(),
                resolution.push_assembly_reference(ExternalAssemblyReference::new(name)),
            )
        })
        .collect();
    let mscorlib = *externs.entry(String::from("mscorlib")).or_insert_with(|| {
        resolution.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"))
    });
    let valuetype = resolution.push_type_reference(type_ref! { System.ValueType in #mscorlib });
    let object = resolution.push_type_reference(type_ref! { System.Object in #mscorlib });

    let types: HashMap<_, _> = ast
        .top_level_decls
        .iter()
        .map(|decl| {
            let (namespace, name) = decl.name().clone().into_names();
            (
                decl.name().to_string(),
                resolution
                    .push_type_definition(TypeDefinition::new(namespace.map(Into::into), name)),
            )
        })
        .collect();

    macro_rules! type_reference {
        ($r:expr) => {
            type_reference($r, &types, &externs, &mut resolution)
        };
    }

    for decl in ast.top_level_decls {
        let idx = types[&decl.name().to_string()];

        resolution[idx].flags.accessibility = if decl.public {
            TypeAccessibility::Public
        } else {
            TypeAccessibility::NotPublic
        };

        use ast::TopLevelKind::*;
        match decl.kind {
            Enum(e) => {
                resolution[idx].fields.push(Field::instance(
                    Accessibility::Public,
                    "value__",
                    match e.base {
                        Some(e) => e.into(),
                        None => BaseType::Int32,
                    }
                    .into(),
                ));

                for (member_idx, ident) in e.members.into_iter().enumerate() {
                    use ast::IntType::*;

                    let mut field = Field::static_member(
                        Accessibility::Public,
                        ident,
                        BaseType::valuetype(idx).into(),
                    );
                    field.literal = true;
                    field.default = Some(match e.base.unwrap_or(Int) {
                        Bool => Constant::Boolean(member_idx == 1),
                        Char => Constant::Char(member_idx.try_into().unwrap()),
                        SByte => Constant::Int8(member_idx.try_into().unwrap()),
                        Byte => Constant::UInt8(member_idx.try_into().unwrap()),
                        Short => Constant::Int16(member_idx.try_into().unwrap()),
                        UShort => Constant::UInt16(member_idx.try_into().unwrap()),
                        Int => Constant::Int32(member_idx.try_into().unwrap()),
                        UInt => Constant::UInt32(member_idx.try_into().unwrap()),
                        Long => Constant::Int64(member_idx.try_into().unwrap()),
                        ULong => Constant::UInt64(member_idx.try_into().unwrap()),
                        NInt => {
                            if cfg!(target_pointer_width = "32") {
                                Constant::Int32(member_idx.try_into().unwrap())
                            } else {
                                Constant::Int64(member_idx.try_into().unwrap())
                            }
                        }
                        NUInt => {
                            if cfg!(target_pointer_width = "32") {
                                Constant::UInt32(member_idx.try_into().unwrap())
                            } else {
                                Constant::UInt64(member_idx.try_into().unwrap())
                            }
                        }
                    });
                    resolution[idx].fields.push(field);
                }
            }
            Type(t) => {
                use ast::TypeKind::*;
                match t.kind {
                    Class { r#abstract } => {
                        resolution[idx].extends = Some(match t.extends {
                            Some(r) => type_reference!(r).into(),
                            None => object.into(),
                        });
                        resolution[idx].flags.abstract_type = r#abstract;
                    }
                    Struct => {
                        resolution[idx].extends = Some(valuetype.into());
                    }
                    Interface => {
                        resolution[idx].flags.kind = Kind::Interface;
                        resolution[idx].implements = t
                            .implements
                            .into_iter()
                            .flatten()
                            .map(|r| (vec![], type_reference!(r).into()))
                            .collect();
                    }
                }

                for item in t.items {
                    use ast::TypeItemKind;
                    match item.kind {
                        TypeItemKind::Field(f) => {
                            resolution[idx].fields.push(Field::new(item.r#static, item.access.into(), f.1, todo!()))
                        }
                        TypeItemKind::Method(_) => {}
                        TypeItemKind::Property(_) => {}
                        TypeItemKind::Event(_) => {}
                    }
                }
            }
        }
    }

    // TODO: the important bits

    std::fs::write(
        &dll,
        DLL::write(&resolution, false, true).expect("could not assemble .NET module"),
    )
    .expect("could not write output file")
}
