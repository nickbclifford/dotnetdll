use dotnetdll::prelude::*;
use std::collections::HashMap;

mod ast;
mod parse;

struct Context<'r, 'data: 'r> {
    types: &'r HashMap<String, TypeIndex>,
    externs: &'r HashMap<String, AssemblyRefIndex>,
    methods: &'r mut HashMap<ast::MethodRef, UserMethod>,
    resolution: &'r mut Resolution<'data>,
}

fn type_reference(decl: ast::TypeRef, ctx: &mut Context) -> UserType {
    match decl.parent {
        Some(parent) => {
            let asm_name = parent.to_string();
            let scope =
                ResolutionScope::Assembly(*ctx.externs.get(&asm_name).unwrap_or_else(|| {
                    panic!("external assembly {} has not been declared", asm_name)
                }));
            let (namespace, name) = decl.target.into_names();
            // shadow with Cow version
            let namespace = namespace.map(Into::into);

            let existing_ref = ctx
                .resolution
                .enumerate_type_references()
                .find(|(_, r)| r.scope == scope && r.namespace == namespace && r.name == name);
            UserType::Reference(match existing_ref {
                Some((idx, _)) => idx,
                None => ctx
                    .resolution
                    .push_type_reference(ExternalTypeReference::new(namespace, name, scope)),
            })
        }
        None => {
            let name = decl.target.to_string();
            UserType::Definition(
                *ctx.types
                    .get(&name)
                    .unwrap_or_else(|| panic!("{} is not defined in the current assembly", name)),
            )
        }
    }
}

fn r#type<T: From<BaseType<T>>>(decl: ast::Type, ctx: &mut Context) -> T {
    use ast::Type::*;
    match decl {
        Integer(i) => BaseType::from(i).into(),
        String => ctype!(string),
        Object => ctype!(object),
        Float => ctype!(float),
        Double => ctype!(double),
        RefType(r) => BaseType::class(type_reference(r, ctx)).into(),
        ValueType(r) => BaseType::valuetype(type_reference(r, ctx)).into(),
        Vector(t) => BaseType::vector(r#type(*t, ctx)).into(),
        Pointer(None) => BaseType::VOID_PTR.into(),
        Pointer(Some(t)) => BaseType::pointer(r#type(*t, ctx)).into(),
    }
}

fn param_type(decl: ast::ParamType, ctx: &mut Context) -> ParameterType {
    let t = r#type(decl.r#type, ctx);
    if decl.r#ref {
        ParameterType::Ref(t)
    } else {
        ParameterType::Value(t)
    }
}

fn method_reference(decl: ast::MethodRef, ctx: &mut Context) -> UserMethod {
    if let Some(&m) = ctx.methods.get(&decl) {
        return m;
    }

    let d = decl.clone();
    let method = ExternalMethodReference::new(
        MethodReferenceParent::Type(r#type(d.parent, ctx)),
        d.method,
        ManagedMethod::new(
            !d.r#static,
            match d.return_type {
                None => ReturnType::VOID,
                Some(p) => ReturnType::new(param_type(p, ctx)),
            },
            d.parameters
                .into_iter()
                .map(|p| Parameter::new(param_type(p, ctx)))
                .collect(),
        ),
    );

    let mut user_method = None;

    if let ast::Type::RefType(r) | ast::Type::ValueType(r) = &decl.parent {
        if let Some(parent) = &r.parent {
            if let Some(&idx) = ctx.types.get(&parent.to_string()) {
                let (method_idx, _) = ctx
                    .resolution
                    .enumerate_methods(idx)
                    .find(|(_, m)| m.signature == method.signature)
                    .unwrap_or_else(|| {
                        panic!(
                            "could not find matching method {} on type {}",
                            method
                                .signature
                                .show_with_name(ctx.resolution, &decl.method),
                            parent
                        )
                    });
                user_method = Some(UserMethod::Definition(method_idx));
            }
        }
    }

    let idx = user_method
        .unwrap_or_else(|| UserMethod::Reference(ctx.resolution.push_method_reference(method)));
    ctx.methods.insert(decl, idx);
    idx
}

fn field_reference(decl: ast::FieldRef, ctx: &mut Context) -> FieldRefIndex {
    let field_ref = ExternalFieldReference::new(
        FieldReferenceParent::Type(r#type(decl.parent, ctx)),
        r#type(decl.return_type, ctx),
        decl.field.into(),
    );

    if let Some((idx, _)) = ctx.resolution.enumerate_field_references().find(|(_, r)| {
        r.parent == field_ref.parent && r.name == field_ref.name && r.field_type == field_ref.field_type
    }) {
        return idx;
    }

    ctx.resolution.push_field_reference(field_ref)
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
    let enum_ref = resolution.push_type_reference(type_ref! { System.Enum in #mscorlib });

    let types: HashMap<_, TypeIndex> = ast
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

    let mut methods = HashMap::new();

    macro_rules! ctx {
        () => {
            &mut Context {
                types: &types,
                externs: &externs,
                methods: &mut methods,
                resolution: &mut resolution,
            }
        };
    }

    let mut methods = vec![];

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
                resolution[idx].extends = Some(enum_ref.into());
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
                            Some(r) => type_reference(r, ctx!()).into(),
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
                            .map(|r| (vec![], type_reference(r, ctx!()).into()))
                            .collect();
                    }
                }

                for item in t.items {
                    use ast::TypeItemKind;
                    match item.kind {
                        TypeItemKind::Field(f) => {
                            let return_type = r#type(f.0, ctx!());
                            resolution[idx].fields.push(Field::new(
                                item.r#static,
                                item.access.into(),
                                f.1,
                                return_type,
                            ));
                        }
                        TypeItemKind::Method(m) => {
                            let (types, names): (Vec<_>, Vec<_>) = m.parameters.into_iter().unzip();

                            let signature = ManagedMethod::new(
                                !item.r#static,
                                match m.return_type {
                                    Some(t) => ReturnType::new(param_type(t, ctx!())),
                                    None => ReturnType::VOID,
                                },
                                types
                                    .into_iter()
                                    .map(|t| Parameter::new(param_type(t, ctx!())))
                                    .collect(),
                            );
                            let method = resolution.push_method(
                                idx,
                                Method::new(item.access.into(), signature, m.name, None),
                            );
                            resolution[method].parameter_metadata = names
                                .into_iter()
                                .map(|n| Some(ParameterMetadata::name(n)))
                                .collect();

                            if let Some(body) = m.body {
                                methods.push((method, body));
                            }
                        }
                        TypeItemKind::Property(p) => {
                            let return_type: MethodType = r#type(p.r#type, ctx!());

                            let property = resolution.push_property(
                                idx,
                                Property::new(
                                    item.r#static,
                                    p.name.clone(),
                                    Parameter::value(return_type.clone()),
                                ),
                            );

                            for ast::SemanticMethod(name, body) in p.methods {
                                let method = match name.as_str() {
                                    "get" => Method::new(
                                        item.access.into(),
                                        msig! { @return_type () },
                                        format!("get_{}", &p.name),
                                        None,
                                    ),
                                    "set" => Method::new(
                                        item.access.into(),
                                        msig! { void (@return_type) },
                                        format!("set_{}", &p.name),
                                        None,
                                    ),
                                    _ => panic!("properties can only have getters and setters"),
                                };
                                let idx = match name.as_str() {
                                    "get" => resolution.set_property_getter(property, method),
                                    "set" => resolution.set_property_setter(property, method),
                                    _ => unreachable!(),
                                };

                                methods.push((idx, body));
                            }
                        }
                        TypeItemKind::Event(e) => {
                            let return_type: MemberType = r#type(e.r#type, ctx!());

                            let mut add = None;
                            let mut remove = None;

                            for ast::SemanticMethod(name, body) in e.methods {
                                let method = Method::new(
                                    item.access.into(),
                                    MethodSignature::new(
                                        !item.r#static,
                                        ReturnType::VOID,
                                        vec![Parameter::value(return_type.clone().into())],
                                    ),
                                    format!("{}_{}", &name, &e.name),
                                    None,
                                );

                                match name.as_str() {
                                    "add" => {
                                        add = Some((method, body));
                                    }
                                    "remove" => {
                                        remove = Some((method, body));
                                    }
                                    _ => panic!(
                                        "events can only have add and remove handlers (for now)"
                                    ),
                                }
                            }

                            let (add, add_body) =
                                add.unwrap_or_else(|| panic!("event missing add handler"));
                            let (remove, remove_body) =
                                remove.unwrap_or_else(|| panic!("event missing remove handler"));

                            let event = resolution
                                .push_event(idx, Event::new(e.name, return_type, add, remove));

                            methods.extend([
                                (resolution.event_add_index(event), add_body),
                                (resolution.event_remove_index(event), remove_body),
                            ]);
                        }
                    }
                }
            }
        }
    }

    for (method_index, body) in methods {
        let mut method = body::Method::new(vec![]);

        if let Some(size) = body.max_stack {
            method.header.maximum_stack_size = size as usize;
        }

        let mut locals = HashMap::new();
        if let Some(loc) = body.locals {
            for (idx, (var_type, name)) in loc.variables.into_iter().enumerate() {
                locals.insert(name, idx);
                method
                    .header
                    .local_variables
                    .push(LocalVariable::new(r#type(var_type, ctx!())));
            }
        }

        let mut arguments = HashMap::new();
        let mut base = 0;
        if resolution[method_index].signature.instance {
            base = 1;
            arguments.insert("this".to_string(), 0);
        }
        for (idx, m) in resolution[method_index]
            .parameter_metadata
            .iter()
            .enumerate()
        {
            arguments.insert(
                m.as_ref().unwrap().name.as_ref().unwrap().to_string(),
                idx + base,
            );
        }

        let (label_vecs, instructions): (Vec<_>, Vec<_>) = body.instructions.into_iter().unzip();
        let labels: HashMap<_, _> = label_vecs
            .into_iter()
            .enumerate()
            .flat_map(|(idx, ls)| ls.into_iter().map(move |l| (l, idx)))
            .collect();

        for instruction in instructions {
            use ast::Instruction::*;
            method.instructions.push(match instruction {
                Add => Instruction::Add,
                Box(t) => Instruction::BoxValue(r#type(t, ctx!())),
                Branch(l) => Instruction::Branch(labels[&l]),
                Call { r#virtual, method } => {
                    let source = method_reference(method, ctx!());
                    if r#virtual {
                        Instruction::call_virtual(source)
                    } else {
                        Instruction::call(source)
                    }
                }
                LoadArgument(a) => Instruction::LoadArgument(arguments[&a] as u16),
                LoadDouble(d) => Instruction::LoadConstantFloat64(d),
                LoadElement(e) => Instruction::load_element(r#type::<MethodType>(e, ctx!())),
                LoadField(f) => Instruction::load_field(field_reference(f, ctx!())),
                LoadFloat(f) => Instruction::LoadConstantFloat32(f),
                LoadInt(i) => Instruction::LoadConstantInt32(i),
                LoadLocal(l) => Instruction::LoadLocal(locals[&l] as u16),
                LoadLong(l) => Instruction::LoadConstantInt64(l),
                LoadString(s) => Instruction::load_string(s),
                New(t, ps) => Instruction::NewObject(method_reference(
                    ast::MethodRef {
                        r#static: false,
                        return_type: None,
                        parent: t,
                        method: ".ctor".to_string(),
                        parameters: ps,
                    },
                    ctx!(),
                )),
                Return => Instruction::Return,
                StoreField(f) => Instruction::store_field(field_reference(f, ctx!())),
                StoreLocal(l) => Instruction::StoreLocal(locals[&l] as u16),
            });
        }

        resolution[method_index].body = Some(method);
    }

    std::fs::write(
        &dll,
        DLL::write(&resolution, false, true).expect("could not assemble .NET module"),
    )
    .expect("could not write output file")
}
