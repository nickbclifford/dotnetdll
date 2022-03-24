use debug_cell::RefCell;
use dotnetdll::resolved::members::FieldSource;
use dotnetdll::{
    dll::DLL,
    resolution::{AssemblyRefIndex, EntryPoint, Resolution},
    resolved::{
        assembly::{Assembly, ExternalAssemblyReference, Version},
        body,
        il::*,
        members::{Constant, Field, Property},
        members::{
            Event, ExternalFieldReference, ExternalMethodReference, FieldReferenceParent, Method,
            MethodReferenceParent, ParameterMetadata, UserMethod,
        },
        module::Module,
        signature::ManagedMethod,
        signature::{msig, MethodSignature, Parameter, ParameterType, ReturnType},
        types::{
            Accessibility as TAccess, BaseType, ExternalTypeReference, LocalVariable, MemberType, MethodType,
            ResolutionScope, TypeDefinition, TypeSource, UserType, ValueKind,
        },
        Accessibility,
    },
};
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use std::borrow::Cow;
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

fn dotted(s: &str) -> (Option<Cow<str>>, Cow<str>) {
    match s.rfind('.') {
        Some(i) => (Some(s[..i].into()), s[i + 1..].into()),
        None => (None, s.into()),
    }
}

fn int_type<T>(t: &str) -> BaseType<T> {
    use BaseType::*;
    match t {
        "bool" => Boolean,
        "char" => Char,
        "sbyte" => Int8,
        "byte" => UInt8,
        "short" => Int16,
        "ushort" => UInt16,
        "int" => Int32,
        "uint" => UInt32,
        "long" => Int64,
        "ulong" => UInt64,
        "nint" => IntPtr,
        "nuint" => UIntPtr,
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

fn access(s: &str) -> Accessibility {
    use Accessibility::*;
    let mut iter = s.split_whitespace();
    match iter.next().unwrap() {
        "public" => Public,
        "private" => {
            if iter.next().is_some() {
                // private protected
                FamilyANDAssembly
            } else {
                Private
            }
        }
        "protected" => {
            if iter.next().is_some() {
                // protected internal
                FamilyORAssembly
            } else {
                Family
            }
        }
        "internal" => Assembly,
        _ => unreachable!(),
    }
}

fn pop_token(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i + 1..].trim_start()),
        None => (s, ""),
    }
}

fn main() {
    let input_filename = std::env::args().nth(1).expect("missing required input filename");
    let input = std::fs::read_to_string(input_filename).expect("could not open input file");

    let mut pairs = match AssemblyParser::parse(Rule::assembly, &input) {
        Ok(a) => a,
        Err(e) => panic!("{}", e),
    };

    let asm_decl = pairs.next().unwrap();
    let (assembly_name, version) = asm_spec(asm_decl);

    let module_name: Cow<_> = format!("{}.dll", assembly_name).into();
    let res = RefCell::new(Resolution::new(Module::new(module_name.clone())));
    let mut assembly = Assembly::new(assembly_name.into());
    assembly.version = version;
    res.borrow_mut().assembly = Some(assembly);

    res.borrow_mut()
        .type_definitions
        .push(TypeDefinition::new(None, "<Module>".into()));

    let mut extern_map = HashMap::new();
    while matches!(pairs.peek(), Some(p) if p.as_rule() == Rule::extern_decl) {
        let (name, version) = asm_spec(pairs.next().unwrap());
        let mut asm_ref = ExternalAssemblyReference::new(name.into());
        asm_ref.version = version;
        extern_map.insert(name, res.borrow_mut().push_assembly_reference(asm_ref));
    }

    // we always need an mscorlib reference, insert a default one if the user didn't specify a version
    let mscorlib = *extern_map.entry("mscorlib").or_insert_with(|| {
        res.borrow_mut()
            .push_assembly_reference(ExternalAssemblyReference::new("mscorlib".into()))
    });

    let ref_map: RefCell<HashMap<(AssemblyRefIndex, &str), _>> = RefCell::new(HashMap::new());

    let get_ref = |a, t| {
        *ref_map.borrow_mut().entry((a, t)).or_insert_with(|| {
            let (namespace, name) = dotted(t);
            res.borrow_mut().push_type_reference(ExternalTypeReference::new(
                namespace,
                name,
                ResolutionScope::Assembly(a),
            ))
        })
    };

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

        let type_def = res
            .borrow_mut()
            .push_type_definition(TypeDefinition::new(namespace, name));
        types.insert(typename, type_def);

        res.borrow_mut()[type_def].flags.accessibility = access;
        kinds.push((type_def, kind));
    }

    let user_type = |p| {
        let (asm, name) = type_ref(p);
        match asm {
            Some(a) => UserType::from(get_ref(extern_map[a], name)),
            None => UserType::from(types[name]),
        }
    };

    fn clitype<'i, T: From<BaseType<T>>>(p: Pair<'i, Rule>, user_type: impl Fn(Pair<'i, Rule>) -> UserType) -> T {
        match p.as_str() {
            "string" => BaseType::String,
            "object" => BaseType::Object,
            "float" => BaseType::Float32,
            "double" => BaseType::Float64,
            _ => {
                let is_valuetype = p.as_str().starts_with("valuetype");
                let inner = p.into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::int_type => int_type(inner.as_str()),
                    Rule::type_ref => BaseType::Type {
                        value_kind: if is_valuetype {
                            ValueKind::ValueType
                        } else {
                            ValueKind::Class
                        },
                        source: user_type(inner).into(),
                    },
                    Rule::vector => BaseType::vector(clitype(inner.into_inner().next().unwrap(), user_type)),
                    Rule::pointer => {
                        if inner.as_str() == "*void" {
                            BaseType::VOID_PTR
                        } else {
                            BaseType::pointer(clitype(inner, user_type))
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
        .into()
    }
    macro_rules! clitype {
        ($e:expr) => {
            clitype($e, user_type)
        };
    }

    fn param_types<'i>(params: Vec<Pair<'i, Rule>>, user_type: impl Fn(Pair<'i, Rule>) -> UserType) -> Vec<Parameter> {
        params
            .into_iter()
            .map(|p| {
                let is_ref = p.as_str().starts_with("ref");
                let clitype = clitype(p.into_inner().next().unwrap(), &user_type);

                Parameter::new(if is_ref {
                    ParameterType::Ref(clitype)
                } else {
                    ParameterType::Value(clitype)
                })
            })
            .collect()
    }

    fn method_signature<'i>(
        is_static: bool,
        return_type: Pair<'i, Rule>,
        params: Vec<Pair<'i, Rule>>,
        user_type: impl Fn(Pair<'i, Rule>) -> UserType,
    ) -> ManagedMethod {
        MethodSignature::new(
            !is_static,
            if return_type.as_str().starts_with("void") {
                ReturnType::VOID
            } else {
                ReturnType::new(ParameterType::Value(clitype(return_type, &user_type)))
            },
            param_types(params, user_type),
        )
    }
    let method_signature = |i, r, p| method_signature(i, r, p, user_type);

    let mut methods = vec![];

    // now start processing top-level bodies
    for (type_def, kind) in kinds {
        match kind {
            TypeKind::Enum { raw_type, idents, .. } => {
                res.borrow_mut()[type_def].flags.sealed = true;
                res.borrow_mut()[type_def].extends = Some(get_ref(mscorlib, "System.Enum").into());
                let mut value_field = Field::instance(
                    Accessibility::Public,
                    "value__".into(),
                    match raw_type {
                        Some(s) => int_type(s),
                        None => BaseType::Int32,
                    }
                    .into(),
                );
                value_field.special_name = true;
                value_field.runtime_special_name = true;
                res.borrow_mut()[type_def].fields.push(value_field);
                for (idx, i) in idents.into_iter().enumerate() {
                    let mut field = Field::instance(
                        Accessibility::Public,
                        i.into(),
                        BaseType::Type {
                            value_kind: ValueKind::ValueType,
                            source: type_def.into(),
                        }
                        .into(),
                    );
                    field.static_member = true;
                    field.literal = true;
                    // TODO: native ints
                    field.default = Some(match raw_type.unwrap_or("int") {
                        "bool" => Constant::Boolean(idx == 1),
                        "char" => Constant::Char(idx.try_into().unwrap()),
                        "sbyte" => Constant::Int8(idx.try_into().unwrap()),
                        "byte" => Constant::UInt8(idx.try_into().unwrap()),
                        "short" => Constant::Int16(idx.try_into().unwrap()),
                        "ushort" => Constant::UInt16(idx.try_into().unwrap()),
                        "int" => Constant::Int32(idx.try_into().unwrap()),
                        "uint" => Constant::UInt32(idx.try_into().unwrap()),
                        "long" => Constant::Int64(idx.try_into().unwrap()),
                        "ulong" => Constant::UInt64(idx.try_into().unwrap()),
                        _ => unreachable!(),
                    });
                    res.borrow_mut()[type_def].fields.push(field);
                }
            }
            TypeKind::Class {
                kind,
                extends,
                implements,
                items,
                name,
            } => {
                let is_abstract = kind.starts_with("abstract") || kind == "interface";
                res.borrow_mut()[type_def].flags.abstract_type = is_abstract;

                res.borrow_mut()[type_def].extends = if let Some(e) = extends {
                    Some(user_type(e).into())
                } else if kind != "interface" {
                    Some(
                        get_ref(
                            mscorlib,
                            if kind == "struct" {
                                "System.ValueType"
                            } else {
                                "System.Object"
                            },
                        )
                        .into(),
                    )
                } else {
                    None
                };

                if let Some(i) = implements {
                    for p in i.into_inner() {
                        let val = (vec![], user_type(p).into());
                        res.borrow_mut()[type_def].implements.push(val)
                    }
                }

                for type_item in items {
                    let mut inner = type_item.into_inner();
                    let accessibility = access(inner.next().unwrap().as_str());
                    let is_static = matches!(inner.peek(), Some(p) if p.as_rule() == Rule::static_member);
                    if is_static {
                        inner.next();
                    }
                    let pair = inner.next().unwrap();
                    let rule = pair.as_rule();
                    let mut inner = pair.into_inner();

                    match rule {
                        Rule::field => {
                            let field_type = inner.next().unwrap();
                            let ident = inner.next().unwrap();

                            let mut field = Field::instance(accessibility, ident.as_str().into(), clitype!(field_type));
                            field.static_member = is_static;
                            res.borrow_mut()[type_def].fields.push(field);
                        }
                        Rule::property => {
                            let prop_type = inner.next().unwrap();
                            let ident = inner.next().unwrap();

                            let property_type: MethodType = clitype!(prop_type);

                            for sem_method in inner {
                                let mut inner = sem_method.into_inner();
                                let semantic = inner.next().unwrap().as_str();
                                let body = inner.next().unwrap();

                                let t = property_type.clone();

                                let mut sig = match semantic {
                                    "get" => msig! { #t () },
                                    "set" => msig! { void (#t) },
                                    other => panic!("invalid property method semantic {}", other),
                                };
                                sig.instance = !is_static;

                                let name = format!("{}_{}", semantic, ident.as_str()).into();
                                let mut method = Method::new(accessibility, sig, name, None);
                                if semantic == "set" {
                                    method
                                        .parameter_metadata
                                        .push(Some(ParameterMetadata::name("value".into())));
                                }
                                methods.push((res.borrow_mut().push_method(type_def, method), body));
                            }

                            res.borrow_mut()[type_def].properties.push(Property::new(
                                ident.as_str().into(),
                                Parameter::new(ParameterType::Value(property_type)),
                            ));
                        }
                        Rule::method => {
                            let ident = inner.next().unwrap();
                            let mut rest: Vec<_> = inner.collect();

                            let mut pop_optional = |rule| {
                                if matches!(&rest[..], [.., last] if last.as_rule() == rule) {
                                    Some(rest.pop().unwrap())
                                } else {
                                    None
                                }
                            };

                            let body = pop_optional(Rule::method_body);
                            if body.is_none() && !is_abstract {
                                panic!(
                                    "method {} cannot have no body in non-abstract class {}",
                                    ident.as_str(),
                                    name
                                );
                            }

                            let rt_special_name = pop_optional(Rule::rt_special_name).is_some();
                            let special_name = pop_optional(Rule::special_name).is_some();
                            let is_entrypoint = pop_optional(Rule::entry_point).is_some();
                            let is_virtual = pop_optional(Rule::virtual_member).is_some();

                            let return_type = rest.pop().unwrap();

                            let (param_types, param_names): (Vec<_>, Vec<_>) = rest
                                .into_iter()
                                .map(|r| {
                                    let mut iter = r.into_inner();
                                    (iter.next().unwrap(), iter.next().unwrap())
                                })
                                .unzip();

                            let sig = method_signature(is_static, return_type, param_types);

                            let mut method = Method::new(accessibility, sig, ident.as_str().into(), None);
                            method.parameter_metadata = param_names
                                .into_iter()
                                .map(|i| Some(ParameterMetadata::name(i.as_str().into())))
                                .collect();
                            method.abstract_member = body.is_none();
                            method.special_name = special_name;
                            method.runtime_special_name = rt_special_name;
                            method.virtual_member = is_virtual;

                            let idx = res.borrow_mut().push_method(type_def, method);
                            if is_entrypoint {
                                res.borrow_mut().entry_point = Some(EntryPoint::Method(idx));
                            }
                            if let Some(b) = body {
                                methods.push((idx, b));
                            }
                        }
                        Rule::event => {
                            let event_type = inner.next().unwrap();
                            let ident = inner.next().unwrap();

                            let property_type: MemberType = clitype!(event_type);

                            let mut add = None;
                            let mut remove = None;
                            for sem_method in inner {
                                let mut inner = sem_method.into_inner();
                                let semantic = inner.next().unwrap().as_str();
                                let body = inner.next().unwrap();

                                let t = property_type.clone().into();
                                let mut sig = msig! { void (#t) };
                                sig.instance = !is_static;

                                let name = format!("{}_{}", semantic, ident.as_str()).into();
                                let mut method = Method::new(accessibility, sig.clone(), name, None);
                                method
                                    .parameter_metadata
                                    .push(Some(ParameterMetadata::name("value".into())));
                                let pair = Some((method, body));

                                match semantic {
                                    "add" => {
                                        add = pair;
                                    }
                                    "remove" => {
                                        remove = pair;
                                    }
                                    other => panic!("invalid event method semantic {}", other),
                                }
                            }

                            let (add_m, add_b) =
                                add.unwrap_or_else(|| panic!("missing add method on event {}", ident.as_str()));
                            let (remove_m, remove_b) =
                                remove.unwrap_or_else(|| panic!("missing remove method on event {}", ident.as_str()));

                            let event = Event::new(ident.as_str().into(), property_type, add_m, remove_m);
                            let event_idx = res.borrow_mut().push_event(type_def, event);
                            methods.push((res.borrow().event_add_index(event_idx), add_b));
                            methods.push((res.borrow().event_remove_index(event_idx), remove_b));
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    for (idx, body) in methods {
        let mut params = HashMap::new();

        {
            let method = &mut res.borrow_mut()[idx];

            for (idx, p) in method.parameter_metadata.iter().enumerate() {
                params.insert(
                    p.as_ref().unwrap().name.to_string(),
                    if method.signature.instance { idx + 1 } else { idx } as u16,
                );
            }
        }

        if res.borrow_mut()[idx].signature.instance {
            params.insert("this".to_string(), 0);
        }

        let mut inner = body.into_inner();

        let maximum_stack_size: usize = if matches!(inner.peek(), Some(p) if p.as_rule() == Rule::nat) {
            inner.next().unwrap().as_str().parse().unwrap()
        } else {
            8
        };

        let mut local_idxs = HashMap::new();

        let (initialize_locals, local_variables) = if matches!(inner.peek(), Some(p) if p.as_rule() == Rule::locals) {
            let locals = inner.next().unwrap();
            (
                locals.as_str().starts_with("init"),
                locals
                    .into_inner()
                    .enumerate()
                    .map(|(idx, l)| {
                        let mut inner = l.into_inner();
                        let var_type = clitype!(inner.next().unwrap());

                        let name = inner.next().unwrap().as_str();
                        local_idxs.insert(name, idx as u16);

                        LocalVariable::new(var_type)
                    })
                    .collect(),
            )
        } else {
            (false, vec![])
        };

        let mut instructions = vec![];
        let mut instruction_counter = 0;
        let mut labels = HashMap::new();

        let mut instr_pairs = vec![];

        for pair in inner {
            let line = pair.as_str().trim_end();

            if pair.as_rule() == Rule::label {
                // strip off the ending colon
                labels.insert(&line[..line.len() - 1], instruction_counter);
            } else {
                instr_pairs.push(pair);
                instruction_counter += 1;
            }
        }

        for pair in instr_pairs {
            if pair.as_rule() != Rule::instruction {
                continue;
            }

            let (mnemonic, mut instr_params) = pop_token(pair.as_str().trim_end());

            fn parse_single(rule: Rule, s: &str) -> Pair<Rule> {
                match AssemblyParser::parse(rule, s) {
                    Ok(mut ps) => ps.next().unwrap(),
                    Err(e) => panic!("failed to parse {:?}: {}", rule, e),
                }
            }

            macro_rules! defined_here {
                (match $t:ident { $def:ident => $def_e:expr, _ => $else:expr, }) => {
                    match $t.as_base() {
                        Some(BaseType::Type {
                            source: TypeSource::User(UserType::Definition($def)),
                            ..
                        }) => $def_e,
                        _ => $else,
                    }
                };
            }

            let field_source = |input| {
                let field_ref = parse_single(Rule::field_ref, input);
                let mut iter = field_ref.into_inner();

                let field_type = clitype!(iter.next().unwrap());

                let mut name_iter = iter.next().unwrap().into_inner();
                let parent: MethodType = clitype!(name_iter.next().unwrap());
                let name = name_iter.next().unwrap().as_str();

                defined_here!(match parent {
                    def => FieldSource::Definition(
                        res.borrow()
                            .enumerate_fields(*def)
                            .find(|(_, f)| f.name == name && f.return_type == field_type)
                            .unwrap_or_else(|| panic!(
                                "could not find field {} on type {}",
                                name,
                                res.borrow()[*def].name
                            ))
                            .0
                    ),
                    _ => FieldSource::Reference({
                        let found_ref = {
                            let res_b = res.borrow();
                            let x = res_b
                                .enumerate_field_references()
                                .find(|(_, r)| {
                                    matches!(&r.parent, FieldReferenceParent::Type(p) if p == &parent)
                                        && r.name == name
                                        && r.field_type == field_type
                                })
                                .map(|(i, _)| i);
                            x
                        };

                        match found_ref {
                            Some(i) => i,
                            None => res.borrow_mut().push_field_reference(ExternalFieldReference::new(
                                FieldReferenceParent::Type(parent),
                                field_type,
                                name.into(),
                            )),
                        }
                    }),
                })
            };

            let user_method = |parent, method_name, sig| {
                let parent: MethodType = parent;
                defined_here!(match parent {
                    d => UserMethod::Definition(
                        res.borrow()
                            .enumerate_methods(*d)
                            .find(|(_, m)| m.name == method_name && m.signature == sig)
                            .unwrap_or_else(|| {
                                panic!(
                                    "could not find method {} on type {}",
                                    method_name,
                                    res.borrow()[*d].name
                                )
                            })
                            .0,
                    ),
                    _ => UserMethod::Reference({
                        let found_ref = {
                            let res_b = res.borrow();
                            let x = res_b
                                .enumerate_method_references()
                                .find(|(_, r)| {
                                    matches!(&r.parent, MethodReferenceParent::Type(t) if t == &parent)
                                        && r.name == method_name
                                        && r.signature == sig
                                })
                                .map(|(i, _)| i);
                            x
                        };

                        match found_ref {
                            Some(i) => i,
                            None => res.borrow_mut().push_method_reference(ExternalMethodReference::new(
                                MethodReferenceParent::Type(parent),
                                method_name,
                                sig,
                            )),
                        }
                    }),
                })
            };

            instructions.push(match mnemonic {
                "return" => Instruction::Return,
                "load" => {
                    let (kind, rest) = pop_token(instr_params);

                    match kind {
                        "int" => Instruction::LoadConstantInt32(rest.parse().unwrap()),
                        "long" => Instruction::LoadConstantInt64(rest.parse().unwrap()),
                        "float" => Instruction::LoadConstantFloat32(rest.parse().unwrap()),
                        "double" => Instruction::LoadConstantFloat64(rest.parse().unwrap()),
                        "string" => {
                            let mut buf = String::new();
                            let mut arg_iter = rest.chars();

                            if arg_iter.next() != Some('"') {
                                panic!("expected string literal");
                            }

                            loop {
                                let c = arg_iter.next().expect("unterminated string literal");
                                match c {
                                    '"' => break,
                                    '\\' => buf.push(match arg_iter.next().expect("bad escape sequence") {
                                        '\\' => '\\',
                                        '"' => '"',
                                        'n' => '\n',
                                        't' => '\t',
                                        other => panic!("unknown escape sequence \\{}", other),
                                    }),
                                    other => buf.push(other),
                                }
                            }

                            Instruction::LoadString(buf.encode_utf16().collect())
                        }
                        "argument" => Instruction::LoadArgument(
                            *params.get(rest).unwrap_or_else(|| panic!("unknown argument {}", rest)),
                        ),
                        "local" => Instruction::LoadLocal(
                            *local_idxs
                                .get(rest)
                                .unwrap_or_else(|| panic!("unknown local variable {}", rest)),
                        ),
                        "field" => Instruction::load_field(field_source(rest)),
                        "static" => {
                            let (k, rest) = pop_token(rest);
                            if k != "field" {
                                panic!("the only static members that can be loaded are fields");
                            }

                            Instruction::load_static_field(field_source(rest))
                        }
                        "element" => {
                            let m: MethodType = clitype!(parse_single(Rule::clitype, rest));
                            Instruction::load_element(m)
                        }
                        unknown => panic!("unknown load kind {}", unknown),
                    }
                }
                "store" => {
                    let (kind, rest) = pop_token(instr_params);

                    match kind {
                        "local" => Instruction::StoreLocal(
                            *local_idxs
                                .get(rest)
                                .unwrap_or_else(|| panic!("unknown local variable {}", rest)),
                        ),
                        "field" => Instruction::store_field(field_source(rest)),
                        "static" => {
                            let (k, rest) = pop_token(rest);
                            if k != "field" {
                                panic!("the only static members that can be stored are fields");
                            }

                            Instruction::store_static_field(field_source(rest))
                        }
                        unknown => panic!("unknown store kind {}", unknown),
                    }
                }
                "branch" => Instruction::Branch(
                    *labels
                        .get(instr_params)
                        .unwrap_or_else(|| panic!("unknown label {}", instr_params)),
                ),
                "box" => Instruction::BoxValue(clitype!(parse_single(Rule::clitype, instr_params))),
                "call" => {
                    let (v, params) = pop_token(instr_params);
                    let is_virtual = v == "virtual";
                    if is_virtual {
                        instr_params = params;
                    }

                    let method_ref = parse_single(Rule::method_ref, instr_params);
                    let is_static = method_ref.as_str().starts_with("static");
                    let mut iter = method_ref.into_inner();

                    let mut name_iter = iter.next().unwrap().into_inner();
                    let parent: MethodType = clitype!(name_iter.next().unwrap());
                    let method_name = name_iter.next().unwrap().as_str();

                    let mut params: Vec<_> = iter.collect();
                    let return_type = params.pop().unwrap();

                    let sig = method_signature(is_static, return_type, params);

                    let method = user_method(parent, method_name.into(), sig);

                    if is_virtual {
                        Instruction::call_virtual(method)
                    } else {
                        Instruction::call(method)
                    }
                }
                "add" => Instruction::Add,
                "new" => Instruction::NewObject({
                    let ctor_ref = parse_single(Rule::ctor_ref, instr_params);
                    let mut iter = ctor_ref.into_inner();

                    let parent: MethodType = clitype!(iter.next().unwrap());
                    let sig = MethodSignature::new(true, ReturnType::VOID, param_types(iter.collect(), user_type));

                    let method = user_method(parent, ".ctor".into(), sig);
                    if let UserMethod::Definition(m) = &method {
                        let def = &res.borrow()[*m];
                        if !(def.special_name && def.runtime_special_name) {
                            panic!("constructor must have specialname and rtspecialname flags defined");
                        }
                    }

                    method
                }),
                unknown => panic!("unknown instruction {}", unknown),
            });
        }

        res.borrow_mut()[idx].body = Some(body::Method {
            header: body::Header {
                initialize_locals,
                maximum_stack_size,
                local_variables,
            },
            instructions,
            data_sections: vec![],
        });
    }

    let written = DLL::write(&res.into_inner(), false, true).unwrap();

    std::fs::write(&module_name.as_ref(), &written).unwrap();

    println!("wrote {}", module_name);
}
