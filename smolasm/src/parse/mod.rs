use combinators::Combinators;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

mod ast;
mod combinators;

#[derive(Parser)]
#[grammar = "parse/assembly.pest"]
struct AssemblyParser;

macro_rules! build_rule_parsers {
    ($( $rule:ident($input:ident) -> $t:ty { $($body:tt)* } )*) => {
        $(
            fn $rule($input: Pair<Rule>) -> $t {
                assert_eq!($input.as_rule(), Rule::$rule);
                $($body)*
            }
        )*
    };
}

build_rule_parsers! {
    ident(input) -> ast::Ident {
        input.as_str().to_string()
    }
    dotted(input) -> ast::Dotted {
        ast::Dotted(input.into_inner().map(ident).collect())
    }
    asm_spec(input) -> ast::AssemblySpec {
        let mut inner = input.into_inner();
        ast::AssemblySpec {
            assembly: dotted(inner.next().unwrap()),
            version: inner.next().map(|v| {
                ast::Version(
                    v.into_inner().map(|p| p.as_str().parse().unwrap()).collect()
                )
            }),
        }
    }
    int_type(input) -> ast::IntType {
        use ast::IntType::*;
        match input.as_str() {
            "bool" => Bool,
            "char" => Char,
            "sbyte" => SByte,
            "byte" => Byte,
            "short" => Short,
            "ushort" => UShort,
            "int" => Int,
            "uint" => UInt,
            "long" => Long,
            "ulong" => ULong,
            "nint" => NInt,
            "nuint" => NUInt
            _ => unreachable!()
        }
    }
    enum_decl(input) -> ast::Enum {
        let mut inner = input.into_inner();
        ast::Enum {
            base: inner.maybe(Rule::int_type, int_type),
            name: dotted(inner.next().unwrap()),
            members: inner.map(ident).collect()
        }
    }
    type_kind(input) -> ast::TypeKind {
        use ast::TypeKind::*;
        match input.as_str() {
            "struct" => Struct,
            "interface" => Interface,
            other => Class { r#abstract: other.starts_with("abstract") }
        }
    }
    type_ref(input) -> ast::TypeReference {
        let mut inner = input.into_inner();
        ast::TypeReference {
            parent: inner.maybe(Rule::dotted, dotted),
            target: dotted(inner.next().unwrap())
        }
    }
    clitype(input) -> ast::Type {
        use ast::Type::*;
        match input.as_str() {
            "string" => String,
            "object" => Object,
            "float" => Float,
            "double" => Double,
            _ => {
                let valuetype = input.as_str().starts_with("valuetype");
                let pair = input.into_inner().next().unwrap();
                match pair.as_rule() {
                    Rule::int_type => Integer(int_type(pair)),
                    Rule::vector => Vector(Box::new(clitype(pair.into_inner().next().unwrap()))),
                    Rule::type_ref => if valuetype {
                        ValueType(type_ref(pair))
                    } else {
                        RefType(type_ref(pair))
                    },
                    Rule::pointer => Pointer({
                        let inner = pair.into_inner().next().unwrap();
                        if inner.as_rule() == Rule::void_ptr {
                            None
                        } else {
                            Some(Box::new(clitype(inner)))
                        }
                    }),
                    _ => unreachable!()
                }
            }
        }
    }
    access(input) -> ast::Access {
        use ast::Access::*;
        match input.as_str() {
            "public" => Public,
            "internal" => Internal,
            s if s.starts_with("private") => if s.ends_with("protected") {
                PrivateProtected
            } else {
                Private
            },
            s if s.starts_with("protected") => if s.ends_with("internal") {
                ProtectedInternal
            } else {
                Protected
            },
            _ => unreachable!()
        }
    }
    field(input) -> ast::Field {
        let mut inner = input.into_inner();
        ast::Field(clitype(inner.next().unwrap()), ident(inner.next().unwrap()))
    }
    param_type(input) -> ast::ParamType {
        ast::ParamType {
            r#ref: input.as_str().starts_with("ref"),
            r#type: clitype(input.into_inner().next().unwrap())
        }
    }
    locals(input) -> ast::Locals {
        ast::Locals {
            init: input.as_str().starts_with("init"),
            variables: input.into_inner().map(|p| {
                let mut inner = p.into_inner();
                (clitype(inner.next().unwrap()), ident(inner.next().unwrap()))
            }).collect()
        }
    }
    label(input) -> ast::Label {
        ident(input.into_inner().next().unwrap())
    }
    instruction(input) -> ast::Instruction {
        todo!()
    }
    method_body(input) -> ast::MethodBody {
        let mut inner = input.into_inner();

        let max_stack = inner.maybe(Rule::nat, |p| p.as_str().parse().unwrap());
        let locals = inner.maybe(Rule::locals, locals);

        let mut instructions = vec![];
        let mut next_labels = vec![];

        for pair in inner {
            match pair.as_rule() {
                Rule::label => {
                    next_labels.push(label(pair));
                }
                Rule::instruction => {
                    instructions.push((next_labels, instruction(pair)));
                    next_labels = vec![];
                }
                _ => unreachable!()
            }
        }

        ast::MethodBody {
            max_stack,
            locals,
            instructions
        }
    }
    method(input) -> ast::Method {
        let mut inner = input.into_inner();
        let name = ident(inner.next().unwrap());
        let parameters = inner.many0(Rule::param, |p| {
            let mut inner = p.into_inner();
            (param_type(inner.next().unwrap()), ident(inner.next().unwrap()))
        });
        let return_type = inner.next().unwrap();

        // TODO
        let attributes = inner.many0(Rule::method_attribute, |p| ());

        ast::Method {
            name,
            parameters,
            return_type: if return_type.as_str() == "void" {
                None
            } else {
                Some(param_type(return_type.into_inner().next().unwrap()))
            },
            body: inner.maybe(Rule::method_body, method_body)
        }
    }
    semantic_method(input) -> ast::SemanticMethod {
        let mut inner = input.into_inner();
        ast::SemanticMethod(ident(inner.next().unwrap()), method_body(inner.next().unwrap()))
    }
    property(input) -> ast::Property {
        let mut inner = input.into_inner();
        ast::Property {
            r#type: clitype(inner.next().unwrap()),
            name: ident(inner.next().unwrap()),
            methods: inner.many0(Rule::semantic_method, semantic_method)
        }
    }
    event(input) -> ast::Event {
        let mut inner = input.into_inner();
        ast::Event {
            r#type: clitype(inner.next().unwrap()),
            name: ident(inner.next().unwrap()),
            methods: inner.many0(Rule::event, semantic_method)
        }
    }
    type_item(input) -> ast::TypeItem {
        let mut inner = input.into_inner();

        let access = access(inner.next().unwrap());
        let r#static = inner.maybe(Rule::static_member, |_| ()).is_some();
        let item = inner.next().unwrap();

        use ast::TypeItemKind::*;
        ast::TypeItem {
            access,
            r#static,
            kind: match item.as_rule() {
                Rule::field => Field(field(item)),
                Rule::property => Property(property(item)),
                Rule::method => Method(method(item)),
                Rule::event => Event(event(item)),
                _ => unreachable!()
            }
        }
    }
    type_decl(input) -> ast::TypeDeclaration {
        let mut inner = input.into_inner();
        ast::TypeDeclaration {
            kind: type_kind(inner.next().unwrap()),
            name: dotted(inner.next().unwrap()),
            extends: inner.maybe(Rule::extends, type_ref),
            implements: inner.maybe(Rule::implements, |p| p.into_inner().map(type_ref).collect()),
            items: inner.map(type_item).collect()
        }
    }
    top_level_decl(input) -> ast::TopLevel {
        let public = input.as_str().starts_with("public");
        let inner = input.into_inner().next().unwrap();

        use ast::TopLevelKind::*;
        ast::TopLevel {
            public,
            kind: match inner.as_rule() {
                Rule::enum_decl => Enum(enum_decl(inner)),
                Rule::type_decl => Type(type_decl(inner)),
                _ => unreachable!(),
            },
        }
    }
}

pub fn assembly(input: &str) -> Result<ast::Assembly, pest::error::Error<Rule>> {
    let mut parse = AssemblyParser::parse(Rule::assembly, input)?;

    let assembly_decl = asm_spec(parse.next().unwrap());
    let mut extern_decls = parse.many0(Rule::extern_decl, |p| {
        asm_spec(p.into_inner().next().unwrap())
    });
    let mut top_level_decls = parse.map(top_level_decl).collect();

    Ok(ast::Assembly {
        assembly_decl,
        extern_decls,
        top_level_decls,
    })
}
