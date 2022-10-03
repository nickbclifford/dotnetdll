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
                if $input.as_rule() != Rule::$rule {
                    let (line, col) = $input.as_span().start_pos().line_col();
                    panic!(
                        "expected {:?} but received {:?} at line {}:{}",
                        Rule::$rule,
                        $input.as_rule(),
                        line,
                        col
                    );
                }
                $($body)*
            }
        )*
    };
}

build_rule_parsers! {
    ident(input) -> ast::Ident {
        input.as_str().to_string()
    }
    method_ident(input) -> ast::Ident {
        input.as_str().to_string()
    }
    dotted(input) -> ast::Dotted {
        ast::Dotted(input.as_str().split('.').map(String::from).collect())
    }
    asm_decl(input) -> ast::AssemblySpec {
        asm_spec(input.into_inner().next().unwrap())
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
            "nuint" => NUInt,
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
    type_ref(input) -> ast::TypeRef {
        let mut inner = input.into_inner();
        let first = dotted(inner.next().unwrap());

        // if there is another pair to consume, then the first pair is the parent assembly
        if let Some(pair) = inner.next() {
            ast::TypeRef {
                parent: Some(first),
                target: dotted(pair)
            }
        } else {
            ast::TypeRef {
                parent: None,
                target: first
            }
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
        let mut buf = input.as_str().to_string();
        // remove trailing colon character
        buf.pop();
        buf
    }
    return_type(input) -> Option<ast::ParamType> {
        if input.as_str() == "void" {
            None
        } else {
            Some(param_type(input.into_inner().next().unwrap()))
        }
    }
    method_ref(input) -> ast::MethodRef {
        let r#static = input.as_str().starts_with("static");
        let mut inner = input.into_inner();
        let mut method_name = inner.next().unwrap().into_inner();
        let parameters = inner.many0(Rule::param_type, param_type);
        let return_type = return_type(inner.next().unwrap());
        ast::MethodRef {
            r#static,
            return_type,
            parent: clitype(method_name.next().unwrap()),
            method: method_ident(method_name.next().unwrap()),
            parameters
        }
    }
    field_ref(input) -> ast::FieldRef {
        let mut inner = input.into_inner();
        let return_type = clitype(inner.next().unwrap());
        let mut field_name = inner.next().unwrap().into_inner();
        ast::FieldRef {
            return_type,
            parent: clitype(field_name.next().unwrap()),
            field: ident(field_name.next().unwrap())
        }
    }
    ctor_ref(input) -> (ast::Type, Vec<ast::ParamType>) {
        let mut inner = input.into_inner();
        (clitype(inner.next().unwrap()), inner.many0(Rule::param_type, param_type))
    }
    instruction(input) -> ast::Instruction {
        use ast::Instruction::*;

        fn pop_token(s: &str) -> (&str, &str) {
            match s.find(char::is_whitespace) {
                Some(i) => (&s[..i], s[i + 1..].trim_start()),
                None => (s, ""),
            }
        }
        fn parse_single(rule: Rule, s: &str) -> Pair<Rule> {
            match AssemblyParser::parse(rule, s) {
                Ok(mut ps) => ps.next().unwrap(),
                Err(e) => panic!("failed to parse {:?} in instruction: {}", rule, e),
            }
        }
        macro_rules! single {
            ($rule:ident, $params:expr) => {
                $rule(parse_single(Rule::$rule, $params))
            }
        }

        let (mnemonic, params) = pop_token(input.as_str());
        match mnemonic {
            "add" => Add,
            "box" => Box(single!(clitype, params)),
            "branch" => Branch(single!(ident, params)),
            "call" => if let ("virtual", virt_params) = pop_token(params) {
                Call {
                    r#virtual: true,
                    method: single!(method_ref, virt_params)
                }
            } else {
                Call {
                    r#virtual: false,
                    method: single!(method_ref, params)
                }
            },
            "load" => {
                let (load_type, params) = pop_token(params);
                match load_type {
                    "argument" => LoadArgument(single!(ident, params)),
                    "double" => LoadDouble(params.parse().unwrap()),
                    "element" => LoadElement(single!(clitype, params)),
                    "field" => LoadField(single!(field_ref, params)),
                    "float" => LoadFloat(params.parse().unwrap()),
                    "int" => LoadInt(params.parse().unwrap()),
                    "local" => LoadLocal(single!(ident, params)),
                    "long" => LoadLong(params.parse().unwrap()),
                    "string" => {
                        let mut buf = String::new();
                        let mut arg_iter = params.chars();

                        if arg_iter.next() != Some('"') {
                            panic!("expected string literal");
                        }

                        loop {
                            match arg_iter.next().expect("unterminated string literal") {
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

                        LoadString(buf)
                    }
                    other => panic!("unrecognized load type `{}`", other)
                }
            },
            "new" => {
                let (parent, param_types) = single!(ctor_ref, params);
                New(parent, param_types)
            },
            "return" => Return,
            "store" => {
                let (store_type, params) = pop_token(params);
                match store_type {
                    "field" => StoreField(single!(field_ref, params)),
                    "local" => StoreLocal(single!(ident, params)),
                    other => panic!("unrecognized store type `{}`", other)
                }
            },
            other => panic!("unrecognized instruction mnemonic `{}`", other)
        }
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
        ast::Method {
            name: method_ident(inner.next().unwrap()),
            parameters: inner.many0(Rule::param, |p| {
                let mut inner = p.into_inner();
                (param_type(inner.next().unwrap()), ident(inner.next().unwrap()))
            }),
            return_type: return_type(inner.next().unwrap()),
            attributes: inner.many0(Rule::method_attribute, |p| p.as_str()[1..].to_string()),
            body: inner.maybe(Rule::method_body, method_body),
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
    extends(input) -> ast::TypeRef {
        type_ref(input.into_inner().next().unwrap())
    }
    implements(input) -> Vec<ast::TypeRef> {
        input.into_inner().map(type_ref).collect()
    }
    type_decl(input) -> ast::TypeDeclaration {
        let mut inner = input.into_inner();
        ast::TypeDeclaration {
            kind: type_kind(inner.next().unwrap()),
            name: dotted(inner.next().unwrap()),
            extends: inner.maybe(Rule::extends, extends),
            implements: inner.maybe(Rule::implements, implements),
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

    let assembly_decl = asm_decl(parse.next().unwrap());
    let extern_decls = parse.many0(Rule::extern_decl, |p| {
        asm_spec(p.into_inner().next().unwrap())
    });
    let top_level_decls = parse.many0(Rule::top_level_decl, top_level_decl);

    Ok(ast::Assembly {
        assembly_decl,
        extern_decls,
        top_level_decls,
    })
}
