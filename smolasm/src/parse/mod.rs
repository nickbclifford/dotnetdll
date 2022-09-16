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
                    v.as_str()[1..]
                        .split('.')
                        .map(|n| n.parse().unwrap())
                        .collect(),
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
        todo!()
    }
    type_item(input) -> ast::TypeItem {
        todo!()
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

        ast::TopLevel {
            public,
            kind: match inner.as_rule() {
                Rule::enum_decl => ast::TopLevelKind::Enum(enum_decl(inner)),
                Rule::type_decl => ast::TopLevelKind::Type(type_decl(inner)),
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
