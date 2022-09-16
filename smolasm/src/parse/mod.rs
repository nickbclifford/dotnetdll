use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

mod ast;

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
    enum_decl(input) -> ast::Enum {
        todo!()
    }
    type_decl(input) -> ast::TypeDeclaration {
        todo!()
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
    let mut extern_decls = vec![];
    let mut top_level_decls = vec![];

    for pair in parse {
        match pair.as_rule() {
            Rule::extern_decl => {
                let mut inner = pair.into_inner();
                extern_decls.push(asm_spec(inner.next().unwrap()));
            }
            Rule::top_level_decl => {
                top_level_decls.push(top_level_decl(pair));
            }
            _ => unreachable!(),
        }
    }

    Ok(ast::Assembly {
        assembly_decl,
        extern_decls,
        top_level_decls,
    })
}
