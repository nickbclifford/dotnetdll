use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;

mod ast;

#[derive(Parser)]
#[grammar = "parse/assembly.pest"]
struct AssemblyParser;

fn ident(input: Pair<Rule>) -> ast::Ident {
    assert_eq!(input.as_rule(), Rule::ident);
    input.as_str().to_string()
}
fn dotted(input: Pair<Rule>) -> ast::Dotted {
    assert_eq!(input.as_rule(), Rule::dotted);
    ast::Dotted(input.into_inner().map(ident).collect())
}

fn asm_spec(input: Pair<Rule>) -> ast::AssemblySpec {
    assert_eq!(input.as_rule(), Rule::asm_spec);
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

fn top_level_decl(input: Pair<Rule>) -> ast::TopLevel {
    assert_eq!(input.as_rule(), Rule::top_level_decl);
    todo!()
}

pub fn assembly(input: &str) -> Result<ast::Assembly, pest::error::Error<Rule>> {
    let mut parse = AssemblyParser::parse(Rule::assembly, input)?;

    let assembly_decl = asm_spec(parse.next().unwrap());
    let mut extern_decls = vec![];
    let mut top_level_decls = vec![];

    for pair in parse {
        match pair.as_rule() {
            Rule::extern_decl => {
                let mut inner = e.into_inner();
                extern_decls.push(asm_spec(inner.next().unwrap()));
            }
            Rule::top_level_decl => {
                top_level_decls.push(top_level_decl(pair));
            }
        }
    }

    Ok(ast::Assembly {
        assembly_decl,
        extern_decls,
        top_level_decls,
    })
}
