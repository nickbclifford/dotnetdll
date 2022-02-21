use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "assembly.pest"]
pub struct AssemblyParser;

fn main() {
    match AssemblyParser::parse(Rule::assembly, include_str!("test.il")) {
        Ok(a) => println!("{:?}", a),
        Err(e) => eprintln!("{}", e)
    }
}
