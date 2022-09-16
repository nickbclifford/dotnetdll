mod parse;

fn main() {
    let input_filename = std::env::args()
        .nth(1)
        .expect("missing required input filename");
    let input = std::fs::read_to_string(input_filename).expect("could not open input file");

    match parse::assembly(&input) {
        Ok(a) => println!("{:#?}", a),
        Err(e) => eprintln!("{:?}", e),
    }
}
