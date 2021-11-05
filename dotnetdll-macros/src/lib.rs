use proc_macro::{self, TokenStream};

use syn::parse_macro_input;

mod binary_il;
mod coded;

#[proc_macro]
pub fn instructions(input: TokenStream) -> TokenStream {
    let ins = parse_macro_input!(input);
    binary_il::instructions(ins).into()
}

#[proc_macro]
pub fn coded_index(input: TokenStream) -> TokenStream {
    let idx = parse_macro_input!(input);
    coded::coded_index(idx).into()
}
