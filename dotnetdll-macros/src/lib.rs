use proc_macro::{self, TokenStream};

use syn::parse_macro_input;

mod binary_il;
mod coded;
mod from;
mod types;

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

#[proc_macro_derive(From, attributes(nested))]
pub fn derive_from(input: TokenStream) -> TokenStream {
    let derive = parse_macro_input!(input);
    from::derive_from(derive).into()
}

#[proc_macro]
pub fn ctype(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input);
    types::ctype(&input).into()
}

#[proc_macro]
pub fn msig(input: TokenStream) -> TokenStream {
    let sig = parse_macro_input!(input);
    types::msig(sig).into()
}
