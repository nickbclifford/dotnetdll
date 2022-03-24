use proc_macro::{self, TokenStream};

use syn::parse_macro_input;

mod binary_il;
mod coded;
mod constructors;
mod from;
mod resolved_il;

macro_rules! def_macros {
    ($($mod:ident :: $name:ident),+) => {
        $(
            #[proc_macro]
            pub fn $name(input: TokenStream) -> TokenStream {
                let input = parse_macro_input!(input);
                $mod::$name(input).into()
            }
        )+
    }
}

def_macros! {
    binary_il::instructions,
    coded::coded_index,
    constructors::msig,
    constructors::type_name,
    constructors::type_ref,
    constructors::method_ref,
    constructors::field_ref,
    resolved_il::r_instructions
}

// derive macro
#[proc_macro_derive(From, attributes(nested))]
pub fn derive_from(input: TokenStream) -> TokenStream {
    let derive = parse_macro_input!(input);
    from::derive_from(derive).into()
}

// requires a reference for implementation reasons
#[proc_macro]
pub fn ctype(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input);
    constructors::ctype(&input).into()
}
