use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Meta, NestedMeta};

pub fn derive_from(input: DeriveInput) -> TokenStream {
    let type_name = input.ident;
    let variants = match input.data {
        Data::Enum(e) => e.variants,
        _ => panic!("derive(Into) is only valid for enums"),
    };
    let generics = input.generics;

    let impls = variants.into_iter().filter_map(|v| {
        let name = v.ident;
        let (attrs, field) = match &v.fields {
            Fields::Unnamed(f) => {
                let field = f.unnamed.first()?;
                (&field.attrs, &field.ty)
            }
            _ => return None,
        };
        let mut nested = vec![];
        for a in attrs {
            match a.parse_meta() {
                Ok(Meta::List(l)) if l.path.is_ident("nested") => {
                    for variant in l.nested {
                        if let NestedMeta::Meta(m) = variant {
                            nested.push(quote! {
                                impl#generics From<#m> for #type_name#generics {
                                    fn from(m: #m) -> Self {
                                        Self::#name(m.into())
                                    }
                                }
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        Some(quote! {
            #(#nested)*
            impl#generics From<#field> for #type_name#generics {
                fn from(f: #field) -> Self {
                    Self::#name(f)
                }
            }
        })
    });

    quote! { #(#impls)* }
}
