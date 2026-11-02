use proc_macro2::TokenStream;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{Data, DeriveInput, Error, Fields, Path, Result, Token};

pub fn derive_from(input: DeriveInput) -> Result<TokenStream> {
    let type_name = input.ident;
    let generics = input.generics;
    let variants = match input.data {
        Data::Enum(e) => e.variants,
        _ => return Err(Error::new(type_name.span(), "derive(From) is only valid for enums")),
    };

    let mut impls = TokenStream::new();

    for variant in variants {
        let name = &variant.ident;

        let field = match &variant.fields {
            Fields::Unnamed(f) => match f.unnamed.first() {
                Some(field) => field,
                None => continue,
            },
            _ => continue,
        };
        let ty = &field.ty;

        for attr in field.attrs.iter().filter(|a| a.path().is_ident("nested")) {
            for path in attr.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)? {
                impls.extend(quote! {
                    impl #generics From<#path> for #type_name #generics {
                        fn from(m: #path) -> Self {
                            Self::#name(m.into())
                        }
                    }
                });
            }
        }

        impls.extend(quote! {
            impl #generics From<#ty> for #type_name #generics {
                fn from(f: #ty) -> Self {
                    Self::#name(f)
                }
            }
        });
    }

    Ok(impls)
}
