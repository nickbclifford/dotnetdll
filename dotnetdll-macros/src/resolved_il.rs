use heck::ToSnakeCase;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::token::Paren;
use syn::{parenthesized, Attribute, Ident, Token, Type};

pub struct Instruction {
    flags: Vec<String>,
    name: Ident,
    fields: Vec<Type>,
    skip_constructor: bool,
}
impl Parse for Instruction {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut skip_constructor = false;
        let mut flags = vec![];
        for attr in input.call(Attribute::parse_outer)? {
            if attr.path.is_ident("flags") {
                flags.extend(attr.parse_args_with(|i: ParseStream| {
                    i.parse_terminated::<_, Token![,]>(|i| {
                        Ok(if i.peek(Token![type]) {
                            i.parse::<Token![type]>()?;
                            "type".to_string()
                        } else {
                            i.parse::<Ident>()?.to_string()
                        })
                    })
                })?);
            } else if attr.path.is_ident("skip_constructor") {
                skip_constructor = true;
            } else {
                return Err(input.error("invalid attribute (only #[flags()]/#[skip_constructor] supported)"));
            }
        }

        Ok(Instruction {
            skip_constructor,
            flags,
            name: input.parse()?,
            fields: {
                if input.peek(Paren) {
                    let content;
                    parenthesized!(content in input);
                    content
                        .parse_terminated::<_, Token![,]>(Type::parse)?
                        .into_iter()
                        .collect()
                } else {
                    vec![]
                }
            },
        })
    }
}

pub struct Instructions(Vec<Instruction>);
impl Parse for Instructions {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Instructions(
            input
                .parse_terminated::<_, Token![,]>(Instruction::parse)?
                .into_iter()
                .collect(),
        ))
    }
}
pub fn r_instructions(Instructions(is): Instructions) -> TokenStream {
    let names: Vec<(Vec<_>, Vec<_>)> = is
        .iter()
        .map(|i| {
            let flag_fields = i.flags.iter().map(|f| {
                Ident::new(
                    &match f.as_str() {
                        check @ ("type" | "range" | "null") => format!("skip_{}_check", check),
                        rest => rest.to_string(),
                    },
                    Span::call_site(),
                )
            });
            let ins_fields = (0..(i.fields.len())).map(|i| format_ident!("param{}", i));

            (flag_fields.collect(), ins_fields.collect())
        })
        .collect();

    let variants = is.iter().zip(names.iter()).map(
        |(
            Instruction {
                flags, name, fields, ..
            },
            (flag_names, field_names),
        )| {
            if flags.is_empty() {
                if fields.is_empty() {
                    quote! { #name }
                } else {
                    quote! { #name(#(#fields),*) }
                }
            } else {
                let named_fields = flags
                    .iter()
                    .map(|f| {
                        if f == "unaligned" {
                            quote! { Option<Alignment> }
                        } else {
                            quote! { bool }
                        }
                    })
                    .chain(fields.iter().map(|t| quote! { #t }))
                    .zip(flag_names.iter().chain(field_names.iter()))
                    .map(|(t, n)| quote! { #n: #t });

                quote! {
                    #name {
                        #(#named_fields),*
                    }
                }
            }
        },
    );

    let match_arms = is
        .iter()
        .zip(names.iter())
        .map(|(Instruction { flags, name, fields, .. }, (flag_names, field_names))| {
            if flags.is_empty() {
                if fields.is_empty() {
                    quote! { Instruction::#name => stringify!(#name).to_string() }
                } else {
                    let bindings: Vec<_> = (0..fields.len())
                        .map(|i| format_ident!("f{}", i))
                        .collect();
                    let f_str = format!("{{}}({})", std::iter::repeat("{}").take(bindings.len()).collect::<Vec<_>>().join(", "));
                    quote! {
                        Instruction::#name(#(#bindings),*) => format!(#f_str, stringify!(#name), #(InstructionShow::show(#bindings, res)),*)
                    }
                }
            } else {
                let to_show: Vec<_> = flag_names.iter().map(|f| {
                   if f == "unaligned" {
                       quote! { #f as &dyn InstructionFlag }
                   } else {
                       quote! { &(stringify!(#f), *#f) as &dyn InstructionFlag }
                   }
                }).collect();

                let pattern = quote! { { #(#flag_names,)* #(#field_names),* } };

                if field_names.is_empty() {
                    quote! {
                        Instruction::#name #pattern => format!("{}{}", stringify!(#name), show_flags([#(#to_show),*]))
                    }
                } else {
                    let f_str = format!("{{}}{{}}({})", std::iter::repeat("{}").take(field_names.len()).collect::<Vec<_>>().join(", "));
                    quote! {
                        Instruction::#name #pattern => {
                            format!(#f_str,
                                stringify!(#name),
                                show_flags([#(#to_show),*]),
                                #(InstructionShow::show(#field_names, res)),*)
                        }
                    }
                }
            }
        });

    let constructors = is
        .iter()
        .zip(names.iter())
        .filter(|(i, _)| !(i.skip_constructor || i.flags.is_empty() && i.fields.is_empty()))
        .map(
            |(
                Instruction {
                    flags, name, fields, ..
                },
                (flag_names, field_names),
            )| {
                let snake_name = format_ident!("{}", name.to_string().to_snake_case());

                let constructor = if flags.is_empty() {
                    quote! { (#(#field_names.into()),*) }
                } else {
                    quote! { {
                        #(#flag_names: Default::default(),)*
                        #(#field_names: #field_names.into()),*
                    } }
                };

                quote! {
                    pub fn #snake_name(#(#field_names: impl Into<#fields>),*) -> Self {
                        Instruction::#name #constructor
                    }
                }
            },
        );

    quote! {
        #[derive(Debug, Clone)]
        pub enum Instruction {
            #(#variants),*
        }

        impl ResolvedDebug for Instruction {
            fn show(&self, res: &Resolution) -> String {
                match self {
                    #(#match_arms),*
                }
            }
        }

        impl Instruction {
            #(#constructors)*
        }
    }
}
