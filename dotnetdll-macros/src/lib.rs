use proc_macro::*;

use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{braced, parse_macro_input, Fields, Ident, Result, Token, Variant};

#[derive(Eq, PartialEq)]
enum InstructionKind {
    Prefix,
    Normal,
}

use InstructionKind::*;

struct Instruction {
    variant: Variant,
    kind: InstructionKind,
}

struct Instructions(Vec<Instruction>);

mod kw {
    syn::custom_keyword!(prefixes);
}

impl Parse for Instructions {
    fn parse(input: ParseStream) -> Result<Self> {
        input.parse::<kw::prefixes>()?;

        let prefix_in;
        braced!(prefix_in in input);

        type InstrVariant = Punctuated<Variant, Token![,]>;
        let prefixes: InstrVariant = prefix_in.parse_terminated(Variant::parse)?;
        let rest: InstrVariant = input.parse_terminated(Variant::parse)?;

        Ok(Instructions(
            prefixes
                .into_iter()
                .map(|p| Instruction {
                    variant: p,
                    kind: Prefix,
                })
                .chain(rest.into_iter().map(|r| Instruction {
                    variant: r,
                    kind: Normal,
                }))
                .collect(),
        ))
    }
}

#[proc_macro]
pub fn instructions(input: TokenStream) -> TokenStream {
    let Instructions(instrs) = parse_macro_input!(input as Instructions);

    let mut variants = Vec::with_capacity(instrs.len());

    let mut normal = vec![];
    let mut extended = vec![];

    for Instruction { variant, kind } in instrs {
        let id = &variant.ident;
        let (_, code) = &variant.discriminant.unwrap();
        let into = match &variant.fields {
            Fields::Named(_) => panic!("enum variant {} cannot have named fields", id),
            Fields::Unnamed(u) => {
                let fields = &u.unnamed;
                variants.push(match kind {
                    Prefix => quote! { #id(#fields, Box<Instruction>) },
                    Normal => quote! { #id(#fields) },
                });
                let mut into_fields: Vec<_> = fields
                    .iter()
                    .map(|_| quote! { IntoInstr::parse(from, offset)? })
                    .collect();
                if kind == Prefix {
                    into_fields.push(quote! { Box::new(from.gread(offset)?) });
                }
                quote! { Instruction::#id(#(#into_fields),*) }
            }
            Fields::Unit => match kind {
                Prefix => {
                    variants.push(quote! { #id(Box<Instruction>) });
                    quote! { Instruction::#id(Box::new(from.gread(offset)?)) }
                }
                Normal => {
                    variants.push(quote! { #id });
                    quote! { Instruction::#id }
                }
            },
        };
        (if variant.attrs.is_empty() {
            &mut normal
        } else {
            &mut extended
        })
        .push(quote! { #code => #into });
    }

    let nums = [
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64",
    ]
    .iter()
    .map(|n| Ident::new(n, Span::call_site().into()));

    TokenStream::from(quote! {
        use scroll::Pread;

        trait IntoInstr: Sized {
            fn parse(from: &[u8], offset: &mut usize) -> Result<Self, scroll::Error>;
        }

        #(
            impl IntoInstr for #nums {
                fn parse(from: &[u8], offset: &mut usize) -> Result<Self, scroll::Error> {
                    from.gread_with(offset, scroll::LE)
                }
            }
        )*

        impl IntoInstr for Token {
            fn parse(from: &[u8], offset: &mut usize) -> Result<Self, scroll::Error> {
                from.gread(offset)
            }
        }

        impl IntoInstr for Vec<i32> {
            fn parse(from: &[u8], offset: &mut usize) -> Result<Self, scroll::Error> {
                let num: i32 = from.gread_with(offset, scroll::LE)?;
                let mut result = vec![0i32; num as usize];
                from.gread_inout_with(offset, &mut result, scroll::LE)?;
                Ok(result)
            }
        }

        #[derive(Debug)]
        pub enum Instruction {
            #(#variants),*
        }

        impl scroll::ctx::TryFromCtx<'_> for Instruction {
            type Error = scroll::Error;

            fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
                let offset = &mut 0;

                let val = match from.gread_with::<u8>(offset, scroll::LE)? {
                    #(#normal),*,
                    0xFE => match from.gread_with::<u8>(offset, scroll::LE)? {
                        #(#extended),*,
                        bad => return Err(scroll::Error::Custom(format!("unknown extended opcode 0xFE {:#04x}", bad)))
                    },
                    bad => return Err(scroll::Error::Custom(format!("unknown opcode {:#04x}", bad)))
                };

                Ok((val, *offset))
            }
        }
    })
}

struct CodedIndex {
    name: Ident,
    tables: Punctuated<Ident, Token![,]>,
}

impl Parse for CodedIndex {
    fn parse(input: ParseStream) -> Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![,]>()?;
        let tables;
        braced!(tables in input);
        Ok(CodedIndex {
            name,
            tables: tables.parse_terminated(Ident::parse)?,
        })
    }
}

#[proc_macro]
pub fn coded_index(input: TokenStream) -> TokenStream {
    let CodedIndex { name, tables } = parse_macro_input!(input as CodedIndex);

    let variants: Vec<_> = tables.iter().filter(|&n| n != "Unused").collect();

    let log = (tables.len() as f32).log2().ceil() as u32;

    let match_arms = tables.iter().enumerate().filter_map(|(idx, n)| {
        if n == "Unused" {
            None
        } else {
            Some(quote! { #idx => #name::#n(index) })
        }
    });

    TokenStream::from(quote! {
        #[derive(Debug, Copy, Clone)]
        pub enum #name {
            #(#variants(usize)),*
        }

        impl<'a> TryFromCtx<'a, Sizes<'a>> for #name {
            type Error = scroll::Error;

            fn try_from_ctx(from: &'a [u8], sizes: Sizes<'a>) -> Result<(Self, usize), Self::Error> {
                let offset = &mut 0;

                let max_size = [#(Kind::#variants),*].iter().map(|t| sizes.tables.get(t).unwrap_or(&0)).max().unwrap();

                let coded = if *max_size < (1 << (16 - #log)) {
                    from.gread_with::<u16>(offset, scroll::LE)? as u32
                } else {
                    from.gread_with::<u32>(offset, scroll::LE)?
                };

                let mask = (1 << #log) - 1;
                let index = (coded >> #log) as usize;

                let val = match (coded & mask) as usize {
                    #(#match_arms),*,
                    bad_tag => return Err(scroll::Error::Custom(format!("bad {} coded index tag {}", stringify!(#name), bad_tag)))
                };

                Ok((val, *offset))
            }
        }
    })
}
