use std::collections::HashMap;

use proc_macro::{self, TokenStream};

use proc_macro2::Span;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{braced, parse_macro_input, Field, Fields, Ident, Result, Token, Variant};

struct Instructions {
    prefixes: Vec<Variant>,
    normal: Vec<Variant>,
}

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

        Ok(Instructions {
            prefixes: prefixes.into_iter().collect(),
            normal: rest.into_iter().collect(),
        })
    }
}

enum TargetIdent {
    Normal(Ident),
    Wildcard(Ident),
}

impl Parse for TargetIdent {
    fn parse(input: ParseStream) -> Result<Self> {
        let ident = input.parse()?;
        Ok(if input.lookahead1().peek(Token![*]) {
            input.parse::<Token![*]>()?;
            TargetIdent::Wildcard(ident)
        } else {
            TargetIdent::Normal(ident)
        })
    }
}

struct TargetAttribute(Vec<TargetIdent>);

impl Parse for TargetAttribute {
    fn parse(input: ParseStream) -> Result<Self> {
        let ids: Punctuated<TargetIdent, Token![,]> = input.parse_terminated(TargetIdent::parse)?;
        Ok(TargetAttribute(ids.into_iter().collect()))
    }
}

#[proc_macro]
pub fn instructions(input: TokenStream) -> TokenStream {
    let Instructions { prefixes, normal } = parse_macro_input!(input);

    let nums = [
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64",
    ]
    .iter()
    .map(|n| Ident::new(n, Span::call_site()));

    fn fields(v: &Variant) -> Vec<Field> {
        match &v.fields {
            Fields::Named(_) => panic!("enum variant {} cannot have named fields", v.ident),
            Fields::Unnamed(u) => u.unnamed.iter().map(Field::clone).collect(),
            Fields::Unit => vec![],
        }
    }

    type FieldsMap = HashMap<Ident, Vec<Field>>;

    let build_targets = |src_map: &FieldsMap,
                         dest_map: &mut FieldsMap,
                         prefix: &Variant,
                         targets: Vec<TargetIdent>| {
        let mut result: Vec<Ident> = vec![];

        for t in targets {
            match t {
                TargetIdent::Normal(i) => result.push(i),
                TargetIdent::Wildcard(i) => result.extend(
                    src_map
                        .keys()
                        .filter(|k| k.to_string().starts_with(&i.to_string()))
                        .map(Ident::clone),
                ),
            }
        }

        for t in result {
            let t_str = t.to_string();

            // cannot be bothered to generalize this
            // ECMA-335, III.2.6 (page 322)
            if prefix.ident == "Unaligned" && (t_str.contains("Ldsfld") || t_str.contains("Stsfld"))
            {
                continue;
            }

            let new_name = Ident::new(&format!("{}{}", prefix.ident, t_str), Span::call_site());
            let mut new_fields = fields(&prefix);
            new_fields.extend(src_map[&t].clone());
            dest_map.insert(new_name, new_fields);
        }
    };

    let fields_map: FieldsMap = normal
        .iter()
        .map(|v| (v.ident.clone(), fields(v)))
        .collect();

    let mut prefixes_map = FieldsMap::new();

    for v in prefixes.iter() {
        let t_attr = v.attrs.iter().find(|a| a.path.is_ident("target")).unwrap();
        let TargetAttribute(targets) = t_attr.parse_args().unwrap();

        build_targets(&fields_map, &mut prefixes_map, v, targets);
    }

    // must be done after first pass is complete
    let mut composed_map = FieldsMap::new();

    for v in prefixes.iter() {
        if let Some(c_attr) = v.attrs.iter().find(|a| a.path.is_ident("compose")) {
            let id: Ident = c_attr.parse_args().unwrap();

            build_targets(
                &prefixes_map,
                &mut composed_map,
                v,
                vec![TargetIdent::Wildcard(id)],
            );
        }
    }

    fn make_variant((id, f): (&Ident, &Vec<impl quote::ToTokens>)) -> proc_macro2::TokenStream {
        if f.is_empty() {
            quote! { #id }
        } else {
            quote! { #id(#(#f),*) }
        }
    }

    fn build_sorted_variants(
        map: &FieldsMap,
    ) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by_key(|e| e.0); // it looks much better in docs when sorted
        sorted.into_iter().map(make_variant)
    }

    let normal_variants = build_sorted_variants(&fields_map);
    let prefix_variants = build_sorted_variants(&prefixes_map);
    let compose_variants = build_sorted_variants(&composed_map);

    let mut parses = vec![];
    let mut extended_parses = vec![];

    for v in normal.iter() {
        let (_, byte) = v.discriminant.as_ref().unwrap();
        let id = &v.ident;
        let parse = make_variant((
            id,
            &fields_map[id]
                .iter()
                .map(|_| quote! { IntoInstr::parse(from, offset)? })
                .collect(),
        ));

        (if v
            .attrs
            .iter()
            .find(|a| a.path.is_ident("extended"))
            .is_some()
        {
            &mut extended_parses
        } else {
            &mut parses
        })
        .push(quote! { #byte => Instruction::#parse });
    }

    let prefix_parses = prefixes.iter().map(|v| {
        let (_, byte) = v.discriminant.as_ref().unwrap();
        let prefix_name = v.ident.to_string();

        fn build_ident(c: char) -> impl FnMut(usize) -> Ident {
            move |i| Ident::new(&format!("{}{}", c, i), Span::call_site())
        }

        let prefix_bindings: Vec<_> = (0..fields(&v).len()).map(build_ident('p')).collect();

        let suffixes = prefixes_map.iter().filter_map(|(id, _)| {
            let variant_name = id.to_string();
            if variant_name.starts_with(&prefix_name) {
                let bare_ident = Ident::new(&variant_name[prefix_name.len()..], Span::call_site());
                let field_bindings: Vec<_> = (0..fields_map[&bare_ident].len()).map(build_ident('f')).collect();
                let left = make_variant((&bare_ident, &field_bindings));
                let right = make_variant((&id, &prefix_bindings.iter().chain(field_bindings.iter()).collect()));
                Some(quote! {
                    Instruction::#left =>
                        Instruction::#right
                })
            } else {
                None
            }
        });

        quote! {
            #byte => {
                #(
                    let #prefix_bindings = IntoInstr::parse(from, offset)?;
                )*
                match from.gread::<Instruction>(offset)? {
                    #(#suffixes,)*
                    bad => return Err(scroll::Error::Custom(
                        format!("bad suffix instruction {:?} for prefix {}", bad, stringify!(#prefix_name))
                    ))
                }
            }
        }
    });

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
            #(#normal_variants,)*
            #(#prefix_variants,)*
            #(#compose_variants),*
        }

        impl scroll::ctx::TryFromCtx<'_> for Instruction {
            type Error = scroll::Error;

            fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
                let offset = &mut 0;

                let val = match from.gread_with::<u8>(offset, scroll::LE)? {
                    #(#parses,)*
                    0xFE => match from.gread_with::<u8>(offset, scroll::LE)? {
                        #(#extended_parses,)*
                        #(#prefix_parses,)*
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
                    #(#match_arms,)*
                    bad_tag => return Err(scroll::Error::Custom(format!("bad {} coded index tag {}", stringify!(#name), bad_tag)))
                };

                Ok((val, *offset))
            }
        }
    })
}
