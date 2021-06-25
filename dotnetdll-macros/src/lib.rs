use std::collections::HashMap;

use proc_macro::{self, TokenStream};

use proc_macro2::Span;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{braced, parse_macro_input, Field, Fields, Ident, Result, Token, Variant};

// separate prefix and normal instruction declarations
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

// identifiers inside the #[target] attribute, wildcards are followed by a *
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

    // extract fields from a variant
    fn fields(v: &Variant) -> Vec<Field> {
        match &v.fields {
            // it doesn't make sense for these instructions to have named fields
            Fields::Named(_) => panic!("enum variant {} cannot have named fields", v.ident),
            // clone because we need them to have a lifetime beyond that of the variant
            Fields::Unnamed(u) => u.unnamed.iter().map(Field::clone).collect(),
            Fields::Unit => vec![],
        }
    }

    // mapping from a variant's name to its owned fields, reused quite often
    type FieldsMap = HashMap<Ident, Vec<Field>>;

    // given a prefix variant and valid suffix targets, get fields from src_map and build combinations in dest_map
    fn build_targets(
        src_map: &FieldsMap,
        dest_map: &mut FieldsMap,
        prefix: &Variant,
        targets: Vec<TargetIdent>,
    ) {
        let mut result: Vec<Ident> = vec![];

        for t in targets {
            match t {
                TargetIdent::Normal(i) => result.push(i),
                TargetIdent::Wildcard(i) => result.extend(
                    // all identifiers that start with the given identifier
                    // e.g. Ldelem* matches Ldelem(Token) but also LdelemI1 and LdelemR4
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
            // Unaligned cannot be composed with Volatile for these instructions
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
    }

    let normal_map: FieldsMap = normal
        .iter()
        .map(|v| (v.ident.clone(), fields(v)))
        .collect();

    let mut prefixes_map = FieldsMap::new();

    for v in prefixes.iter() {
        let t_attr = v.attrs.iter().find(|a| a.path.is_ident("target")).unwrap();
        let TargetAttribute(targets) = t_attr.parse_args().unwrap();

        build_targets(&normal_map, &mut prefixes_map, v, targets);
    }

    // must be done after first pass of prefixing is complete
    let mut composed_map = FieldsMap::new();

    for v in prefixes.iter() {
        if let Some(c_attr) = v.attrs.iter().find(|a| a.path.is_ident("compose")) {
            let id: Ident = c_attr.parse_args().unwrap();

            // for composition, the attribute argument is the only valid target
            build_targets(
                &prefixes_map,
                &mut composed_map,
                v,
                vec![TargetIdent::Wildcard(id)],
            );
        }
    }

    // builds unit variant if no fields, else builds tuple variant
    // impl IntoIterator avoids unnecessary Vec construction
    // impl ToTokens allows for usage with both variant definition and construction
    fn make_variant(
        id: &Ident,
        iter: impl IntoIterator<Item = impl quote::ToTokens>,
    ) -> proc_macro2::TokenStream {
        let mut peek = iter.into_iter().peekable();
        if peek.peek().is_none() {
            quote! { #id }
        } else {
            quote! { #id(#(#peek),*) }
        }
    }

    // builds a sorted iterator of variants
    // they look much better in docs when sorted
    fn build_sorted_variants(
        map: &FieldsMap,
    ) -> impl Iterator<Item = proc_macro2::TokenStream> + '_ {
        let mut sorted: Vec<_> = map.iter().collect();
        sorted.sort_by_key(|e| e.0);
        sorted.into_iter().map(|(i, f)| make_variant(i, f))
    }

    let normal_variants = build_sorted_variants(&normal_map);
    let prefix_variants = build_sorted_variants(&prefixes_map);
    let compose_variants = build_sorted_variants(&composed_map);

    let mut parses = vec![];
    let mut extended_parses = vec![];

    for v in normal.iter() {
        let (_, byte) = v.discriminant.as_ref().unwrap();
        let id = &v.ident;

        // construct variant with IntoInstr trait impl
        let parse = make_variant(
            id,
            normal_map[id]
                .iter()
                .map(|_| quote! { IntoInstr::parse(from, offset)? }),
        );

        // put match arm in correct bucket
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

    // constructing prefix variants is a lot more complicated
    let prefix_parses = prefixes.iter().map(|v| {
        let (_, byte) = v.discriminant.as_ref().unwrap();
        let prefix_name = v.ident.to_string();

        // build parameters with simple indexes
        fn build_ident(c: char) -> impl FnMut(usize) -> Ident {
            move |i| Ident::new(&format!("{}{}", c, i), Span::call_site())
        }

        let prefix_bindings: Vec<_> = (0..fields(&v).len()).map(build_ident('p')).collect();

        // builds match arms for each valid suffix
        // the Vec construction is necessary to avoid lifetime problems
        let build_suffixes = |input_map: &FieldsMap, suffix_lookup: &FieldsMap| -> Vec<_> {
            input_map.iter().filter_map(|(id, _)| {
                let variant_name = id.to_string();
                // only build for the current prefix
                if variant_name.starts_with(&prefix_name) {
                    // remove the prefix name from the full variant to get the suffix name
                    let bare_ident = Ident::new(&variant_name[prefix_name.len()..], Span::call_site());

                    // lookup number of fields on the suffix, build bindings for them
                    let field_bindings: Vec<_> = (0..suffix_lookup[&bare_ident].len()).map(build_ident('f')).collect();

                    let left = make_variant(&bare_ident, field_bindings.iter());
                    // concat all the bindings together to build the final instruction
                    let right = make_variant(&id, prefix_bindings.iter().chain(field_bindings.iter()));
                    Some(quote! {
                        Instruction::#left => Instruction::#right
                    })
                } else {
                    None
                }
            }).collect()
        };

        let normal_suffixes = build_suffixes(&prefixes_map, &normal_map);
        let composed_suffixes = build_suffixes(&composed_map, &prefixes_map);

        quote! {
            // match arm inside 0xFE, checks prefix byte
            #byte => {
                // if it has any parameters, parse them here
                #(
                    let #prefix_bindings = IntoInstr::parse(from, offset)?;
                )*
                // parse a full instruction
                match from.gread(offset)? {
                    // check all valid suffixes
                    #(#normal_suffixes,)*
                    #(#composed_suffixes,)*
                    bad => return Err(scroll::Error::Custom(
                        format!("bad suffix instruction {:?} for prefix {}", bad, stringify!(#prefix_name))
                    ))
                }
            }
        }
    });

    // builds type names for IntoInstr impls
    let nums = [
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64",
    ]
    .iter()
    .map(|n| Ident::new(n, Span::call_site()));

    TokenStream::from(quote! {
        use scroll::Pread;

        // types are really hard to deal with in macros
        // it's easiest to just use a private trait instead for this kind of dispatch
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

        // the Switch instruction is the only usage of this
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
                    // single-byte instructions
                    #(#parses,)*
                    0xFE => match from.gread_with::<u8>(offset, scroll::LE)? {
                        // instructions that use the 0xFE extended range
                        #(#extended_parses,)*
                        // constructed prefixed instructions
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

    // only define named variants
    let variants: Vec<_> = tables.iter().filter(|&n| n != "Unused").collect();

    // the spec only says "log n", this is the implementation that makes sense for integers and bitwise ops
    let log = (tables.len() as f32).log2().ceil() as u32;

    // the Unused ident is used to pad out meaningful variants to a certain index
    // so use enumerate to build the match arms
    let match_arms = tables.iter().enumerate().filter_map(|(idx, n)| {
        if n == "Unused" {
            None
        } else {
            Some(quote! { #idx => #name::#n(index) })
        }
    });

    TokenStream::from(quote! {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
        pub enum #name {
            #(#variants(usize),)*
            Null
        }

        impl<'a> TryFromCtx<'a, Sizes<'a>> for #name {
            type Error = scroll::Error;

            // ECMA-335, II.24.2.6 (page 274)
            fn try_from_ctx(from: &'a [u8], sizes: Sizes<'a>) -> Result<(Self, usize), Self::Error> {
                let offset = &mut 0;

                let max_size = [#(Kind::#variants),*].iter().map(|t| sizes.tables.get(t).unwrap_or(&0)).max().unwrap();

                let coded = if *max_size < (1 << (16 - #log)) {
                    from.gread_with::<u16>(offset, scroll::LE)? as u32
                } else {
                    from.gread_with::<u32>(offset, scroll::LE)?
                };

                if coded == 0 {
                    return Ok((#name::Null, *offset));
                }

                let mask = (1 << #log) - 1;
                let index = (coded >> #log) as usize;

                let val = match (coded & mask) as usize {
                    #(#match_arms,)*
                    bad_tag => return Err(scroll::Error::Custom(format!("bad {} coded index tag {}", stringify!(#name), bad_tag)))
                };

                Ok((val, *offset))
            }
        }

        impl #name {
            pub fn is_null(&self) -> bool {
                *self == #name::Null
            }
        }
    })
}
