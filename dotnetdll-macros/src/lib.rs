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
            let mut new_fields = fields(prefix);
            new_fields.extend(src_map[&t].clone());
            dest_map.insert(new_name, new_fields);
        }
    }

    let normal_map: FieldsMap = normal
        .iter()
        .map(|v| (v.ident.clone(), fields(v)))
        .collect();

    let mut prefixes_map = FieldsMap::new();

    for v in &prefixes {
        let t_attr = v.attrs.iter().find(|a| a.path.is_ident("target")).unwrap();
        let TargetAttribute(targets) = t_attr.parse_args().unwrap();

        build_targets(&normal_map, &mut prefixes_map, v, targets);
    }

    // must be done after first pass of prefixing is complete
    let mut composed_map = FieldsMap::new();

    for v in &prefixes {
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

    // build parameters with simple indexes
    fn build_ident(c: char) -> impl FnMut(usize) -> Ident {
        move |i| Ident::new(&format!("{}{}", c, i), Span::call_site())
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

    let mut base_sizes = HashMap::new();

    let mut writes = HashMap::new();

    for v in &normal {
        let (_, byte) = v.discriminant.as_ref().unwrap();
        let id = &v.ident;

        let fields = &normal_map[id];
        let num_fields = fields.len();

        // construct variant with InstructionField trait impl
        let parse = make_variant(
            id,
            fields
                .iter()
                .map(|_| quote! { InstructionField::parse(from, offset)? }),
        );

        let byte_writer = quote! { (#byte as u8) };

        // put match arm in correct bucket
        let (size, bucket, mut to_write) = if v.attrs.iter().any(|a| a.path.is_ident("extended")) {
            (
                2_usize,
                &mut extended_parses,
                vec![quote! { 0xFE_u8 }, byte_writer],
            )
        } else {
            (1_usize, &mut parses, vec![byte_writer])
        };

        // build identifiers for the variant's fields
        let field_idents: Vec<_> = (0..num_fields).map(build_ident('n')).collect();
        to_write.extend(field_idents.iter().map(|i| quote! { #i }));

        writes.insert(id.clone(), (field_idents, to_write));

        bucket.push(quote! { #byte => Instruction::#parse });

        base_sizes.insert(id.clone(), (size, num_fields));
    }

    // constructing prefix variants is a lot more complicated
    let prefix_parses = prefixes.iter().map(|v| {
        let (_, byte) = v.discriminant.as_ref().unwrap();
        let prefix_name = v.ident.to_string();

        let prefix_bindings: Vec<_> = (0..fields(v).len()).map(build_ident('p')).collect();

        // builds match arms for each valid suffix
        // the Vec construction is necessary to avoid lifetime problems
        let build_suffixes = |input_map: &FieldsMap, suffix_lookup: &FieldsMap| -> Vec<_> {
            input_map.keys().filter_map(|id| {
                let variant_name = id.to_string();
                // only build for the current prefix
                if let Some(bare) = variant_name.strip_prefix(&prefix_name) {
                    // remove the prefix name from the full variant to get the suffix name
                    let bare_ident = Ident::new(bare, Span::call_site());

                    // lookup number of fields on the suffix, build bindings for them
                    let field_bindings: Vec<_> = (0..suffix_lookup[&bare_ident].len()).map(build_ident('f')).collect();

                    let left = make_variant(&bare_ident, field_bindings.iter());
                    // concat all the bindings together to build the final instruction
                    let right = make_variant(id, prefix_bindings.iter().chain(field_bindings.iter()));
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
                    let #prefix_bindings = InstructionField::parse(from, offset)?;
                )*
                // parse a full instruction
                match from.gread(offset)? {
                    // check all valid suffixes
                    #(#normal_suffixes,)*
                    #(#composed_suffixes,)*
                    bad => throw!("bad suffix instruction {:?} for prefix {}", bad, stringify!(#prefix_name))
                }
            }
        }
    });

    let mut build_sizes = |prefix_name: &str, input_map: &FieldsMap| {
        // same logic for ident matching as parse building
        for (id, fields) in input_map.iter() {
            let variant_name = id.to_string();
            if let Some(bare) = variant_name.strip_prefix(&prefix_name) {
                let bare_ident = Ident::new(bare, Span::call_site());

                let (suffix_size, _) = base_sizes[&bare_ident];
                base_sizes.insert(id.clone(), (2 + suffix_size, fields.len()));
            }
        }
    };

    // single prefix sizes
    for v in &prefixes {
        build_sizes(&v.ident.to_string(), &prefixes_map);
    }
    // composed prefix sizes (requires single prefixes)
    for v in &prefixes {
        build_sizes(&v.ident.to_string(), &composed_map);
    }

    let bytesize = base_sizes.into_iter().map(|(id, (base_size, num_fields))| {
        let fields: Vec<_> = (0..num_fields).map(build_ident('f')).collect();
        let var = make_variant(&id, fields.iter());

        // include the base instruction size, then the bytesize of each field
        let sizes = std::iter::once(quote! { #base_size })
            .chain(fields.into_iter().map(|f| quote! { #f.bytesize() }));
        // join with pluses to add
        quote! { Instruction::#var => #(#sizes)+* }
    });

    let mut build_writes = |prefix: &Variant, input_map: &FieldsMap| {
        let prefix_name = prefix.ident.to_string();
        let (_, byte) = prefix.discriminant.as_ref().unwrap();
        let num_fields = fields(prefix).len();

        // ditto
        for (id, _) in input_map.iter() {
            let variant_name = id.to_string();
            if let Some(bare) = variant_name.strip_prefix(&prefix_name) {
                let bare_ident = Ident::new(bare, Span::call_site());

                let (suffix_fields, suffix_to_write) = &writes[&bare_ident];

                let prefix_fields: Vec<_> = (0..num_fields).map(build_ident('p')).collect();

                let mut to_write = vec![quote! { 0xFEu8 }, quote! { (#byte as u8) }];
                to_write.extend(prefix_fields.iter().map(|i| quote! { #i }));
                // clone because we want to repeat what's in the suffix
                to_write.extend(suffix_to_write.iter().map(Clone::clone));

                let all_fields = prefix_fields
                    .into_iter()
                    // clone because we want the same idents
                    .chain(suffix_fields.iter().map(Clone::clone))
                    .collect();

                writes.insert(id.clone(), (all_fields, to_write));
            }
        }
    };

    // single prefix writes
    for v in &prefixes {
        build_writes(v, &prefixes_map);
    }
    // composed prefix writes (requires single prefixes)
    for v in &prefixes {
        build_writes(v, &composed_map);
    }

    let write_matches = writes.into_iter().map(|(id, (fields, to_write))| {
        let var = make_variant(&id, fields);
        quote! { Instruction::#var => { #( #to_write.write(into, offset)?; )* } }
    });

    // builds type names for InstructionField impls
    let nums = [
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64",
    ]
    .iter()
    .map(|n| Ident::new(n, Span::call_site()));

    TokenStream::from(quote! {
        use scroll::{Pread, Pwrite};
        use std::mem::size_of;

        // types are really hard to deal with in macros
        // it's easiest to just use a private trait instead for this kind of dispatch

        trait InstructionField: Sized {
            fn parse(from: &[u8], offset: &mut usize) -> scroll::Result<Self>;
            fn write(self, into: &mut [u8], offset: &mut usize) -> scroll::Result<()>;
            fn bytesize(&self) -> usize;
        }

        #(
            impl InstructionField for #nums {
                fn parse(from: &[u8], offset: &mut usize) -> scroll::Result<Self> {
                    from.gread_with(offset, scroll::LE)
                }

                fn write(self, into: &mut [u8], offset: &mut usize) -> scroll::Result<()> {
                    into.gwrite_with(self, offset, scroll::LE)?;
                    Ok(())
                }

                fn bytesize(&self) -> usize {
                    size_of::<Self>()
                }
            }
        )*

        impl InstructionField for Token {
            fn parse(from: &[u8], offset: &mut usize) -> scroll::Result<Self> {
                from.gread(offset)
            }

            fn write(self, into: &mut [u8], offset: &mut usize) -> scroll::Result<()> {
                into.gwrite(self, offset)?;
                Ok(())
            }

            fn bytesize(&self) -> usize {
                4
            }
        }

        // the Switch instruction is the only usage of this
        impl InstructionField for Vec<i32> {
            fn parse(from: &[u8], offset: &mut usize) -> scroll::Result<Self> {
                let num: u32 = from.gread_with(offset, scroll::LE)?;
                let mut result = vec![0i32; num as usize];
                from.gread_inout_with(offset, &mut result, scroll::LE)?;
                Ok(result)
            }

            fn write(self, into: &mut [u8], offset: &mut usize) -> scroll::Result<()> {
                into.gwrite_with(self.len() as u32, offset, scroll::LE)?;
                for i in self {
                    into.gwrite_with(i, offset, scroll::LE)?;
                }
                Ok(())
            }

            fn bytesize(&self) -> usize {
                size_of::<u32>() + (self.len() * size_of::<i32>())
            }
        }

        #[derive(Debug)]
        pub enum Instruction {
            #(#normal_variants,)*
            #(#prefix_variants,)*
            #(#compose_variants),*
        }

        impl Instruction {
            pub fn bytesize(&self) -> usize {
                match self {
                    #(#bytesize),*
                }
            }
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
                        bad => throw!("unknown extended opcode 0xFE {:#04x}", bad)
                    },
                    bad => throw!("unknown opcode {:#04x}", bad)
                };

                Ok((val, *offset))
            }
        }
        impl scroll::ctx::TryIntoCtx for Instruction {
            type Error = scroll::Error;

            fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
                let offset = &mut 0;

                match self {
                    #(#write_matches),*
                }

                Ok(*offset)
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
    let from_match_arms = tables.iter().enumerate().filter_map(|(idx, n)| {
        if n == "Unused" {
            None
        } else {
            Some(quote! { #idx => #name::#n(index) })
        }
    });

    let into_match_arms = tables.iter().enumerate().filter_map(|(idx, n)| {
        if n == "Unused" {
            None
        } else {
            Some(quote! { #name::#n(i) => (*i, #idx) })
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
                    #(#from_match_arms,)*
                    bad_tag => throw!("bad {} coded index tag {}", stringify!(#name), bad_tag)
                };

                Ok((val, *offset))
            }
        }

        impl<'a> TryIntoCtx<Sizes<'a>> for #name {
            type Error = scroll::Error;

            // same page
            fn try_into_ctx(self, into: &mut [u8], sizes: Sizes<'a>) -> Result<usize, Self::Error> {
                let offset = &mut 0;

                let max_size = [#(Kind::#variants),*].iter().map(|t| sizes.tables.get(t).unwrap_or(&0)).max().unwrap();

                let (index, tag) = self.build_indices();

                if *max_size < (1 << (16 - #log)) {
                    into.gwrite_with(((index as u16) << #log) | tag as u16, offset, scroll::LE)?;
                } else {
                    into.gwrite_with(((index as u32) << #log) | tag as u32, offset, scroll::LE)?;
                }

                Ok(*offset)
            }
        }

        impl PartialOrd for #name {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for #name {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.build_indices().cmp(&other.build_indices())
            }
        }

        impl #name {
            pub fn is_null(&self) -> bool {
                *self == #name::Null
            }

            fn build_indices(&self) -> (usize, usize) {
                match self {
                    #(#into_match_arms,)*
                    #name::Null => (0, 0)
                }
            }
        }
    })
}
