use proc_macro2::Ident;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{braced, Result, Token};

pub struct CodedIndex {
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

pub fn coded_index(CodedIndex { name, tables }: CodedIndex) -> proc_macro2::TokenStream {
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

    quote! {
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
    }
}
