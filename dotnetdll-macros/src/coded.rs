use proc_macro2::Ident;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Attribute, Result, Token, braced};

pub struct CodedIndex {
    attrs: Vec<Attribute>,
    name: Ident,
    tables: Punctuated<Ident, Token![,]>,
}

impl Parse for CodedIndex {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let name = input.parse()?;
        input.parse::<Token![,]>()?;
        let tables;
        braced!(tables in input);
        Ok(CodedIndex {
            attrs,
            name,
            tables: tables.parse_terminated(Ident::parse)?,
        })
    }
}

pub fn coded_index(CodedIndex { attrs, name, tables }: CodedIndex) -> proc_macro2::TokenStream {
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

    let token_match_arms = tables.iter().filter_map(|n| {
        if n == "Unused" {
            None
        } else {
            Some(quote! { #name::#n(i) => (Kind::#n, i) })
        }
    });

    let target_tables = variants.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ");

    let tag_mappings = tables
        .iter()
        .enumerate()
        .map(|(idx, n)| {
            if n == "Unused" {
                format!("- `0b{idx:0width$b}` => unused", width = log as usize)
            } else {
                format!("- `0b{idx:0width$b}` => `{n}`", width = log as usize)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let tag_bits = if log == 1 { "bit" } else { "bits" };
    let auto_doc = format!(
        "Coded index over {target_tables}.\n\nUses {log} low tag {tag_bits}:\n{tag_mappings}\n\nThe remaining upper bits contain the selected table row id (RID).\nSee `ECMA-335, II.24.2.6` and `ECMA-335, II.23.2.8`."
    );

    quote! {
        #(#attrs)*
        #[doc = #auto_doc]
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

                let max_size = [#(sizes.tables[Kind::#variants as usize]),*].into_iter().max().unwrap();

                let coded = if max_size < (1 << (16 - #log)) {
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
                    bad_tag => {
                        return Err(scroll::Error::Custom(format!(
                            "bad {} coded index tag {}",
                            stringify!(#name),
                            bad_tag
                        )))
                    }
                };

                Ok((val, *offset))
            }
        }

        impl<'a> TryIntoCtx<Sizes<'a>> for #name {
            type Error = scroll::Error;

            // same page
            fn try_into_ctx(self, into: &mut [u8], sizes: Sizes<'a>) -> Result<usize, Self::Error> {
                let offset = &mut 0;

                let max_size = [#(sizes.tables[Kind::#variants as usize]),*].into_iter().max().unwrap();

                let (index, tag) = self.build_indices();

                if max_size < (1 << (16 - #log)) {
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

        impl From<#name> for Token {
            fn from(i: #name) -> Self {
                let (kind, index) = match i {
                    #(#token_match_arms,)*
                    #name::Null => (Kind::from_u8(0).unwrap(), 0) // whatever
                };

                Token {
                    target: TokenTarget::Table(kind),
                    index,
                }
            }
        }
    }
}
