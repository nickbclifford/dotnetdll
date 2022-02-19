use proc_macro2::TokenStream;
use quote::{quote, ToTokens, TokenStreamExt};
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::{Bracket, Paren};
use syn::{bracketed, parenthesized, Ident, Token};

#[derive(Debug)]
pub enum TypeSegment {
    Bare(Ident),
    Brackets,
    Asterisk,
    Variable(Ident),
}

impl Parse for TypeSegment {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(Ident::peek_any) {
            input.parse().map(TypeSegment::Bare)
        } else if lookahead.peek(Bracket) {
            let content;
            bracketed!(content in input);
            // TODO: allow shaped arrays
            if !content.is_empty() {
                Err(content.error("only empty arrays are currently allowed"))
            } else {
                Ok(TypeSegment::Brackets)
            }
        } else if lookahead.peek(Token![*]) {
            input.parse::<Token![*]>()?;
            Ok(TypeSegment::Asterisk)
        } else if lookahead.peek(Token![#]) {
            input.parse::<Token![#]>()?;
            Ok(TypeSegment::Variable(input.parse()?))
        } else {
            Err(lookahead.error())
        }
    }
}

pub struct Type(Vec<TypeSegment>);

impl Parse for Type {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut inner = vec![];
        loop {
            inner.push(input.parse()?);
            if input.peek(Paren) || input.peek(Token![,]) || input.is_empty() {
                break;
            }
        }
        Ok(Type(inner))
    }
}

impl ToTokens for Type {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(ctype(self));
    }
}

macro_rules! check_idents {
    (match $i:ident { $($src:literal => $dest:ident,)* }) => {
        $(if $i == $src { quote! { BaseType::$dest.into() } } else )+ {
            panic!("unknown type {:?}", $i)
        }
    }
}

pub fn ctype(Type(segments): &Type) -> TokenStream {
    fn go(segments: &[TypeSegment]) -> TokenStream {
        match segments {
            [] => TokenStream::new(),
            [TypeSegment::Bare(i)] => check_idents!(match i {
                "bool" => Boolean,
                "char" => Char,
                "sbyte" => Int8,
                "byte" => UInt8,
                "short" => Int16,
                "ushort" => UInt16,
                "int" => Int32,
                "uint" => UInt32,
                "long" => Int64,
                "ulong" => UInt64,
                "float" => Float32,
                "double" => Float64,
                "nint" => IntPtr,
                "nuint" => UIntPtr,
                "object" => Object,
                "string" => String,
            }),
            [TypeSegment::Variable(i)] => quote! { #i },
            [ss @ .., TypeSegment::Brackets] => {
                let first = go(ss);
                quote! { BaseType::vector(#first).into() }
            }
            [TypeSegment::Bare(i), TypeSegment::Asterisk] if i == "void" => quote! { BaseType::VOID_PTR.into() }, // special case
            [ss @ .., TypeSegment::Asterisk] => {
                let first = go(ss);
                quote! { BaseType::pointer(#first).into() }
            }
            rest => panic!("invalid type declaration {:?}", rest),
        }
    }

    go(&segments)
}

pub enum Parameter {
    Value(Type),
    Ref(Type),
    // if you need a typedref in your method signature, you can deal with constructing the signature yourself
}

impl Parse for Parameter {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(Token![ref]) {
            input.parse::<Token![ref]>()?;
            Ok(Parameter::Ref(input.parse()?))
        } else {
            Ok(Parameter::Value(input.parse()?))
        }
    }
}

impl ToTokens for Parameter {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(match self {
            Parameter::Value(t) => quote! { ParameterType::Value(#t) },
            Parameter::Ref(t) => quote! { ParameterType::Ref(#t) },
        });
    }
}

pub struct Signature {
    is_static: bool,
    return_type: Option<Parameter>,
    parameters: Punctuated<Parameter, Token![,]>,
}

mod kw {
    syn::custom_keyword!(void);
}

impl Parse for Signature {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let is_static = if input.peek(Token![static]) {
            input.parse::<Token![static]>()?;
            true
        } else {
            false
        };

        let return_type = if input.peek(kw::void) {
            input.parse::<kw::void>()?;
            None
        } else {
            Some(input.parse()?)
        };

        let content;
        parenthesized!(content in input);

        Ok(Self {
            is_static,
            return_type,
            parameters: content.parse_terminated(Parameter::parse)?,
        })
    }
}

pub fn msig(sig: Signature) -> TokenStream {
    let constructor = if !sig.is_static {
        quote! { instance }
    } else {
        quote! { static_member }
    };

    let return_type = match sig.return_type {
        None => quote! { ReturnType::VOID },
        Some(p) => quote! { ReturnType::new(#p) },
    };

    let params = sig.parameters.into_iter();

    quote! {
        MethodSignature::#constructor(#return_type, vec![#(Parameter::new(#params)),*])
    }
}
