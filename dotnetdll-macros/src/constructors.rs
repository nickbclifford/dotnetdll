use proc_macro2::TokenStream;
use quote::{quote, ToTokens, TokenStreamExt};
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::{Bracket, Paren};
use syn::{bracketed, parenthesized, Ident, Token};

pub struct External(Ident);
impl Parse for External {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        input.parse::<Token![#]>()?;
        Ok(External(input.parse()?))
    }
}
impl ToTokens for External {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.0.to_tokens(tokens)
    }
}

enum TypeSegment {
    Bare(Ident),
    Brackets,
    Asterisk,
    Variable(Box<External>),
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
            _ => panic!("invalid type declaration"),
        }
    }

    go(segments)
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

mod kw {
    syn::custom_keyword!(void);
}
pub struct ReturnType(Option<Parameter>);
impl Parse for ReturnType {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(ReturnType(if input.peek(kw::void) {
            input.parse::<kw::void>()?;
            None
        } else {
            Some(input.parse()?)
        }))
    }
}

pub struct ParameterList(Punctuated<Parameter, Token![,]>);
impl Parse for ParameterList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        parenthesized!(content in input);
        Ok(ParameterList(Punctuated::parse_terminated(&content)?))
    }
}

pub struct Signature {
    is_static: Option<Token![static]>,
    return_type: ReturnType,
    parameters: ParameterList,
}
impl Parse for Signature {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            is_static: input.parse()?,
            return_type: input.parse()?,
            parameters: input.parse()?,
        })
    }
}

pub fn msig(sig: Signature) -> TokenStream {
    let constructor = if sig.is_static.is_none() {
        quote! { instance }
    } else {
        quote! { static_member }
    };

    let return_type = match sig.return_type.0 {
        None => quote! { ReturnType::VOID },
        Some(p) => quote! { ReturnType::new(#p) },
    };

    let params = sig.parameters.0.into_iter();

    quote! {
        MethodSignature::#constructor(#return_type, vec![#(Parameter::new(#params)),*])
    }
}

pub struct TypeName(Punctuated<Ident, Token![.]>);
impl Parse for TypeName {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(TypeName(Punctuated::parse_separated_nonempty(input)?))
    }
}

pub fn type_name(TypeName(qualified): TypeName) -> TokenStream {
    let mut names: Vec<_> = qualified.into_iter().collect();

    let name = names.pop();
    let namespace = if names.is_empty() {
        quote! { None }
    } else {
        quote! { Some(stringify!(#(#names).*)) }
    };

    quote! { (#namespace, stringify!(#name)) }
}

pub struct TypeRef(TypeName, External);
impl Parse for TypeRef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![in]>()?;
        let assembly = input.parse()?;
        Ok(TypeRef(name, assembly))
    }
}

pub fn type_ref(TypeRef(typename, External(asm)): TypeRef) -> TokenStream {
    let tn = type_name(typename);
    quote! {{
        let (ns, name) = #tn;
        ExternalTypeReference::new(ns.map(Into::into), name.into(), ResolutionScope::Assembly(#asm))
    }}
}

// just handle stuff like .ctor and .cctor for now
pub struct MethodName(Option<Token![.]>, Ident);
impl Parse for MethodName {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(MethodName(input.parse()?, input.parse()?))
    }
}
impl ToTokens for MethodName {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.0.to_tokens(tokens);
        self.1.to_tokens(tokens);
    }
}

pub struct MethodRef {
    parent: External,
    name: MethodName,
    signature: Signature,
}
impl Parse for MethodRef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let is_static = input.parse()?;
        let return_type = input.parse()?;
        let parent = input.parse()?;
        input.parse::<Token![::]>()?;
        let name = input.parse()?;
        let parameters = input.parse()?;

        Ok(MethodRef {
            parent,
            name,
            signature: Signature {
                is_static,
                return_type,
                parameters,
            },
        })
    }
}

pub fn method_ref(meth: MethodRef) -> TokenStream {
    let sig = msig(meth.signature);
    let name = meth.name;
    let parent = meth.parent;

    quote! {
        ExternalMethodReference::new(
            MethodReferenceParent::Type(#parent),
            stringify!(#name).into(),
            #sig
        )
    }
}
