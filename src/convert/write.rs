use crate::{
    binary::{
        heap::{BlobWriter, HeapWriter},
        metadata::{
            index::{Blob, TypeDefOrRef},
            table::TypeSpec,
        },
        signature::{
            encoded::{CustomMod, Param, ParamType, RetType, RetTypeType, Type as SType},
            kinds::StandAloneMethodSig,
        },
    },
    dll::Result,
    resolved::{signature::*, types::*},
};
use scroll::{ctx::TryIntoCtx, Pwrite};
use std::collections::HashMap;

pub struct Context<'a> {
    pub blobs: &'a mut BlobWriter,
    pub specs: &'a mut Vec<TypeSpec>,
    pub type_cache: &'a mut HashMap<u64, TypeDefOrRef>,
    pub blob_cache: &'a mut HashMap<u64, Blob>,
}

pub fn index(t: &impl TypeKind, ctx: &mut Context) -> Result<TypeDefOrRef> {
    let hash = crate::utils::hash(t);

    if let Some(&i) = ctx.type_cache.get(&hash) {
        return Ok(i);
    }

    let result = t.into_idx(ctx)?;

    ctx.type_cache.insert(hash, result);

    Ok(result)
}

pub fn blob_index(t: &impl TypeKind, ctx: &mut Context) -> Result<Blob> {
    let hash = crate::utils::hash(t);

    if let Some(&i) = ctx.blob_cache.get(&hash) {
        return Ok(i);
    }

    let result = sig_blob(t.into_sig(ctx)?, ctx)?;

    ctx.blob_cache.insert(hash, result);

    Ok(result)
}

pub fn user_index(t: UserType) -> TypeDefOrRef {
    match t {
        UserType::Definition(d) => TypeDefOrRef::TypeDef(d.0 + 1),
        UserType::Reference(r) => TypeDefOrRef::TypeRef(r.0 + 1),
    }
}

pub trait TypeKind: std::hash::Hash {
    fn into_sig(&self, ctx: &mut Context) -> Result<SType>;
    fn into_idx(&self, ctx: &mut Context) -> Result<TypeDefOrRef>;
}

impl TypeKind for MemberType {
    fn into_sig(&self, ctx: &mut Context) -> Result<SType> {
        match self {
            MemberType::Base(b) => base_sig(&**b, ctx),
            MemberType::TypeGeneric(i) => Ok(SType::Var(*i as u32)),
        }
    }

    fn into_idx(&self, ctx: &mut Context) -> Result<TypeDefOrRef> {
        match self {
            MemberType::Base(b) => base_index(&**b, ctx),
            MemberType::TypeGeneric(i) => sig_index(SType::Var(*i as u32), ctx),
        }
    }
}

impl TypeKind for MethodType {
    fn into_sig(&self, ctx: &mut Context) -> Result<SType> {
        match self {
            MethodType::Base(b) => base_sig(&**b, ctx),
            MethodType::TypeGeneric(i) => Ok(SType::Var(*i as u32)),
            MethodType::MethodGeneric(i) => Ok(SType::MVar(*i as u32)),
        }
    }

    fn into_idx(&self, ctx: &mut Context) -> Result<TypeDefOrRef> {
        match self {
            MethodType::Base(b) => base_index(&**b, ctx),
            MethodType::TypeGeneric(i) => sig_index(SType::Var(*i as u32), ctx),
            MethodType::MethodGeneric(i) => sig_index(SType::MVar(*i as u32), ctx),
        }
    }
}

pub fn source_index(t: &TypeSource<impl TypeKind>, ctx: &mut Context) -> Result<TypeDefOrRef> {
    match t {
        TypeSource::User(u) => Ok(user_index(*u)),
        // TODO: we have no way of knowing whether the instantiation is for a class or value type
        TypeSource::Generic(_) => todo!(),
    }
}

pub fn base_index<T: TypeKind>(base: &BaseType<T>, ctx: &mut Context) -> Result<TypeDefOrRef> {
    Ok(match base {
        BaseType::Type(t) => source_index(t, ctx)?,
        rest => sig_index(base_sig(rest, ctx)?, ctx)?,
    })
}

pub fn sig_blob(sig: impl TryIntoCtx<Error = scroll::Error>, ctx: &mut Context) -> Result<Blob> {
    // TODO: scroll expanding buffer
    let mut bytes = vec![];

    bytes.pwrite(sig, 0)?;

    Ok(ctx.blobs.write(&bytes)?)
}

fn sig_index(sig: SType, ctx: &mut Context) -> Result<TypeDefOrRef> {
    let len = ctx.specs.len();

    let t = TypeSpec {
        signature: sig_blob(sig, ctx)?,
    };
    ctx.specs.push(t);

    Ok(TypeDefOrRef::TypeSpec(len))
}

fn base_sig<T: TypeKind>(base: &BaseType<T>, ctx: &mut Context) -> Result<SType> {
    use BaseType::*;

    Ok(match base {
        Boolean => SType::Boolean,
        Char => SType::Char,
        Int8 => SType::Int8,
        UInt8 => SType::UInt8,
        Int16 => SType::Int16,
        UInt16 => SType::UInt16,
        Int32 => SType::Int32,
        UInt32 => SType::UInt32,
        Int64 => SType::Int64,
        UInt64 => SType::UInt64,
        Float32 => SType::Float32,
        Float64 => SType::Float64,
        IntPtr => SType::IntPtr,
        UIntPtr => SType::UIntPtr,
        Object => SType::Object,
        String => SType::String,
        Vector(m, t) => SType::SzArray(custom_modifiers(m), Box::new(t.into_sig(ctx)?)),
        Array(t, shape) => SType::Array(Box::new(t.into_sig(ctx)?), shape.clone()),
        ValuePointer(m, opt) => SType::Ptr(
            custom_modifiers(m),
            match opt {
                Some(t) => Some(Box::new(t.into_sig(ctx)?)),
                None => None,
            },
        ),
        FunctionPointer(sig) => SType::FnPtr(Box::new(StandAloneMethodSig {
            has_this: sig.instance,
            explicit_this: sig.explicit_this,
            calling_convention: sig.calling_convention,
            ret_type: ret_type_sig(&sig.return_type, ctx)?,
            params: sig
                .parameters
                .iter()
                .map(|p| parameter_sig(p, ctx))
                .collect::<Result<_>>()?,
            varargs: match &sig.varargs {
                Some(p) => p
                    .iter()
                    .map(|p| parameter_sig(p, ctx))
                    .collect::<Result<_>>()?,
                None => vec![],
            },
        })),
        _ => unreachable!(),
    })
}

pub fn custom_modifiers(mods: &[CustomTypeModifier]) -> Vec<CustomMod> {
    mods.iter()
        .map(|m| match m {
            CustomTypeModifier::Optional(t) => CustomMod::Optional(user_index(*t).into()),
            CustomTypeModifier::Required(t) => CustomMod::Required(user_index(*t).into()),
        })
        .collect()
}

fn parameter_sig(p: &Parameter, ctx: &mut Context) -> Result<Param> {
    Ok(Param(
        custom_modifiers(&p.0),
        match &p.1 {
            ParameterType::Value(v) => ParamType::Type(v.into_sig(ctx)?),
            ParameterType::Ref(r) => ParamType::ByRef(r.into_sig(ctx)?),
            ParameterType::TypedReference => ParamType::TypedByRef,
        },
    ))
}

pub fn parameter(p: &Parameter, ctx: &mut Context) -> Result<Blob> {
    sig_blob(parameter_sig(p, ctx)?, ctx)
}

fn ret_type_sig(p: &ReturnType, ctx: &mut Context) -> Result<RetType> {
    Ok(RetType(
        custom_modifiers(&p.0),
        match &p.1 {
            Some(ParameterType::Value(v)) => RetTypeType::Type(v.into_sig(ctx)?),
            Some(ParameterType::Ref(r)) => RetTypeType::ByRef(r.into_sig(ctx)?),
            Some(ParameterType::TypedReference) => RetTypeType::TypedByRef,
            None => RetTypeType::Void,
        },
    ))
}
