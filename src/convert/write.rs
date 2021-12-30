use crate::{
    binary::{
        heap::{BlobWriter, HeapWriter},
        metadata::{
            index::{Blob, TypeDefOrRef},
            table::TypeSpec,
        },
        signature::{
            encoded::{CustomMod, Param, ParamType, RetType, RetTypeType, Type as SType},
            kinds::{MethodDefSig, StandAloneMethodSig},
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

    let result = t.as_idx(ctx)?;

    ctx.type_cache.insert(hash, result);

    Ok(result)
}

pub fn blob_index(t: &impl TypeKind, ctx: &mut Context) -> Result<Blob> {
    let hash = crate::utils::hash(t);

    if let Some(&i) = ctx.blob_cache.get(&hash) {
        return Ok(i);
    }

    let result = sig_blob(t.as_sig(ctx)?, ctx)?;

    ctx.blob_cache.insert(hash, result);

    Ok(result)
}

pub fn user_index(t: UserType) -> TypeDefOrRef {
    match t {
        UserType::Definition(d) => TypeDefOrRef::TypeDef(d.0 + 1),
        UserType::Reference(r) => TypeDefOrRef::TypeRef(r.0 + 1),
    }
}

pub trait TypeKind: Sized + std::hash::Hash {
    fn as_sig(&self, ctx: &mut Context) -> Result<SType>;
    fn as_idx(&self, ctx: &mut Context) -> Result<TypeDefOrRef>;
    fn as_base(&self) -> Option<&BaseType<Self>>;
}

impl TypeKind for MemberType {
    fn as_sig(&self, ctx: &mut Context) -> Result<SType> {
        match self {
            MemberType::Base(b) => base_sig(&**b, ctx),
            MemberType::TypeGeneric(i) => Ok(SType::Var(*i as u32)),
        }
    }

    fn as_idx(&self, ctx: &mut Context) -> Result<TypeDefOrRef> {
        match self {
            MemberType::Base(b) => base_index(&**b, ctx),
            MemberType::TypeGeneric(i) => sig_index(SType::Var(*i as u32), ctx),
        }
    }

    fn as_base(&self) -> Option<&BaseType<Self>> {
        match self {
            MemberType::Base(b) => Some(&**b),
            _ => None,
        }
    }
}

impl TypeKind for MethodType {
    fn as_sig(&self, ctx: &mut Context) -> Result<SType> {
        match self {
            MethodType::Base(b) => base_sig(&**b, ctx),
            MethodType::TypeGeneric(i) => Ok(SType::Var(*i as u32)),
            MethodType::MethodGeneric(i) => Ok(SType::MVar(*i as u32)),
        }
    }

    fn as_idx(&self, ctx: &mut Context) -> Result<TypeDefOrRef> {
        match self {
            MethodType::Base(b) => base_index(&**b, ctx),
            MethodType::TypeGeneric(i) => sig_index(SType::Var(*i as u32), ctx),
            MethodType::MethodGeneric(i) => sig_index(SType::MVar(*i as u32), ctx),
        }
    }

    fn as_base(&self) -> Option<&BaseType<Self>> {
        match self {
            MethodType::Base(b) => Some(&**b),
            _ => None,
        }
    }
}

pub fn source_index(t: &TypeSource<impl TypeKind>, ctx: &mut Context) -> Result<TypeDefOrRef> {
    Ok(match t {
        TypeSource::User(u) => user_index(*u),
        TypeSource::Generic(g) => {
            let base = user_index(g.base).into();
            let params = g
                .parameters
                .iter()
                .map(|g| g.as_sig(ctx))
                .collect::<Result<_>>()?;
            sig_index(
                match g.base_kind {
                    InstantiationKind::Class => SType::GenericInstClass(base, params),
                    InstantiationKind::ValueType => SType::GenericInstValueType(base, params),
                },
                ctx,
            )?
        }
    })
}

pub fn base_index<T: TypeKind>(base: &BaseType<T>, ctx: &mut Context) -> Result<TypeDefOrRef> {
    Ok(match base {
        BaseType::Type(t) => source_index(t, ctx)?,
        rest => sig_index(base_sig(rest, ctx)?, ctx)?,
    })
}

pub fn sig_blob(sig: impl TryIntoCtx<Error = scroll::Error>, ctx: &mut Context) -> Result<Blob> {
    // TODO: scroll expanding buffer, maybe preallocated scratch buffer?
    let mut bytes = vec![];

    bytes.pwrite(sig, 0)?;

    Ok(ctx.blobs.write(&bytes)?)
}

fn sig_index(
    sig: impl TryIntoCtx<Error = scroll::Error>,
    ctx: &mut Context,
) -> Result<TypeDefOrRef> {
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
        Vector(m, t) => SType::SzArray(custom_modifiers(m), Box::new(t.as_sig(ctx)?)),
        Array(t, shape) => SType::Array(Box::new(t.as_sig(ctx)?), shape.clone()),
        ValuePointer(m, opt) => SType::Ptr(
            custom_modifiers(m),
            match opt {
                Some(t) => Some(Box::new(t.as_sig(ctx)?)),
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
            ParameterType::Value(v) => ParamType::Type(v.as_sig(ctx)?),
            ParameterType::Ref(r) => ParamType::ByRef(r.as_sig(ctx)?),
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
            Some(ParameterType::Value(v)) => RetTypeType::Type(v.as_sig(ctx)?),
            Some(ParameterType::Ref(r)) => RetTypeType::ByRef(r.as_sig(ctx)?),
            Some(ParameterType::TypedReference) => RetTypeType::TypedByRef,
            None => RetTypeType::Void,
        },
    ))
}

fn method_def_sig(p: &ManagedMethod, ctx: &mut Context) -> Result<MethodDefSig> {
    Ok(MethodDefSig {
        has_this: p.instance,
        explicit_this: p.explicit_this,
        calling_convention: p.calling_convention,
        ret_type: ret_type_sig(&p.return_type, ctx)?,
        params: p
            .parameters
            .iter()
            .map(|p| parameter_sig(p, ctx))
            .collect::<Result<_>>()?,
    })
}

pub fn method_def(p: &ManagedMethod, ctx: &mut Context) -> Result<Blob> {
    sig_blob(method_def_sig(p, ctx)?, ctx)
}

pub fn idx_with_modifiers(
    t: &impl TypeKind,
    mods: &[CustomTypeModifier],
    ctx: &mut Context,
) -> Result<TypeDefOrRef> {
    if let Some(BaseType::Type(TypeSource::User(u))) = t.as_base() {
        Ok(user_index(*u))
    } else {
        let sig = t.as_sig(ctx)?;
        let mods = custom_modifiers(mods);

        struct Wrapper(Vec<CustomMod>, SType);
        impl TryIntoCtx for Wrapper {
            type Error = scroll::Error;

            fn try_into_ctx(
                self,
                buf: &mut [u8],
                _: (),
            ) -> std::result::Result<usize, Self::Error> {
                let offset = &mut 0;

                for m in self.0 {
                    buf.gwrite(m, offset)?;
                }
                buf.gwrite(self.1, offset)?;

                Ok(*offset)
            }
        }

        sig_index(Wrapper(mods, sig), ctx)
    }
}
