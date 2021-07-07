use super::{
    binary::{
        heap::{Blob, Heap},
        metadata::{
            index,
            table::{Kind, TypeSpec},
        },
        signature::{encoded::*, kinds::MethodDefSig},
    },
    dll::{DLLError, Result},
    resolved::{signature, types::*},
};
use crate::binary::metadata::index::TypeDefOrRef;
use scroll::Pread;

pub struct Context<'a> {
    pub specs: &'a Vec<TypeSpec>,
    pub blobs: &'a Blob<'a>,
}

pub fn user_type(TypeDefOrRefOrSpec(token): TypeDefOrRefOrSpec) -> Result<UserType> {
    use index::TokenTarget::*;
    let idx = token.index - 1;
    match token.target {
        Table(Kind::TypeDef) => Ok(UserType::Definition(idx)),
        Table(Kind::TypeRef) => Ok(UserType::Reference(idx)),
        bad => Err(format!(
            "bad metadata token target {:?} for a user type",
            bad
        )),
    }
    .map_err(|e| DLLError::CLI(scroll::Error::Custom(e)))
}

pub fn custom_modifier(src: CustomMod) -> Result<CustomTypeModifier> {
    Ok(match src {
        CustomMod::Required(t) => CustomTypeModifier::Required(user_type(t)?),
        CustomMod::Optional(t) => CustomTypeModifier::Optional(user_type(t)?),
    })
}

fn base_type_sig<'a, T>(
    sig: Type,
    enclosing: impl Fn(Type, &'a Context) -> Result<T>,
    ctx: &'a Context,
) -> Result<BaseType<T>> {
    use Type::*;

    Ok(match sig {
        Boolean => BaseType::Boolean,
        Char => BaseType::Char,
        Int8 => BaseType::Int8,
        UInt8 => BaseType::UInt8,
        Int16 => BaseType::Int16,
        UInt16 => BaseType::UInt16,
        Int32 => BaseType::Int32,
        UInt32 => BaseType::UInt32,
        Int64 => BaseType::Int64,
        UInt64 => BaseType::UInt64,
        Float32 => BaseType::Float32,
        Float64 => BaseType::Float64,
        IntPtr => BaseType::IntPtr,
        UIntPtr => BaseType::UIntPtr,
        Object => BaseType::Object,
        String => BaseType::String,
        Array(t, shape) => BaseType::Array(enclosing(*t, ctx)?, shape),
        SzArray(cmod, t) => BaseType::Vector(
            opt_map_try!(cmod, |c| custom_modifier(c)),
            enclosing(*t, ctx)?,
        ),
        Ptr(cmod, pt) => BaseType::ValuePointer(
            opt_map_try!(cmod, |c| custom_modifier(c)),
            opt_map_try!(*pt, |t| enclosing(t, ctx)),
        ),
        Class(tok) | ValueType(tok) => BaseType::Type(TypeSource::User(user_type(tok)?)),
        FnPtrDef(d) => BaseType::FunctionPointer(managed_method(*d, ctx)?),
        FnPtrRef(r) => {
            let mut new_sig = managed_method(r.method_def, ctx)?;
            new_sig.varargs = Some(
                r.varargs
                    .into_iter()
                    .map(|p| parameter(p, ctx))
                    .collect::<Result<_>>()?,
            );
            BaseType::FunctionPointer(new_sig)
        }
        GenericInstClass(tok, types) | GenericInstValueType(tok, types) => {
            BaseType::Type(TypeSource::Generic(GenericInstantiation {
                base: user_type(tok)?,
                parameters: types
                    .into_iter()
                    .map(|t| enclosing(t, ctx))
                    .collect::<Result<_>>()?,
            }))
        }
        bad => {
            return Err(DLLError::CLI(scroll::Error::Custom(format!(
                "invalid type signature for base type {:?}",
                bad
            ))))
        }
    })
}

pub fn member_type_sig(sig: Type, ctx: &Context) -> Result<MemberType> {
    Ok(match sig {
        Type::Var(idx) => MemberType::TypeGeneric(idx as usize),
        rest => MemberType::Base(Box::new(base_type_sig(rest, member_type_sig, ctx)?)),
    })
}

pub fn method_type_sig(sig: Type, ctx: &Context) -> Result<MethodType> {
    Ok(match sig {
        Type::Var(idx) => MethodType::TypeGeneric(idx as usize),
        Type::MVar(idx) => MethodType::MethodGeneric(idx as usize),
        rest => MethodType::Base(Box::new(base_type_sig(rest, method_type_sig, ctx)?)),
    })
}

pub fn member_type_idx(idx: index::TypeDefOrRef, ctx: &Context) -> Result<MemberType> {
    match idx {
        TypeDefOrRef::TypeDef(i) => Ok(MemberType::Base(Box::new(BaseType::Type(
            TypeSource::User(UserType::Definition(i - 1)),
        )))),
        TypeDefOrRef::TypeRef(i) => Ok(MemberType::Base(Box::new(BaseType::Type(
            TypeSource::User(UserType::Reference(i - 1)),
        )))),
        TypeDefOrRef::TypeSpec(i) => member_type_sig(
            ctx.blobs.at_index(ctx.specs[i - 1].signature)?.pread(0)?,
            ctx,
        ),
        TypeDefOrRef::Null => Err(DLLError::CLI(scroll::Error::Custom(
            "invalid null type index".to_string(),
        ))),
    }
}

pub fn method_type_idx(idx: index::TypeDefOrRef, ctx: &Context) -> Result<MethodType> {
    match idx {
        TypeDefOrRef::TypeDef(i) => Ok(MethodType::Base(Box::new(BaseType::Type(
            TypeSource::User(UserType::Definition(i - 1)),
        )))),
        TypeDefOrRef::TypeRef(i) => Ok(MethodType::Base(Box::new(BaseType::Type(
            TypeSource::User(UserType::Reference(i - 1)),
        )))),
        TypeDefOrRef::TypeSpec(i) => method_type_sig(
            ctx.blobs.at_index(ctx.specs[i - 1].signature)?.pread(0)?,
            ctx,
        ),
        TypeDefOrRef::Null => Err(DLLError::CLI(scroll::Error::Custom(
            "invalid null type index".to_string(),
        ))),
    }
}

pub fn parameter(p: Param, ctx: &Context) -> Result<signature::Parameter> {
    use signature::ParameterType::*;

    Ok(signature::Parameter(
        opt_map_try!(p.0, |c| custom_modifier(c)),
        match p.1 {
            ParamType::Type(t) => Value(method_type_sig(t, ctx)?),
            ParamType::ByRef(t) => Ref(method_type_sig(t, ctx)?),
            ParamType::TypedByRef => TypedReference,
        },
    ))
}

pub fn managed_method(sig: MethodDefSig, ctx: &Context) -> Result<signature::ManagedMethod> {
    use signature::*;
    Ok(ManagedMethod {
        instance: sig.has_this,
        explicit_this: sig.explicit_this,
        calling_convention: sig.calling_convention,
        parameters: sig
            .params
            .into_iter()
            .map(|p| parameter(p, ctx))
            .collect::<Result<_>>()?,
        return_type: ReturnType(
            opt_map_try!(sig.ret_type.0, |c| custom_modifier(c)),
            match sig.ret_type.1 {
                RetTypeType::Type(t) => Some(ParameterType::Value(method_type_sig(t, ctx)?)),
                RetTypeType::ByRef(t) => Some(ParameterType::Ref(method_type_sig(t, ctx)?)),
                RetTypeType::TypedByRef => Some(ParameterType::TypedReference),
                RetTypeType::Void => None,
            },
        ),
        varargs: None,
    })
}
