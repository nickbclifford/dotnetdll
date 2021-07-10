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
    pub def_len: usize,
    pub ref_len: usize,
    pub specs: &'a Vec<TypeSpec>,
    pub blobs: &'a Blob<'a>,
}

pub fn user_type(TypeDefOrRefOrSpec(token): TypeDefOrRefOrSpec, ctx: &Context) -> Result<UserType> {
    use index::TokenTarget::*;
    let idx = token.index - 1;
    match token.target {
        Table(Kind::TypeDef) => {
            if idx < ctx.def_len {
                Ok(UserType::Definition(idx))
            } else {
                Err(format!(
                    "invalid type definition index {} for user type",
                    idx
                ))
            }
        }
        Table(Kind::TypeRef) => {
            if idx < ctx.ref_len {
                Ok(UserType::Reference(idx))
            } else {
                Err(format!(
                    "invalid type reference index {} for user type",
                    idx
                ))
            }
        }
        bad => Err(format!(
            "bad metadata token target {:?} for a user type",
            bad
        )),
    }
    .map_err(|e| DLLError::CLI(scroll::Error::Custom(e)))
}

pub fn custom_modifier(src: CustomMod, ctx: &Context) -> Result<CustomTypeModifier> {
    Ok(match src {
        CustomMod::Required(t) => CustomTypeModifier::Required(user_type(t, ctx)?),
        CustomMod::Optional(t) => CustomTypeModifier::Optional(user_type(t, ctx)?),
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
            opt_map_try!(cmod, |c| custom_modifier(c, ctx)),
            enclosing(*t, ctx)?,
        ),
        Ptr(cmod, pt) => BaseType::ValuePointer(
            opt_map_try!(cmod, |c| custom_modifier(c, ctx)),
            opt_map_try!(*pt, |t| enclosing(t, ctx)),
        ),
        Class(tok) | ValueType(tok) => BaseType::Type(TypeSource::User(user_type(tok, ctx)?)),
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
                base: user_type(tok, ctx)?,
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

macro_rules! def_type_idx {
    (fn $name:ident uses $sig:ident -> $t:ident) => {
        pub fn $name(idx: index::TypeDefOrRef, ctx: &Context) -> Result<$t> {
            match idx {
                TypeDefOrRef::TypeDef(i) => {
                    let idx = i - 1;
                    if idx < ctx.def_len {
                        Ok($t::Base(Box::new(BaseType::Type(TypeSource::User(
                            UserType::Definition(idx),
                        )))))
                    } else {
                        Err(format!(
                            "invalid type definition index {} while parsing a type",
                            idx
                        ))
                    }
                }
                TypeDefOrRef::TypeRef(i) => {
                    let idx = i - 1;
                    if idx < ctx.ref_len {
                        Ok($t::Base(Box::new(BaseType::Type(TypeSource::User(
                            UserType::Reference(idx),
                        )))))
                    } else {
                        Err(format!(
                            "invalid type reference index {} while parsing a type",
                            idx
                        ))
                    }
                }
                TypeDefOrRef::TypeSpec(i) => {
                    let idx = i - 1;
                    match ctx.specs.get(idx) {
                        Some(s) => Ok($sig(ctx.blobs.at_index(s.signature)?.pread(0)?, ctx)?),
                        None => Err(format!(
                            "invalid type spec index {} while parsing a type",
                            idx
                        )),
                    }
                }
                TypeDefOrRef::Null => Err("invalid null type index".to_string()),
            }
            .map_err(|e| DLLError::CLI(scroll::Error::Custom(e)))
        }
    };
}

def_type_idx!(fn member_type_idx uses member_type_sig -> MemberType);
def_type_idx!(fn method_type_idx uses method_type_sig -> MethodType);

macro_rules! type_source_error {
    ($bind:ident) => {
        Err(DLLError::CLI(scroll::Error::Custom(format!(
            "invalid type source {:?}",
            $bind
        ))))
    };
}

macro_rules! def_type_source {
    (fn $name:ident uses $idx:ident -> $t:ident) => {
        pub fn $name(idx: index::TypeDefOrRef, ctx: &Context) -> Result<TypeSource<$t>> {
            match $idx(idx, ctx)? {
                $t::Base(b) => match *b {
                    BaseType::Type(s) => Ok(s),
                    bad => type_source_error!(bad),
                },
                bad => type_source_error!(bad),
            }
        }
    };
}

def_type_source!(fn member_type_source uses member_type_idx -> MemberType);
def_type_source!(fn method_type_source uses method_type_idx -> MethodType);

pub fn parameter(p: Param, ctx: &Context) -> Result<signature::Parameter> {
    use signature::ParameterType::*;

    Ok(signature::Parameter(
        opt_map_try!(p.0, |c| custom_modifier(c, ctx)),
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
            opt_map_try!(sig.ret_type.0, |c| custom_modifier(c, ctx)),
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
