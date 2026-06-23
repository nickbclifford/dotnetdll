use crate::{
    binary::{metadata::index::TypeDefOrRef, signature::encoded::Type},
    dll::{DLLError, ResolveError},
    resolved::types::{BaseType, MemberType, MethodType},
};

pub mod read;
pub mod write;

#[inline]
fn as_resolve(err: &DLLError, context: &'static str) -> ResolveError {
    match err {
        DLLError::Resolve(resolve) => *resolve,
        _ => ResolveError::LazyLookupFailed(context),
    }
}

pub trait TypeKind: Sized + std::hash::Hash + std::fmt::Debug {
    fn from_base(b: BaseType<Self>) -> Self;
    fn from_sig(t: Type, ctx: &read::Context) -> std::result::Result<Self, ResolveError>;

    fn as_sig(&self, ctx: &mut write::Context) -> std::result::Result<Type, ResolveError>;
    fn as_idx(&self, ctx: &mut write::Context) -> std::result::Result<TypeDefOrRef, ResolveError>;
    fn as_base(&self) -> Option<&BaseType<Self>>;

    fn into_base(self) -> Option<BaseType<Self>>;
}

impl TypeKind for MemberType {
    fn from_base(b: BaseType<Self>) -> Self {
        MemberType::Base(Box::new(b))
    }

    fn from_sig(t: Type, ctx: &read::Context) -> std::result::Result<Self, ResolveError> {
        Ok(match t {
            Type::Var(idx) => MemberType::TypeGeneric(idx as usize),
            rest => MemberType::Base(Box::new(
                read::base_type_sig(rest, ctx).map_err(|err| as_resolve(&err, "member type from signature"))?,
            )),
        })
    }

    fn as_sig(&self, ctx: &mut write::Context) -> std::result::Result<Type, ResolveError> {
        match self {
            MemberType::Base(b) => {
                write::base_sig(&**b, ctx).map_err(|err| as_resolve(&err, "member type to signature"))
            }
            MemberType::TypeGeneric(i) => Ok(Type::Var(*i as u32)),
        }
    }

    fn as_idx(&self, ctx: &mut write::Context) -> std::result::Result<TypeDefOrRef, ResolveError> {
        match self {
            MemberType::Base(b) => {
                write::base_index(&**b, ctx).map_err(|err| as_resolve(&err, "member type to index"))
            }
            MemberType::TypeGeneric(i) => {
                write::into_index(Type::Var(*i as u32), ctx).map_err(|err| as_resolve(&err, "member generic to index"))
            }
        }
    }

    fn as_base(&self) -> Option<&BaseType<Self>> {
        match self {
            MemberType::Base(b) => Some(&**b),
            _ => None,
        }
    }

    fn into_base(self) -> Option<BaseType<Self>> {
        match self {
            MemberType::Base(b) => Some(*b),
            _ => None,
        }
    }
}

impl TypeKind for MethodType {
    fn from_base(b: BaseType<Self>) -> Self {
        MethodType::Base(Box::new(b))
    }

    fn from_sig(t: Type, ctx: &read::Context) -> std::result::Result<Self, ResolveError> {
        Ok(match t {
            Type::Var(idx) => MethodType::TypeGeneric(idx as usize),
            Type::MVar(idx) => MethodType::MethodGeneric(idx as usize),
            rest => MethodType::Base(Box::new(
                read::base_type_sig(rest, ctx).map_err(|err| as_resolve(&err, "method type from signature"))?,
            )),
        })
    }

    fn as_sig(&self, ctx: &mut write::Context) -> std::result::Result<Type, ResolveError> {
        match self {
            MethodType::Base(b) => {
                write::base_sig(&**b, ctx).map_err(|err| as_resolve(&err, "method type to signature"))
            }
            MethodType::TypeGeneric(i) => Ok(Type::Var(*i as u32)),
            MethodType::MethodGeneric(i) => Ok(Type::MVar(*i as u32)),
        }
    }

    fn as_idx(&self, ctx: &mut write::Context) -> std::result::Result<TypeDefOrRef, ResolveError> {
        match self {
            MethodType::Base(b) => {
                write::base_index(&**b, ctx).map_err(|err| as_resolve(&err, "method type to index"))
            }
            MethodType::TypeGeneric(i) => {
                write::into_index(Type::Var(*i as u32), ctx).map_err(|err| as_resolve(&err, "method type generic to index"))
            }
            MethodType::MethodGeneric(i) => {
                write::into_index(Type::MVar(*i as u32), ctx).map_err(|err| as_resolve(&err, "method generic to index"))
            }
        }
    }

    fn as_base(&self) -> Option<&BaseType<Self>> {
        match self {
            MethodType::Base(b) => Some(&**b),
            _ => None,
        }
    }

    fn into_base(self) -> Option<BaseType<Self>> {
        match self {
            MethodType::Base(b) => Some(*b),
            _ => None,
        }
    }
}
