use crate::{
    binary::{metadata::index::TypeDefOrRef, signature::encoded::Type},
    dll::Result,
    resolved::types::{BaseType, MemberType, MethodType},
};

pub mod read;
pub mod write;

pub trait TypeKind: Sized + std::hash::Hash + std::fmt::Debug {
    fn from_base(b: BaseType<Self>) -> Self;
    fn from_sig(t: Type, ctx: &read::Context) -> Result<Self>;

    fn as_sig(&self, ctx: &mut write::Context) -> Result<Type>;
    fn as_idx(&self, ctx: &mut write::Context) -> Result<TypeDefOrRef>;
    fn as_base(&self) -> Option<&BaseType<Self>>;

    fn into_base(self) -> Option<BaseType<Self>>;
}

impl TypeKind for MemberType {
    fn from_base(b: BaseType<Self>) -> Self {
        MemberType::Base(Box::new(b))
    }

    fn from_sig(t: Type, ctx: &read::Context) -> Result<Self> {
        Ok(match t {
            Type::Var(idx) => MemberType::TypeGeneric(idx as usize),
            rest => MemberType::Base(Box::new(read::base_type_sig(rest, ctx)?)),
        })
    }

    fn as_sig(&self, ctx: &mut write::Context) -> Result<Type> {
        match self {
            MemberType::Base(b) => write::base_sig(&**b, ctx),
            MemberType::TypeGeneric(i) => Ok(Type::Var(*i as u32)),
        }
    }

    fn as_idx(&self, ctx: &mut write::Context) -> Result<TypeDefOrRef> {
        match self {
            MemberType::Base(b) => write::base_index(&**b, ctx),
            MemberType::TypeGeneric(i) => write::into_index(Type::Var(*i as u32), ctx),
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

    fn from_sig(t: Type, ctx: &read::Context) -> Result<Self> {
        Ok(match t {
            Type::Var(idx) => MethodType::TypeGeneric(idx as usize),
            Type::MVar(idx) => MethodType::MethodGeneric(idx as usize),
            rest => MethodType::Base(Box::new(read::base_type_sig(rest, ctx)?)),
        })
    }

    fn as_sig(&self, ctx: &mut write::Context) -> Result<Type> {
        match self {
            MethodType::Base(b) => write::base_sig(&**b, ctx),
            MethodType::TypeGeneric(i) => Ok(Type::Var(*i as u32)),
            MethodType::MethodGeneric(i) => Ok(Type::MVar(*i as u32)),
        }
    }

    fn as_idx(&self, ctx: &mut write::Context) -> Result<TypeDefOrRef> {
        match self {
            MethodType::Base(b) => write::base_index(&**b, ctx),
            MethodType::TypeGeneric(i) => write::into_index(Type::Var(*i as u32), ctx),
            MethodType::MethodGeneric(i) => write::into_index(Type::MVar(*i as u32), ctx),
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
