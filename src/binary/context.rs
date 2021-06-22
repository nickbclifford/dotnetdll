use super::{
    heap,
    metadata::{index, table::*},
    signature::encoded::*,
};
use heap::Heap;
use scroll::Pread;

// TODO: which of these should be references?

#[derive(Copy, Clone)]
pub struct Context<'a> {
    pub strs: &'a heap::Strings<'a>,
    pub blobs: &'a heap::Blob<'a>,
    pub tables: &'a Tables,
}

pub trait ToCtxString {
    fn to_string(&self, ctx: Context) -> String;
}

macro_rules! basic_impl {
    ($t:ident) => {
        impl ToCtxString for $t {
            fn to_string(&self, ctx: Context) -> String {
                format!(
                    "{}.{}",
                    ctx.strs.at_index(self.type_namespace).unwrap(),
                    ctx.strs.at_index(self.type_name).unwrap()
                )
            }
        }
    };
}

basic_impl!(TypeDef);
basic_impl!(TypeRef);

impl ToCtxString for TypeSpec {
    fn to_string(&self, ctx: Context) -> String {
        let sig = ctx
            .blobs
            .at_index(self.signature)
            .and_then(|b| b.pread::<Type>(0))
            .unwrap();

        sig.to_string(ctx)
    }
}

impl TypeDefOrRefOrSpec {
    pub fn do_with_ctx<T>(
        &self,
        ctx: Context,
        do_def: impl FnOnce(TypeDef) -> T,
        do_ref: impl FnOnce(TypeRef) -> T,
        do_spec: impl FnOnce(TypeSpec) -> T,
    ) -> T {
        use index::*;
        let Token { target, index } = self.0;
        match target {
            TokenTarget::Table(Kind::TypeDef) => do_def(ctx.tables.type_def[index - 1]),
            TokenTarget::Table(Kind::TypeRef) => do_ref(ctx.tables.type_ref[index - 1]),
            TokenTarget::Table(Kind::TypeSpec) => do_spec(ctx.tables.type_spec[index - 1]),
            _ => unreachable!(),
        }
    }
}

impl ToCtxString for TypeDefOrRefOrSpec {
    fn to_string(&self, ctx: Context) -> String {
        self.do_with_ctx(
            ctx,
            |d| d.to_string(ctx),
            |r| r.to_string(ctx),
            |s| s.to_string(ctx),
        )
    }
}

impl ToCtxString for Type {
    fn to_string(&self, ctx: Context) -> String {
        use Type::*;

        match self {
            Boolean | Char | Int16 | UInt16 | Int32 | UInt32 | Int64 | UInt64 | IntPtr
            | UIntPtr | String | Object => format!("System.{:?}", self),
            Int8 => "System.SByte".to_string(),
            UInt8 => "System.Byte".to_string(),
            Float32 => "System.Float".to_string(),
            Float64 => "System.Double".to_string(),
            Array(t, shape) => {
                format!("{}{}", t.to_string(ctx), "[]".repeat(shape.rank))
            }
            Class(t) => t.to_string(ctx),
            FnPtrDef(_) => todo!(),
            FnPtrRef(_) => todo!(),
            GenericInstClass(token, types) | GenericInstValueType(token, types) => format!(
                "{}<{}>",
                token.to_string(ctx),
                types
                    .iter()
                    .map(|t| t.to_string(ctx))
                    .collect::<Vec<std::string::String>>()
                    .join(", ")
            ),
            MVar(n) => format!("M{}", n),
            Ptr(_, ptrt) => format!(
                "{}*",
                match &**ptrt {
                    None => "void".to_string(),
                    Some(t) => t.to_string(ctx),
                }
            ),
            SzArray(_, t) => format!("{}[]", t.to_string(ctx)),
            ValueType(token) => token.to_string(ctx),
            Var(n) => format!("T{}", n),
        }
    }
}

impl ToCtxString for index::TypeDefOrRef {
    fn to_string(&self, ctx: Context) -> String {
        use index::TypeDefOrRef::*;
        match self {
            TypeDef(i) => ctx.tables.type_def[i - 1].to_string(ctx),
            TypeRef(i) => ctx.tables.type_ref[i - 1].to_string(ctx),
            TypeSpec(i) => ctx.tables.type_spec[i - 1].to_string(ctx),
        }
    }
}
