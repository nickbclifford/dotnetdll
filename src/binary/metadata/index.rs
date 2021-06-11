use super::table::{HasKind, Kind};
use bitvec::{order::Lsb0, slice::BitSlice};
use num_traits::FromPrimitive;
use scroll::{ctx::TryFromCtx, Pread};
use std::{collections::HashMap, marker::PhantomData};

use dotnetdll_macros::coded_index;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenTarget {
    Table(Kind),
    UserString,
}

#[derive(Clone, Copy, Debug)]
pub struct Token {
    pub target: TokenTarget,
    pub index: usize,
}

impl TryFromCtx<'_> for Token {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let num: u32 = from.gread_with(offset, scroll::LE)?;

        let tag = (num >> 24) as u8;

        let index = (num & 0xFFFFFF) as usize;

        Ok((
            Token {
                target: if tag == 0x70 {
                    TokenTarget::UserString
                } else {
                    TokenTarget::Table(Kind::from_u8(tag).unwrap())
                },
                index,
            },
            *offset,
        ))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Sizes<'a> {
    pub heap: &'a BitSlice<Lsb0, u8>,
    pub tables: &'a HashMap<Kind, u32>,
}

macro_rules! uint_impl {
    ($ty:ty) => {
        impl<'a> TryFromCtx<'a, Sizes<'a>> for $ty {
            type Error = scroll::Error;

            fn try_from_ctx(from: &'a [u8], _: Sizes<'a>) -> Result<(Self, usize), Self::Error> {
                TryFromCtx::try_from_ctx(from, scroll::LE)
            }
        }
    };
}

uint_impl!(u8);
uint_impl!(u16);
uint_impl!(u32);
uint_impl!(u64);

macro_rules! heap_index {
    ($name:ident, $idx:literal) => {
        #[derive(Debug, Copy, Clone)]
        pub struct $name(pub usize);
        impl<'a> TryFromCtx<'a, Sizes<'a>> for $name {
            type Error = scroll::Error;

            fn try_from_ctx(
                from: &'a [u8],
                sizes: Sizes<'a>,
            ) -> Result<(Self, usize), Self::Error> {
                let offset = &mut 0;

                let idx = if sizes.heap[$idx] {
                    from.gread_with::<u32>(offset, scroll::LE)? as usize
                } else {
                    from.gread_with::<u16>(offset, scroll::LE)? as usize
                };

                Ok(($name(idx), *offset))
            }
        }
    };
}

heap_index!(String, 0);
heap_index!(GUID, 1);
heap_index!(Blob, 2);

#[derive(Debug, Copy, Clone)]
pub struct Simple<T: HasKind>(pub usize, std::marker::PhantomData<T>);
impl<'a, T: 'a + HasKind> TryFromCtx<'a, Sizes<'a>> for Simple<T> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], sizes: Sizes<'a>) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let idx = if *sizes.tables.get(&T::get_kind()).unwrap_or(&0) < (1 << 16) {
            from.gread_with::<u16>(offset, scroll::LE)? as usize
        } else {
            from.gread_with::<u32>(offset, scroll::LE)? as usize
        };

        Ok((Simple(idx, PhantomData), *offset))
    }
}

coded_index!(TypeDefOrRef, {
    TypeDef,
    TypeRef,
    TypeSpec
});
coded_index!(HasConstant, {
    Field,
    Param,
    Property
});
coded_index!(HasCustomAttribute, {
    MethodDef,
    Field,
    TypeRef,
    TypeDef,
    Param,
    InterfaceImpl,
    MemberRef,
    Module,
    DeclSecurity,
    Property,
    Event,
    StandAloneSig,
    ModuleRef,
    TypeSpec,
    Assembly,
    AssemblyRef,
    File,
    ExportedType,
    ManifestResource,
    GenericParam,
    GenericParamConstraint,
    MethodSpec
});
coded_index!(HasFieldMarshal, {
    Field,
    Param
});
coded_index!(HasDeclSecurity, {
    TypeDef,
    MethodDef,
    Assembly
});
coded_index!(MemberRefParent, {
    TypeDef,
    TypeRef,
    ModuleRef,
    MethodDef,
    TypeSpec
});
coded_index!(HasSemantics, {
    Event,
    Property
});
coded_index!(MethodDefOrRef, {
    MethodDef,
    MemberRef
});
coded_index!(MemberForwarded, {
    Field,
    MethodDef
});
coded_index!(Implementation, {
    File,
    AssemblyRef,
    ExportedType
});
coded_index!(CustomAttributeType, {
    Unused,
    Unused,
    MethodDef,
    MemberRef,
    Unused
});
coded_index!(ResolutionScope, {
    Module,
    ModuleRef,
    AssemblyRef,
    TypeRef
});
coded_index!(TypeOrMethodDef, {
    TypeDef,
    MethodDef
});
