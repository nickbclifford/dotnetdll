use super::table::{HasKind, Kind};
use bitvec::{order::Lsb0, slice::BitSlice};
use num_traits::FromPrimitive;
use scroll::{ctx::TryFromCtx, Endian, Pread};
use std::{collections::HashMap, marker::PhantomData};

// paste! macro
use paste::paste;

#[derive(Clone, Copy, Debug)]
pub struct Token {
    pub table: Kind,
    pub index: usize,
}

impl<'a> TryFromCtx<'a, Endian> for Token {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let num: u32 = from.gread_with(offset, ctx)?;

        let table = Kind::from_u32(num >> 24).unwrap();
        let index = (num & 0xFFFFFF) as usize;

        Ok((Token { table, index }, *offset))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Sizes<'a> {
    pub heap: &'a BitSlice<Lsb0, u8>,
    pub tables: &'a HashMap<Kind, u32>,
}

#[derive(Clone, Copy, Debug)]
pub struct Context<'a>(pub Endian, pub Sizes<'a>);

macro_rules! uint_impl {
    ($ty:ty) => {
        impl<'a> TryFromCtx<'a, Context<'a>> for $ty {
            type Error = scroll::Error;

            fn try_from_ctx(
                from: &'a [u8],
                Context(end, _): Context<'a>,
            ) -> Result<(Self, usize), Self::Error> {
                TryFromCtx::try_from_ctx(from, end)
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
        impl<'a> TryFromCtx<'a, Context<'a>> for $name {
            type Error = scroll::Error;

            fn try_from_ctx(
                from: &'a [u8],
                Context(end, sizes): Context<'a>,
            ) -> Result<(Self, usize), Self::Error> {
                let offset = &mut 0;

                let idx = if sizes.heap[$idx] {
                    from.gread_with::<u32>(offset, end)? as usize
                } else {
                    from.gread_with::<u16>(offset, end)? as usize
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
pub struct Simple<T: HasKind>(pub Option<usize>, std::marker::PhantomData<T>);
impl<'a, T: 'a + HasKind> TryFromCtx<'a, Context<'a>> for Simple<T> {
    type Error = scroll::Error;

    fn try_from_ctx(
        from: &'a [u8],
        Context(end, sizes): Context<'a>,
    ) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let idx = match sizes.tables.get(&T::get_kind()) {
            Some(size) => Some(if *size < (1 << 16) {
                from.gread_with::<u16>(offset, end)? as usize
            } else {
                from.gread_with::<u32>(offset, end)? as usize
            }),
            None => None,
        };

        Ok((Simple(idx, PhantomData), *offset))
    }
}

macro_rules! count_items {
    ($name:ident) => { 1 };
    ($first:ident, $($rest:ident),*) => {
        1 + count_items!($($rest),*)
    }
}

macro_rules! coded_index {
    ($name:ident, {$($tag:ident),+}) => {
        #[derive(Debug, Copy, Clone)]
        pub struct $name(pub Option<(usize, Kind)>);

        paste! {
            #[allow(non_upper_case_globals)]
            const [<$name NUM_TABLES>]: usize = count_items!($($tag),*);
            #[allow(non_upper_case_globals)]
            const [<$name TAGS>]: [Kind; [<$name NUM_TABLES>]] = [$($tag),*];

            impl<'a> TryFromCtx<'a, Context<'a>> for $name {
                type Error = scroll::Error;

                fn try_from_ctx(from: &'a [u8], Context(end, sizes): Context<'a>) -> Result<(Self, usize), Self::Error> {
                    let offset = &mut 0;

                    let log = ([<$name NUM_TABLES>] as f32).log2().ceil() as u32;

                    let max_size = [<$name TAGS>].iter().map(|t| sizes.tables.get(t).unwrap_or(&0)).max().unwrap();

                    let coded = if *max_size < (1 << (16 - log)) {
                        from.gread_with::<u16>(offset, end)? as u32
                    } else {
                        from.gread_with::<u32>(offset, end)?
                    };

                    let mask = (1 << log) - 1;
                    let tag = (coded & mask) as usize;
                    let index = (coded >> log) as usize;

                    Ok((
                        $name(
                            if tag < [<$name NUM_TABLES>] {
                                Some((index, [<$name TAGS>][tag]))
                            } else {
                                None
                            }
                        ),
                        *offset
                    ))
                }
            }
        }
    }
}

use Kind::*;

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
