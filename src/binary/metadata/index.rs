use super::table::{HasKind, Kind};
use bitvec::access::BitSafeU8;
use bitvec::slice::BitSlice;
use num_traits::{FromPrimitive, ToPrimitive};
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};
use std::{cmp::Ordering, marker::PhantomData};

use dotnetdll_macros::coded_index;

/// Destination namespace for a 4-byte metadata [`Token`].
///
/// A token can either point at a metadata table row (`Table`) or at a user-string
/// literal in the `#US` heap (`UserString`).
///
/// See `ECMA-335, II.22` and `ECMA-335, II.24.2.5`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenTarget {
    /// Token points to a row in one metadata table, identified by its table id.
    Table(Kind),
    /// Token points to the `#US` heap (tag `0x70`).
    UserString,
}

/// A raw 4-byte metadata token.
///
/// Tokens encode an 8-bit target tag in the high byte and a 24-bit index in the
/// low three bytes. For table tokens this index is the row id (RID); for
/// user-string tokens it is the `#US` heap index.
///
/// See `ECMA-335, II.22`.
#[derive(Clone, Copy, Debug)]
pub struct Token {
    /// Target namespace encoded by the token's high byte.
    pub target: TokenTarget,
    /// Low 24-bit index payload (RID for table tokens, `#US` index for user strings).
    pub index: usize,
}

impl TryFromCtx<'_> for Token {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let num: u32 = from.gread_with(offset, scroll::LE)?;

        let tag = (num >> 24) as u8;

        let index = (num & 0x00FF_FFFF) as usize;

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
try_into_ctx!(Token, |self, into| {
    let offset = &mut 0;

    let tag = match self.target {
        TokenTarget::Table(k) => k.to_u8().unwrap(),
        TokenTarget::UserString => 0x70,
    };

    // we know that the index is only 3 bytes long, so we can safely OR the tag into the top
    into.gwrite_with(((tag as u32) << 24) | (self.index as u32), offset, scroll::LE)?;

    Ok(*offset)
});

/// Width-selection context for variable-sized metadata indices.
///
/// The `#~` stream header provides both:
/// - `heap_sizes`, which selects 2-byte vs 4-byte widths for heap indices, and
/// - per-table row counts, which select 2-byte vs 4-byte widths for table/coded indices.
///
/// `Sizes` carries those two inputs while decoding/encoding row fields.
///
/// See `ECMA-335, II.24.2.6`.
#[derive(Clone, Copy, Debug)]
pub struct Sizes<'a> {
    /// Bit flags from the metadata header's `heap_sizes` byte.
    ///
    /// Bits 0, 1, and 2 select wide (4-byte) indices for `#Strings`, `#GUID`,
    /// and `#Blob` respectively; when clear, those indices are 2 bytes.
    ///
    /// See `ECMA-335, II.24.2.5` and `ECMA-335, II.24.2.6`.
    pub heap: &'a BitSlice<BitSafeU8>,
    /// Per-table row counts, indexed by metadata table id (`Kind as usize`).
    ///
    /// A simple index into table `T` is 2 bytes when `tables[T] < 2^16`, or 4
    /// bytes otherwise.
    ///
    /// See `ECMA-335, II.24.2.6`.
    pub tables: &'a TableRowCounts,
}

/// Row counts for each metadata table id (`Kind as usize`).
///
/// This wrapper exists so generated coded-index code can read table sizes through either
/// `tables[usize]` or `tables.get(&Kind)`, depending on which `dotnetdll-macros` release is
/// used during build/verification.
#[derive(Clone, Copy, Debug)]
pub struct TableRowCounts([u32; 45]);

impl From<[u32; 45]> for TableRowCounts {
    fn from(value: [u32; 45]) -> Self {
        Self(value)
    }
}

impl std::ops::Index<usize> for TableRowCounts {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl TableRowCounts {
    pub fn get(&self, kind: &Kind) -> Option<&u32> {
        self.0.get(*kind as usize)
    }
}

macro_rules! uint_impl {
    ($ty:ty) => {
        impl<'a> TryFromCtx<'a, Sizes<'a>> for $ty {
            type Error = scroll::Error;

            fn try_from_ctx(from: &'a [u8], _: Sizes<'a>) -> Result<(Self, usize), Self::Error> {
                TryFromCtx::try_from_ctx(from, scroll::LE)
            }
        }
        impl<'a> TryIntoCtx<Sizes<'a>> for $ty {
            type Error = scroll::Error;

            fn try_into_ctx(self, into: &mut [u8], _: Sizes<'a>) -> Result<usize, Self::Error> {
                self.try_into_ctx(into, scroll::LE)
            }
        }
    };
}

uint_impl!(u8);
uint_impl!(u16);
uint_impl!(u32);
uint_impl!(u64);

macro_rules! heap_index {
    ($(#[$meta:meta])* $name:ident, $idx:literal) => {
        $(#[$meta])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $name(pub usize);
        impl<'a> TryFromCtx<'a, Sizes<'a>> for $name {
            type Error = scroll::Error;

            fn try_from_ctx(from: &'a [u8], sizes: Sizes<'a>) -> Result<(Self, usize), Self::Error> {
                let offset = &mut 0;

                let idx = if sizes.heap[$idx] {
                    from.gread_with::<u32>(offset, scroll::LE)? as usize
                } else {
                    from.gread_with::<u16>(offset, scroll::LE)? as usize
                };

                Ok(($name(idx), *offset))
            }
        }
        impl<'a> TryIntoCtx<Sizes<'a>> for $name {
            type Error = scroll::Error;

            fn try_into_ctx(self, into: &mut [u8], sizes: Sizes<'a>) -> Result<usize, Self::Error> {
                let offset = &mut 0;

                if sizes.heap[$idx] {
                    into.gwrite_with(self.0 as u32, offset, scroll::LE)?;
                } else {
                    into.gwrite_with(self.0 as u16, offset, scroll::LE)?;
                }

                Ok(*offset)
            }
        }
        impl From<usize> for $name {
            fn from(i: usize) -> Self {
                $name(i)
            }
        }

        impl $name {
            /// Returns `true` when this heap index is null (`0`).
            pub fn is_null(&self) -> bool {
                self.0 == 0
            }
        }
    };
}

heap_index!(
    /// Index into the `#Strings` heap.
    ///
    /// Encoded as either 2 bytes or 4 bytes depending on `heap_sizes` bit 0 in
    /// the `#~` stream header. A value of `0` is the null index.
    ///
    /// See `ECMA-335, II.24.2.5` and `ECMA-335, II.24.2.6`.
    String,
    0
);
heap_index!(
    /// Index into the `#GUID` heap.
    ///
    /// Encoded as either 2 bytes or 4 bytes depending on `heap_sizes` bit 1 in
    /// the `#~` stream header. A value of `0` is the null index.
    ///
    /// See `ECMA-335, II.24.2.5` and `ECMA-335, II.24.2.6`.
    GUID,
    1
);
heap_index!(
    /// Index into the `#Blob` heap.
    ///
    /// Encoded as either 2 bytes or 4 bytes depending on `heap_sizes` bit 2 in
    /// the `#~` stream header. A value of `0` is the null index.
    ///
    /// See `ECMA-335, II.24.2.5` and `ECMA-335, II.24.2.6`.
    Blob,
    2
);

/// Typed index into a single metadata table.
///
/// `Simple<T>` stores a row id (RID) for table `T`. Its on-disk width is
/// selected from the target table's row count: 2 bytes when the table has fewer
/// than `2^16` rows, otherwise 4 bytes.
///
/// See `ECMA-335, II.24.2.6`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Simple<T>(
    /// The raw RID (`0` means null/no row).
    pub usize,
    PhantomData<T>,
);
impl<'a, T: 'a + HasKind> TryFromCtx<'a, Sizes<'a>> for Simple<T> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], sizes: Sizes<'a>) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let idx = if sizes.tables[T::kind() as usize] < (1 << 16) {
            from.gread_with::<u16>(offset, scroll::LE)? as usize
        } else {
            from.gread_with::<u32>(offset, scroll::LE)? as usize
        };

        Ok((Simple(idx, PhantomData), *offset))
    }
}
impl<'a, T: 'a + HasKind> TryIntoCtx<Sizes<'a>> for Simple<T> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], sizes: Sizes<'a>) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        if sizes.tables[T::kind() as usize] < (1 << 16) {
            into.gwrite_with(self.0 as u16, offset, scroll::LE)?;
        } else {
            into.gwrite_with(self.0 as u32, offset, scroll::LE)?;
        }

        Ok(*offset)
    }
}
impl<T: Eq> PartialOrd for Simple<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: Eq> Ord for Simple<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
impl<T> From<usize> for Simple<T> {
    fn from(val: usize) -> Self {
        Simple(val, PhantomData)
    }
}

impl<T> Simple<T> {
    /// Returns `true` when this table index is null (`0`).
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }
}

coded_index!(
    TypeDefOrRef,
    {
        TypeDef,
        TypeRef,
        TypeSpec
    }
);
coded_index!(
    HasConstant,
    {
        Field,
        Param,
        Property
    }
);
coded_index!(
    HasCustomAttribute,
    {
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
    }
);
coded_index!(
    HasFieldMarshal,
    {
        Field,
        Param
    }
);
coded_index!(
    HasDeclSecurity,
    {
        TypeDef,
        MethodDef,
        Assembly
    }
);
coded_index!(
    MemberRefParent,
    {
        TypeDef,
        TypeRef,
        ModuleRef,
        MethodDef,
        TypeSpec
    }
);
coded_index!(
    HasSemantics,
    {
        Event,
        Property
    }
);
coded_index!(
    MethodDefOrRef,
    {
        MethodDef,
        MemberRef
    }
);
coded_index!(
    MemberForwarded,
    {
        Field,
        MethodDef
    }
);
coded_index!(
    Implementation,
    {
        File,
        AssemblyRef,
        ExportedType
    }
);
coded_index!(
    CustomAttributeType,
    {
        Unused,
        Unused,
        MethodDef,
        MemberRef,
        Unused
    }
);
coded_index!(
    ResolutionScope,
    {
        Module,
        ModuleRef,
        AssemblyRef,
        TypeRef
    }
);
coded_index!(
    TypeOrMethodDef,
    {
        TypeDef,
        MethodDef
    }
);
