//! Encoded signature building blocks shared across method, field, property, and marshal blobs.
//!
//! This module contains the binary discriminants and compact encodings used by signature grammars
//! in `#Blob` metadata: element-type tags, custom modifiers, `Type`, parameter/return wrappers,
//! and unmanaged native marshalling intrinsics.
//!
//! - `ELEMENT_TYPE_*` constants are the one-byte element-type tags from `CorElementType`.
//!   See ECMA-335, II.23.1.16.
//! - `NATIVE_TYPE_*` constants are marshalling descriptor tags.
//!   See ECMA-335, II.23.4.

use paste::paste;
use scroll::{
    Error, Pread, Pwrite,
    ctx::{TryFromCtx, TryIntoCtx},
};

use super::{
    super::metadata::{index, table},
    compressed, kinds,
};

macro_rules! element_types {
    ($( $(#[$meta:meta])* $name:ident = $val:literal ),+ $(,)?) => {
        $(
            paste! {
                $(#[$meta])*
                pub const [<ELEMENT_TYPE_ $name>]: u8 = $val;
            }
        )*
    }
}

element_types! {
    /// `ELEMENT_TYPE_END` (`0x00`), used as a list terminator in specific signature grammars.
    END = 0x00,
    /// `ELEMENT_TYPE_VOID` (`0x01`), the `void` return type marker.
    VOID = 0x01,
    /// `ELEMENT_TYPE_BOOLEAN` (`0x02`), the built-in `bool` type.
    BOOLEAN = 0x02,
    /// `ELEMENT_TYPE_CHAR` (`0x03`), the built-in UTF-16 code-unit type.
    CHAR = 0x03,
    /// `ELEMENT_TYPE_I1` (`0x04`), signed 8-bit integer.
    I1 = 0x04,
    /// `ELEMENT_TYPE_U1` (`0x05`), unsigned 8-bit integer.
    U1 = 0x05,
    /// `ELEMENT_TYPE_I2` (`0x06`), signed 16-bit integer.
    I2 = 0x06,
    /// `ELEMENT_TYPE_U2` (`0x07`), unsigned 16-bit integer.
    U2 = 0x07,
    /// `ELEMENT_TYPE_I4` (`0x08`), signed 32-bit integer.
    I4 = 0x08,
    /// `ELEMENT_TYPE_U4` (`0x09`), unsigned 32-bit integer.
    U4 = 0x09,
    /// `ELEMENT_TYPE_I8` (`0x0a`), signed 64-bit integer.
    I8 = 0x0a,
    /// `ELEMENT_TYPE_U8` (`0x0b`), unsigned 64-bit integer.
    U8 = 0x0b,
    /// `ELEMENT_TYPE_R4` (`0x0c`), 32-bit IEEE floating-point.
    R4 = 0x0c,
    /// `ELEMENT_TYPE_R8` (`0x0d`), 64-bit IEEE floating-point.
    R8 = 0x0d,
    /// `ELEMENT_TYPE_STRING` (`0x0e`), the built-in `string` reference type.
    STRING = 0x0e,
    /// `ELEMENT_TYPE_PTR` (`0x0f`), unmanaged pointer (`T*`).
    PTR = 0x0f,
    /// `ELEMENT_TYPE_BYREF` (`0x10`), managed by-reference (`T&`).
    BYREF = 0x10,
    /// `ELEMENT_TYPE_VALUETYPE` (`0x11`), user-defined value type token.
    VALUETYPE = 0x11,
    /// `ELEMENT_TYPE_CLASS` (`0x12`), user-defined reference type token.
    CLASS = 0x12,
    /// `ELEMENT_TYPE_VAR` (`0x13`), generic type parameter (`!n`).
    VAR = 0x13,
    /// `ELEMENT_TYPE_ARRAY` (`0x14`), multi-dimensional array with [`ArrayShape`].
    ARRAY = 0x14,
    /// `ELEMENT_TYPE_GENERICINST` (`0x15`), closed generic type instantiation.
    GENERICINST = 0x15,
    /// `ELEMENT_TYPE_TYPEDBYREF` (`0x16`), typed reference.
    TYPEDBYREF = 0x16,
    /// `ELEMENT_TYPE_I` (`0x18`), platform-sized signed integer (`native int`).
    I = 0x18,
    /// `ELEMENT_TYPE_U` (`0x19`), platform-sized unsigned integer (`native uint`).
    U = 0x19,
    /// `ELEMENT_TYPE_FNPTR` (`0x1b`), function pointer signature.
    FNPTR = 0x1b,
    /// `ELEMENT_TYPE_OBJECT` (`0x1c`), the built-in `object` reference type.
    OBJECT = 0x1c,
    /// `ELEMENT_TYPE_SZARRAY` (`0x1d`), single-dimensional zero-based array (`T[]`).
    SZARRAY = 0x1d,
    /// `ELEMENT_TYPE_MVAR` (`0x1e`), generic method parameter (`!!n`).
    MVAR = 0x1e,
    /// `ELEMENT_TYPE_CMOD_REQD` (`0x1f`), required custom modifier prefix.
    CMOD_REQD = 0x1f,
    /// `ELEMENT_TYPE_CMOD_OPT` (`0x20`), optional custom modifier prefix.
    CMOD_OPT = 0x20,
    /// `ELEMENT_TYPE_INTERNAL` (`0x21`), runtime-internal type marker.
    INTERNAL = 0x21,
    /// `ELEMENT_TYPE_MODIFIER` (`0x40`), modifier mask value in element-type space.
    MODIFIER = 0x40,
    /// `ELEMENT_TYPE_SENTINEL` (`0x41`), vararg fixed/optional parameter boundary marker.
    SENTINEL = 0x41,
    /// `ELEMENT_TYPE_PINNED` (`0x45`), local-variable pinning constraint marker (Constraint item).
    ///
    /// See ECMA-335, II.23.2.9.
    PINNED = 0x45,
}

/// Compact `TypeDef`/`TypeRef`/`TypeSpec` token used inside signatures.
///
/// Signature blobs do not store a full 4-byte metadata token here. Instead, they store a compressed
/// integer where the low 2 bits encode the target table (`0=TypeDef`, `1=TypeRef`, `2=TypeSpec`)
/// and the remaining bits encode the row id.
///
/// See ECMA-335, II.23.2.8.
#[derive(Debug, Clone)]
pub struct TypeDefOrRefOrSpec(
    /// The decoded metadata token.
    pub index::Token,
);

impl From<index::TypeDefOrRef> for TypeDefOrRefOrSpec {
    fn from(t: index::TypeDefOrRef) -> Self {
        use index::TypeDefOrRef::*;
        use num_traits::FromPrimitive;

        TypeDefOrRefOrSpec(match t {
            TypeDef(i) => index::Token {
                target: index::TokenTarget::Table(table::Kind::TypeDef),
                index: i,
            },
            TypeRef(i) => index::Token {
                target: index::TokenTarget::Table(table::Kind::TypeRef),
                index: i,
            },
            TypeSpec(i) => index::Token {
                target: index::TokenTarget::Table(table::Kind::TypeSpec),
                index: i,
            },
            Null => index::Token {
                target: index::TokenTarget::Table(table::Kind::from_u8(0).unwrap()),
                index: 0,
            },
        })
    }
}

impl TryFromCtx<'_> for TypeDefOrRefOrSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(value) = from.gread(offset)?;

        Ok((
            TypeDefOrRefOrSpec(index::Token {
                target: index::TokenTarget::Table(match value & 0b11 {
                    0 => table::Kind::TypeDef,
                    1 => table::Kind::TypeRef,
                    2 => table::Kind::TypeSpec,
                    _ => throw!("bad token table specifier 0x3"),
                }),
                index: (value >> 2) as usize,
            }),
            *offset,
        ))
    }
}
try_into_ctx!(TypeDefOrRefOrSpec, |self, into| {
    let offset = &mut 0;

    let table = match self.0.target {
        index::TokenTarget::Table(table::Kind::TypeDef) => 0,
        index::TokenTarget::Table(table::Kind::TypeRef) => 1,
        index::TokenTarget::Table(table::Kind::TypeSpec) => 2,
        other => throw!("invalid token {:?}, only TypeDef/Ref/Spec allowed", other),
    };

    let value = (self.0.index << 2) | table;

    into.gwrite(compressed::Unsigned(value as u32), offset)?;

    Ok(*offset)
});

/// Defines the shape of an array that is potentially multi-dimensional and may have size bounds.
///
/// An array's shape is defined by its rank (number of dimensions), the sizes of each dimension,
/// and the lower bounds for each dimension.
///
/// Note that according to the standard (ECMA-335, II.23.2.13):
/// - `rank` is the total number of dimensions.
/// - `sizes` may contain fewer than `rank` elements, in which case only the first `sizes.len()` dimensions
///   have an explicit size.
/// - `lower_bounds` may contain fewer than `rank` elements, in which case only the first `lower_bounds.len()`
///   dimensions have an explicit lower bound. Dimensions without an explicit lower bound default to 0.
///
/// See ECMA-335, II.23.2.13 (page 265) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArrayShape {
    pub rank: usize,
    pub sizes: Vec<usize>,
    pub lower_bounds: Vec<isize>,
}

impl TryFromCtx<'_> for ArrayShape {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(rank) = from.gread(offset)?;

        let compressed::Unsigned(num_sizes) = from.gread(offset)?;
        let sizes: Vec<_> = (0..num_sizes)
            .map(|_| {
                let compressed::Unsigned(size) = from.gread(offset)?;
                Ok(size as usize)
            })
            .collect::<scroll::Result<_>>()?;

        let compressed::Unsigned(num_bounds) = from.gread(offset)?;
        let lower_bounds = (0..num_bounds)
            .map(|_| {
                let compressed::Signed(bound) = from.gread(offset)?;
                Ok(bound as isize)
            })
            .collect::<scroll::Result<_>>()?;

        Ok((
            ArrayShape {
                rank: rank as usize,
                sizes,
                lower_bounds,
            },
            *offset,
        ))
    }
}
try_into_ctx!(ArrayShape, |self, into| {
    let offset = &mut 0;

    into.gwrite(compressed::Unsigned(self.rank as u32), offset)?;
    into.gwrite(compressed::Unsigned(self.sizes.len() as u32), offset)?;
    for s in self.sizes {
        into.gwrite(compressed::Unsigned(s as u32), offset)?;
    }
    into.gwrite(compressed::Unsigned(self.lower_bounds.len() as u32), offset)?;
    for b in self.lower_bounds {
        into.gwrite(compressed::Signed(b as i32), offset)?;
    }

    Ok(*offset)
});

/// Signature-level custom modifier (`modreq` / `modopt`).
///
/// A custom modifier prefixes a type position in a signature and references a type via
/// [`TypeDefOrRefOrSpec`]. Required modifiers must be understood by consumers that reference the
/// containing signature; optional modifiers may be ignored.
///
/// See ECMA-335, II.23.2.7.
#[derive(Debug, Clone)]
pub enum CustomMod {
    /// Required custom modifier (`ELEMENT_TYPE_CMOD_REQD`).
    Required(TypeDefOrRefOrSpec),
    /// Optional custom modifier (`ELEMENT_TYPE_CMOD_OPT`).
    Optional(TypeDefOrRefOrSpec),
}

/// Internal lightweight parse failure marker used while scanning custom modifier lists.
pub struct FailUnit;
impl From<scroll::Error> for FailUnit {
    fn from(_: Error) -> Self {
        FailUnit
    }
}

impl TryFromCtx<'_> for CustomMod {
    // since all reading is done from all_custom_mods, which discards errors,
    // avoid allocating error messages and just fail with a unit
    type Error = FailUnit;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(tag) = from.gread(offset)?;
        let tag_u8 = tag as u8;
        if tag_u8 != ELEMENT_TYPE_CMOD_OPT && tag_u8 != ELEMENT_TYPE_CMOD_REQD {
            return Err(FailUnit);
        }

        let token = from.gread(offset)?;

        Ok((
            match tag_u8 {
                ELEMENT_TYPE_CMOD_OPT => CustomMod::Optional(token),
                ELEMENT_TYPE_CMOD_REQD => CustomMod::Required(token),
                _ => unreachable!(),
            },
            *offset,
        ))
    }
}
try_into_ctx!(CustomMod, |self, into| {
    let offset = &mut 0;

    let (tag, token) = match self {
        CustomMod::Required(t) => (ELEMENT_TYPE_CMOD_REQD, t),
        CustomMod::Optional(t) => (ELEMENT_TYPE_CMOD_OPT, t),
    };

    into.gwrite(compressed::Unsigned(tag as u32), offset)?;
    into.gwrite(token, offset)?;

    Ok(*offset)
});

/// Reads a maximal contiguous sequence of [`CustomMod`] items at `offset`.
///
/// Parsing stops at the first non-`CMOD_*` byte or parse failure and returns all successfully read
/// modifiers. The input `offset` is advanced past the consumed bytes.
///
/// See ECMA-335, II.23.2.7.
pub fn all_custom_mods(from: &[u8], offset: &mut usize) -> Vec<CustomMod> {
    // CMOD_REQD (0x1f) and CMOD_OPT (0x20) are both < 128, so they encode as single bytes.
    // Peek the first byte to avoid a full gread when there are no custom mods (the common case).
    match from.get(*offset) {
        Some(&b) if b == ELEMENT_TYPE_CMOD_REQD || b == ELEMENT_TYPE_CMOD_OPT => {}
        _ => return Vec::new(),
    }

    let mut mods = Vec::new();
    loop {
        match from.gread::<CustomMod>(offset) {
            Ok(m) => mods.push(m),
            Err(_) => return mods,
        }
    }
}

/// Encoded signature type.
///
/// This enum models the `Type` non-terminal used throughout signature blobs, including primitive
/// types, type/method generic variables, pointers, arrays, function pointers, and generic
/// instantiations.
///
/// See ECMA-335, II.23.2.12 and II.23.2.13.
#[derive(Debug, Clone)]
pub enum Type {
    /// `ELEMENT_TYPE_BOOLEAN`.
    Boolean,
    /// `ELEMENT_TYPE_CHAR`.
    Char,
    /// `ELEMENT_TYPE_I1`.
    Int8,
    /// `ELEMENT_TYPE_U1`.
    UInt8,
    /// `ELEMENT_TYPE_I2`.
    Int16,
    /// `ELEMENT_TYPE_U2`.
    UInt16,
    /// `ELEMENT_TYPE_I4`.
    Int32,
    /// `ELEMENT_TYPE_U4`.
    UInt32,
    /// `ELEMENT_TYPE_I8`.
    Int64,
    /// `ELEMENT_TYPE_U8`.
    UInt64,
    /// `ELEMENT_TYPE_R4`.
    Float32,
    /// `ELEMENT_TYPE_R8`.
    Float64,
    /// `ELEMENT_TYPE_I` (`native int`).
    IntPtr,
    /// `ELEMENT_TYPE_U` (`native uint`).
    UIntPtr,
    /// `ELEMENT_TYPE_ARRAY` with element type and [`ArrayShape`].
    Array(Box<Type>, ArrayShape),
    /// `ELEMENT_TYPE_CLASS` + encoded type token.
    Class(TypeDefOrRefOrSpec),
    /// `ELEMENT_TYPE_FNPTR` + stand-alone method signature.
    FnPtr(Box<kinds::StandAloneMethodSig>),
    /// `ELEMENT_TYPE_GENERICINST CLASS` + generic arguments.
    GenericInstClass(TypeDefOrRefOrSpec, Vec<Type>),
    /// `ELEMENT_TYPE_GENERICINST VALUETYPE` + generic arguments.
    GenericInstValueType(TypeDefOrRefOrSpec, Vec<Type>),
    /// `ELEMENT_TYPE_MVAR` method generic parameter number.
    MVar(u32),
    /// `ELEMENT_TYPE_OBJECT`.
    Object,
    /// `ELEMENT_TYPE_PTR` with optional pointee type (`None` encodes `void*`).
    Ptr(Vec<CustomMod>, Option<Box<Type>>),
    /// `ELEMENT_TYPE_STRING`.
    String,
    /// `ELEMENT_TYPE_SZARRAY` with custom modifiers on the element type.
    SzArray(Vec<CustomMod>, Box<Type>),
    /// `ELEMENT_TYPE_VALUETYPE` + encoded type token.
    ValueType(TypeDefOrRefOrSpec),
    /// `ELEMENT_TYPE_VAR` type generic parameter number.
    Var(u32),
}

impl TryFromCtx<'_> for Type {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;

        use Type::*;

        let val = match tag {
            ELEMENT_TYPE_BOOLEAN => Boolean,
            ELEMENT_TYPE_CHAR => Char,
            ELEMENT_TYPE_I1 => Int8,
            ELEMENT_TYPE_U1 => UInt8,
            ELEMENT_TYPE_I2 => Int16,
            ELEMENT_TYPE_U2 => UInt16,
            ELEMENT_TYPE_I4 => Int32,
            ELEMENT_TYPE_U4 => UInt32,
            ELEMENT_TYPE_I8 => Int64,
            ELEMENT_TYPE_U8 => UInt64,
            ELEMENT_TYPE_R4 => Float32,
            ELEMENT_TYPE_R8 => Float64,
            ELEMENT_TYPE_I => IntPtr,
            ELEMENT_TYPE_U => UIntPtr,
            ELEMENT_TYPE_ARRAY => {
                let type_data = from.gread(offset)?;
                let shape = from.gread(offset)?;
                Array(Box::new(type_data), shape)
            }
            ELEMENT_TYPE_CLASS => Class(from.gread(offset)?),
            ELEMENT_TYPE_FNPTR => FnPtr(Box::new(from.gread(offset)?)),
            ELEMENT_TYPE_GENERICINST => {
                let next_tag: u8 = from.gread_with(offset, scroll::LE)?;
                let token = from.gread(offset)?;

                let compressed::Unsigned(arg_count) = from.gread(offset)?;
                let mut types = Vec::with_capacity(arg_count as usize);
                for _ in 0..arg_count {
                    types.push(from.gread(offset)?);
                }

                match next_tag {
                    ELEMENT_TYPE_CLASS => GenericInstClass(token, types),
                    ELEMENT_TYPE_VALUETYPE => GenericInstValueType(token, types),
                    _ => throw!("bad generic instantiation tag {:#04x}", next_tag),
                }
            }
            ELEMENT_TYPE_MVAR => {
                let compressed::Unsigned(number) = from.gread(offset)?;
                MVar(number)
            }
            ELEMENT_TYPE_OBJECT => Object,
            ELEMENT_TYPE_PTR => Ptr(
                all_custom_mods(from, offset),
                if from[*offset] == ELEMENT_TYPE_VOID {
                    *offset += 1;
                    None
                } else {
                    Some(Box::new(from.gread(offset)?))
                },
            ),
            ELEMENT_TYPE_STRING => String,
            ELEMENT_TYPE_SZARRAY => {
                let mods = all_custom_mods(from, offset);

                let type_data = from.gread(offset)?;
                SzArray(mods, Box::new(type_data))
            }
            ELEMENT_TYPE_VALUETYPE => ValueType(from.gread(offset)?),
            ELEMENT_TYPE_VAR => {
                let compressed::Unsigned(number) = from.gread(offset)?;
                Var(number)
            }
            _ => throw!("bad type discriminator tag {:#04x}", tag),
        };

        Ok((val, *offset))
    }
}
try_into_ctx!(Type, |self, into| {
    let offset = &mut 0;

    use Type::*;

    match self {
        Boolean => {
            into.gwrite_with(ELEMENT_TYPE_BOOLEAN, offset, scroll::LE)?;
        }
        Char => {
            into.gwrite_with(ELEMENT_TYPE_CHAR, offset, scroll::LE)?;
        }
        Int8 => {
            into.gwrite_with(ELEMENT_TYPE_I1, offset, scroll::LE)?;
        }
        UInt8 => {
            into.gwrite_with(ELEMENT_TYPE_U1, offset, scroll::LE)?;
        }
        Int16 => {
            into.gwrite_with(ELEMENT_TYPE_I2, offset, scroll::LE)?;
        }
        UInt16 => {
            into.gwrite_with(ELEMENT_TYPE_U2, offset, scroll::LE)?;
        }
        Int32 => {
            into.gwrite_with(ELEMENT_TYPE_I4, offset, scroll::LE)?;
        }
        UInt32 => {
            into.gwrite_with(ELEMENT_TYPE_U4, offset, scroll::LE)?;
        }
        Int64 => {
            into.gwrite_with(ELEMENT_TYPE_I8, offset, scroll::LE)?;
        }
        UInt64 => {
            into.gwrite_with(ELEMENT_TYPE_U8, offset, scroll::LE)?;
        }
        Float32 => {
            into.gwrite_with(ELEMENT_TYPE_R4, offset, scroll::LE)?;
        }
        Float64 => {
            into.gwrite_with(ELEMENT_TYPE_R8, offset, scroll::LE)?;
        }
        IntPtr => {
            into.gwrite_with(ELEMENT_TYPE_I, offset, scroll::LE)?;
        }
        UIntPtr => {
            into.gwrite_with(ELEMENT_TYPE_U, offset, scroll::LE)?;
        }
        Array(t, shape) => {
            into.gwrite_with(ELEMENT_TYPE_ARRAY, offset, scroll::LE)?;
            into.gwrite(*t, offset)?;
            into.gwrite(shape, offset)?;
        }
        Class(t) => {
            into.gwrite_with(ELEMENT_TYPE_CLASS, offset, scroll::LE)?;
            into.gwrite(t, offset)?;
        }
        FnPtr(s) => {
            into.gwrite_with(ELEMENT_TYPE_FNPTR, offset, scroll::LE)?;
            into.gwrite(*s, offset)?;
        }
        GenericInstClass(src, ts) => {
            into.gwrite_with(ELEMENT_TYPE_GENERICINST, offset, scroll::LE)?;
            into.gwrite_with(ELEMENT_TYPE_CLASS, offset, scroll::LE)?;
            into.gwrite(src, offset)?;
            into.gwrite(compressed::Unsigned(ts.len() as u32), offset)?;
            for t in ts {
                into.gwrite(t, offset)?;
            }
        }
        GenericInstValueType(src, ts) => {
            into.gwrite_with(ELEMENT_TYPE_GENERICINST, offset, scroll::LE)?;
            into.gwrite_with(ELEMENT_TYPE_VALUETYPE, offset, scroll::LE)?;
            into.gwrite(src, offset)?;
            into.gwrite(compressed::Unsigned(ts.len() as u32), offset)?;
            for t in ts {
                into.gwrite(t, offset)?;
            }
        }
        MVar(n) => {
            into.gwrite_with(ELEMENT_TYPE_MVAR, offset, scroll::LE)?;
            into.gwrite(compressed::Unsigned(n), offset)?;
        }
        Object => {
            into.gwrite_with(ELEMENT_TYPE_OBJECT, offset, scroll::LE)?;
        }
        Ptr(mods, opt) => {
            into.gwrite_with(ELEMENT_TYPE_PTR, offset, scroll::LE)?;
            for m in mods {
                into.gwrite(m, offset)?;
            }
            match opt {
                Some(t) => into.gwrite(*t, offset)?,
                None => into.gwrite_with(ELEMENT_TYPE_VOID, offset, scroll::LE)?,
            };
        }
        String => {
            into.gwrite_with(ELEMENT_TYPE_STRING, offset, scroll::LE)?;
        }
        SzArray(mods, t) => {
            into.gwrite_with(ELEMENT_TYPE_SZARRAY, offset, scroll::LE)?;
            for m in mods {
                into.gwrite(m, offset)?;
            }
            into.gwrite(*t, offset)?;
        }
        ValueType(t) => {
            into.gwrite_with(ELEMENT_TYPE_VALUETYPE, offset, scroll::LE)?;
            into.gwrite(t, offset)?;
        }
        Var(n) => {
            into.gwrite_with(ELEMENT_TYPE_VAR, offset, scroll::LE)?;
            into.gwrite(compressed::Unsigned(n), offset)?;
        }
    }

    Ok(*offset)
});

/// Parameter-type payload used by [`Param`].
///
/// See ECMA-335, II.23.2.10.
#[derive(Debug, Clone)]
pub enum ParamType {
    /// A regular parameter type.
    Type(Type),
    /// A managed by-reference parameter (`byref T`).
    ByRef(Type),
    /// A typed reference parameter (`typedbyref`).
    TypedByRef,
}

/// Encoded method parameter signature item.
///
/// A parameter consists of zero or more custom modifiers followed by a [`ParamType`].
///
/// See ECMA-335, II.23.2.10.
#[derive(Debug, Clone)]
pub struct Param(
    /// Custom modifiers that precede the parameter type.
    pub Vec<CustomMod>,
    /// The parameter type payload.
    pub ParamType,
);

impl TryFromCtx<'_> for Param {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let mods = all_custom_mods(from, offset);

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        let val = match tag {
            ELEMENT_TYPE_TYPEDBYREF => ParamType::TypedByRef,
            ELEMENT_TYPE_BYREF => ParamType::ByRef(from.gread(offset)?),
            _ => {
                *offset -= 1;
                ParamType::Type(from.gread(offset)?)
            }
        };

        Ok((Param(mods, val), *offset))
    }
}
try_into_ctx!(Param, |self, into| {
    let offset = &mut 0;

    for m in self.0 {
        into.gwrite(m, offset)?;
    }

    match self.1 {
        ParamType::Type(t) => into.gwrite(t, offset)?,
        ParamType::ByRef(t) => {
            into.gwrite_with(ELEMENT_TYPE_BYREF, offset, scroll::LE)?;
            into.gwrite(t, offset)?
        }
        ParamType::TypedByRef => into.gwrite_with(ELEMENT_TYPE_TYPEDBYREF, offset, scroll::LE)?,
    };

    Ok(*offset)
});

/// Return-type payload used by [`RetType`].
///
/// `RetType` uses the same forms as [`ParamType`], with an additional `void` case.
///
/// See ECMA-335, II.23.2.11.
#[derive(Debug, Clone)]
pub enum RetTypeType {
    /// A non-`void` return type.
    Type(Type),
    /// A managed by-reference return (`byref T`).
    ByRef(Type),
    /// A typed reference return (`typedbyref`).
    TypedByRef,
    /// `void` return.
    Void,
}

/// Encoded method return signature item.
///
/// A return type consists of zero or more custom modifiers followed by a [`RetTypeType`].
///
/// See ECMA-335, II.23.2.11.
#[derive(Debug, Clone)]
pub struct RetType(
    /// Custom modifiers that precede the return type.
    pub Vec<CustomMod>,
    /// The return type payload.
    pub RetTypeType,
);

impl TryFromCtx<'_> for RetType {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let mods = all_custom_mods(from, offset);

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        let val = match tag {
            ELEMENT_TYPE_VOID => RetTypeType::Void,
            ELEMENT_TYPE_TYPEDBYREF => RetTypeType::TypedByRef,
            ELEMENT_TYPE_BYREF => RetTypeType::ByRef(from.gread(offset)?),
            _ => {
                *offset -= 1;
                RetTypeType::Type(from.gread(offset)?)
            }
        };

        Ok((RetType(mods, val), *offset))
    }
}
try_into_ctx!(RetType, |self, into| {
    let offset = &mut 0;

    for m in self.0 {
        into.gwrite(m, offset)?;
    }

    match self.1 {
        RetTypeType::Type(t) => into.gwrite(t, offset)?,
        RetTypeType::ByRef(t) => {
            into.gwrite_with(ELEMENT_TYPE_BYREF, offset, scroll::LE)?;
            into.gwrite(t, offset)?
        }
        RetTypeType::TypedByRef => into.gwrite_with(ELEMENT_TYPE_TYPEDBYREF, offset, scroll::LE)?,
        RetTypeType::Void => into.gwrite_with(ELEMENT_TYPE_VOID, offset, scroll::LE)?,
    };

    Ok(*offset)
});

/// Unmanaged intrinsic type discriminator used in `MarshalSpec` blobs.
///
/// The first 16 variants correspond directly to `NativeIntrinsic` in ECMA-335 marshalling
/// descriptors. Additional variants represent widely used Microsoft extensions accepted by this
/// crate during parse/write.
///
/// See ECMA-335, II.23.4.
#[derive(Debug, Copy, Clone)]
pub enum NativeIntrinsic {
    /// `NATIVE_TYPE_BOOLEAN` (`bool`).
    Boolean,
    /// `NATIVE_TYPE_I1`.
    Int8,
    /// `NATIVE_TYPE_U1`.
    UInt8,
    /// `NATIVE_TYPE_I2`.
    Int16,
    /// `NATIVE_TYPE_U2`.
    UInt16,
    /// `NATIVE_TYPE_I4`.
    Int32,
    /// `NATIVE_TYPE_U4`.
    UInt32,
    /// `NATIVE_TYPE_I8`.
    Int64,
    /// `NATIVE_TYPE_U8`.
    UInt64,
    /// `NATIVE_TYPE_R4`.
    Float32,
    /// `NATIVE_TYPE_R8`.
    Float64,
    /// `NATIVE_TYPE_LPSTR`.
    LPStr,
    /// `NATIVE_TYPE_LPWSTR`.
    LPWStr,
    /// `NATIVE_TYPE_INT`.
    IntPtr,
    /// `NATIVE_TYPE_UINT`.
    UIntPtr,
    /// `NATIVE_TYPE_FUNC` (function pointer).
    Function,
    /// Microsoft extension (`0x0f`).
    Currency,
    /// Microsoft extension (`0x13`).
    BStr,
    /// Microsoft extension (`0x16`).
    LPTStr,
    /// Microsoft extension (`0x17`).
    FixedSysString,
    /// Microsoft extension (`0x19`).
    COMIUnknown,
    /// Microsoft extension (`0x1a`).
    COMIDispatch,
    /// Microsoft extension (`0x1b`).
    Struct,
    /// Microsoft extension (`0x1c`).
    COMInterface,
    /// Microsoft extension (`0x1d`).
    SafeArray,
    /// Microsoft extension (`0x1e`).
    FixedArray,
    /// Microsoft extension (`0x22`).
    ByValStr,
    /// Microsoft extension (`0x23`).
    AnsiBStr,
    /// Microsoft extension (`0x24`).
    TBStr,
    /// Microsoft extension (`0x25`).
    VariantBool,
    /// Microsoft extension (`0x28`).
    AsAny,
    /// Microsoft extension (`0x2b`).
    LpStruct,
    /// Microsoft extension (`0x2c`).
    CustomMarshaler,
    /// Microsoft extension (`0x30`).
    LPUTF8Str,
}

macro_rules! native_types {
    ($( $(#[$meta:meta])* $name:ident = $val:literal ),+ $(,)?) => {
        $(
            paste! {
                $(#[$meta])*
                pub const [<NATIVE_TYPE_ $name>]: u8 = $val;
            }
        )*
    }
}

native_types! {
    /// `NATIVE_TYPE_BOOLEAN` (`0x02`) marshalling intrinsic.
    BOOLEAN = 0x02,
    /// `NATIVE_TYPE_I1` (`0x03`) marshalling intrinsic.
    I1 = 0x03,
    /// `NATIVE_TYPE_U1` (`0x04`) marshalling intrinsic.
    U1 = 0x04,
    /// `NATIVE_TYPE_I2` (`0x05`) marshalling intrinsic.
    I2 = 0x05,
    /// `NATIVE_TYPE_U2` (`0x06`) marshalling intrinsic.
    U2 = 0x06,
    /// `NATIVE_TYPE_I4` (`0x07`) marshalling intrinsic.
    I4 = 0x07,
    /// `NATIVE_TYPE_U4` (`0x08`) marshalling intrinsic.
    U4 = 0x08,
    /// `NATIVE_TYPE_I8` (`0x09`) marshalling intrinsic.
    I8 = 0x09,
    /// `NATIVE_TYPE_U8` (`0x0a`) marshalling intrinsic.
    U8 = 0x0a,
    /// `NATIVE_TYPE_R4` (`0x0b`) marshalling intrinsic.
    R4 = 0x0b,
    /// `NATIVE_TYPE_R8` (`0x0c`) marshalling intrinsic.
    R8 = 0x0c,
    /// `NATIVE_TYPE_LPSTR` (`0x14`) marshalling intrinsic.
    LPSTR = 0x14,
    /// `NATIVE_TYPE_LPWSTR` (`0x15`) marshalling intrinsic.
    LPWSTR = 0x15,
    /// `NATIVE_TYPE_INT` (`0x1f`) marshalling intrinsic.
    INT = 0x1f,
    /// `NATIVE_TYPE_UINT` (`0x20`) marshalling intrinsic.
    UINT = 0x20,
    /// `NATIVE_TYPE_FUNC` (`0x26`) marshalling intrinsic.
    FUNC = 0x26,
    /// `NATIVE_TYPE_ARRAY` (`0x2a`) marshalling intrinsic.
    ARRAY = 0x2a,
    /// `NATIVE_TYPE_MAX` (`0x50`) element-type sentinel used in array marshal specs.
    MAX = 0x50,
}

impl TryFromCtx<'_> for NativeIntrinsic {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        use NativeIntrinsic::*;

        let val = match from.gread_with::<u8>(offset, scroll::LE)? {
            NATIVE_TYPE_BOOLEAN => Boolean,
            NATIVE_TYPE_I1 => Int8,
            NATIVE_TYPE_U1 => UInt8,
            NATIVE_TYPE_I2 => Int16,
            NATIVE_TYPE_U2 => UInt16,
            NATIVE_TYPE_I4 => Int32,
            NATIVE_TYPE_U4 => UInt32,
            NATIVE_TYPE_I8 => Int64,
            NATIVE_TYPE_U8 => UInt64,
            NATIVE_TYPE_R4 => Float32,
            NATIVE_TYPE_R8 => Float64,
            NATIVE_TYPE_LPSTR => LPStr,
            NATIVE_TYPE_LPWSTR => LPWStr,
            NATIVE_TYPE_INT => IntPtr,
            NATIVE_TYPE_UINT => UIntPtr,
            NATIVE_TYPE_FUNC => Function,
            // Microsoft specials
            0x0f => Currency,
            0x13 => BStr,
            0x16 => LPTStr,
            0x17 => FixedSysString,
            0x19 => COMIUnknown,
            0x1a => COMIDispatch,
            0x1b => Struct,
            0x1c => COMInterface,
            0x1d => SafeArray,
            0x1e => FixedArray,
            0x22 => ByValStr,
            0x23 => AnsiBStr,
            0x24 => TBStr,
            0x25 => VariantBool,
            0x28 => AsAny,
            0x2b => LpStruct,
            0x2c => CustomMarshaler,
            0x30 => LPUTF8Str,
            bad => throw!("bad native instrinsic value {:#04x}", bad),
        };

        Ok((val, *offset))
    }
}
try_into_ctx!(NativeIntrinsic, |self, into| {
    let offset = &mut 0;

    use NativeIntrinsic::*;
    into.gwrite_with(
        match self {
            Boolean => NATIVE_TYPE_BOOLEAN,
            Int8 => NATIVE_TYPE_I1,
            UInt8 => NATIVE_TYPE_U1,
            Int16 => NATIVE_TYPE_I2,
            UInt16 => NATIVE_TYPE_U2,
            Int32 => NATIVE_TYPE_I4,
            UInt32 => NATIVE_TYPE_U4,
            Int64 => NATIVE_TYPE_I8,
            UInt64 => NATIVE_TYPE_U8,
            Float32 => NATIVE_TYPE_R4,
            Float64 => NATIVE_TYPE_R8,
            LPStr => NATIVE_TYPE_LPSTR,
            LPWStr => NATIVE_TYPE_LPWSTR,
            IntPtr => NATIVE_TYPE_INT,
            UIntPtr => NATIVE_TYPE_UINT,
            Function => NATIVE_TYPE_FUNC,
            // Microsoft specials
            Currency => 0x0f,
            BStr => 0x13,
            LPTStr => 0x16,
            FixedSysString => 0x17,
            COMIUnknown => 0x19,
            COMIDispatch => 0x1a,
            Struct => 0x1b,
            COMInterface => 0x1c,
            SafeArray => 0x1d,
            FixedArray => 0x1e,
            ByValStr => 0x22,
            AnsiBStr => 0x23,
            TBStr => 0x24,
            VariantBool => 0x25,
            AsAny => 0x28,
            LpStruct => 0x2b,
            CustomMarshaler => 0x2c,
            LPUTF8Str => 0x30,
        },
        offset,
        scroll::LE,
    )?;

    Ok(*offset)
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_ref_spec() {
        use crate::binary::metadata::{index::TokenTarget, table::Kind};

        let TypeDefOrRefOrSpec(t) = [0x49].pread(0).unwrap();
        assert_eq!(t.target, TokenTarget::Table(Kind::TypeRef));
        assert_eq!(t.index, 0x12);

        let mut buf = [0_u8; 1];
        buf.pwrite(TypeDefOrRefOrSpec(t), 0).unwrap();
        assert_eq!(buf, [0x49]);
    }
}
