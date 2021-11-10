use paste::paste;
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Error, Pread, Pwrite,
};

use super::{
    super::metadata::{index, table},
    compressed, kinds,
};

macro_rules! element_types {
    ($($name:ident = $val:literal),+) => {
        $(
            paste! {
                pub const [<ELEMENT_TYPE_ $name>]: u8 = $val;
            }
        )*
    }
}

element_types! {
    END = 0x00,
    VOID = 0x01,
    BOOLEAN = 0x02,
    CHAR = 0x03,
    I1 = 0x04,
    U1 = 0x05,
    I2 = 0x06,
    U2 = 0x07,
    I4 = 0x08,
    U4 = 0x09,
    I8 = 0x0a,
    U8 = 0x0b,
    R4 = 0x0c,
    R8 = 0x0d,
    STRING = 0x0e,
    PTR = 0x0f,
    BYREF = 0x10,
    VALUETYPE = 0x11,
    CLASS = 0x12,
    VAR = 0x13,
    ARRAY = 0x14,
    GENERICINST = 0x15,
    TYPEDBYREF = 0x16,
    I = 0x18,
    U = 0x19,
    FNPTR = 0x1b,
    OBJECT = 0x1c,
    SZARRAY = 0x1d,
    MVAR = 0x1e,
    CMOD_REQD = 0x1f,
    CMOD_OPT = 0x20,
    INTERNAL = 0x21,
    MODIFIER = 0x40,
    SENTINEL = 0x41,
    PINNED = 0x45
}

#[derive(Debug, Clone)]
pub struct TypeDefOrRefOrSpec(pub index::Token);

impl TryFromCtx<'_> for TypeDefOrRefOrSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
impl TryIntoCtx for TypeDefOrRefOrSpec {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
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
    }
}

#[derive(Debug, Clone)]
pub struct ArrayShape {
    pub rank: usize,
    pub sizes: Vec<usize>,
    pub lower_bounds: Vec<isize>,
}

impl TryFromCtx<'_> for ArrayShape {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
impl TryIntoCtx for ArrayShape {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
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
    }
}

#[derive(Debug, Clone)]
pub enum CustomMod {
    Required(TypeDefOrRefOrSpec),
    Optional(TypeDefOrRefOrSpec),
}

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

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(tag) = from.gread(offset)?;
        let token = from.gread(offset)?;

        Ok((
            match tag as u8 {
                ELEMENT_TYPE_CMOD_OPT => CustomMod::Optional(token),
                ELEMENT_TYPE_CMOD_REQD => CustomMod::Required(token),
                _ => return Err(FailUnit),
            },
            *offset,
        ))
    }
}
impl TryIntoCtx for CustomMod {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        let (tag, token) = match self {
            CustomMod::Required(t) => (ELEMENT_TYPE_CMOD_REQD, t),
            CustomMod::Optional(t) => (ELEMENT_TYPE_CMOD_OPT, t),
        };

        into.gwrite(compressed::Unsigned(tag as u32), offset)?;
        into.gwrite(token, offset)?;

        Ok(*offset)
    }
}

pub fn all_custom_mods(from: &[u8], offset: &mut usize) -> Vec<CustomMod> {
    let mut mods = vec![];

    loop {
        match from.gread::<CustomMod>(offset) {
            Ok(m) => mods.push(m),
            Err(_) => return mods,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Type {
    Boolean,
    Char,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float32,
    Float64,
    IntPtr,
    UIntPtr,
    Array(Box<Type>, ArrayShape),
    Class(TypeDefOrRefOrSpec),
    FnPtr(Box<kinds::StandAloneMethodSig>),
    GenericInstClass(TypeDefOrRefOrSpec, Vec<Type>),
    GenericInstValueType(TypeDefOrRefOrSpec, Vec<Type>),
    MVar(u32),
    Object,
    Ptr(Vec<CustomMod>, Option<Box<Type>>),
    String,
    SzArray(Vec<CustomMod>, Box<Type>),
    ValueType(TypeDefOrRefOrSpec),
    Var(u32),
}

impl TryFromCtx<'_> for Type {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
                let types = (0..arg_count)
                    .map(|_| from.gread(offset))
                    .collect::<Result<_, _>>()?;

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
impl TryIntoCtx for Type {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
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
    }
}

#[derive(Debug, Clone)]
pub enum ParamType {
    Type(Type),
    ByRef(Type),
    TypedByRef,
}

#[derive(Debug, Clone)]
pub struct Param(pub Vec<CustomMod>, pub ParamType);

impl TryFromCtx<'_> for Param {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
impl TryIntoCtx for Param {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
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
            ParamType::TypedByRef => {
                into.gwrite_with(ELEMENT_TYPE_TYPEDBYREF, offset, scroll::LE)?
            }
        };

        Ok(*offset)
    }
}

#[derive(Debug, Clone)]
pub enum RetTypeType {
    Type(Type),
    ByRef(Type),
    TypedByRef,
    Void,
}

#[derive(Debug, Clone)]
pub struct RetType(pub Vec<CustomMod>, pub RetTypeType);

impl TryFromCtx<'_> for RetType {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
impl TryIntoCtx for RetType {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
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
            RetTypeType::TypedByRef => {
                into.gwrite_with(ELEMENT_TYPE_TYPEDBYREF, offset, scroll::LE)?
            }
            RetTypeType::Void => into.gwrite_with(ELEMENT_TYPE_VOID, offset, scroll::LE)?,
        };

        Ok(*offset)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum NativeIntrinsic {
    Boolean,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float32,
    Float64,
    LPStr,
    LPWStr,
    IntPtr,
    UIntPtr,
    Function,
    // not in ECMA spec, but part of Microsoft unmanaged types
    COMInterface,
    BStr,
    AsAny,
    COMIUnknown,
    LPUTF8Str,
}

macro_rules! native_types {
    ($($name:ident = $val:literal),+) => {
        $(
            paste! {
                pub const [<NATIVE_TYPE_ $name>]: u8 = $val;
            }
        )*
    }
}

native_types! {
    BOOLEAN = 0x02,
    I1 = 0x03,
    U1 = 0x04,
    I2 = 0x05,
    U2 = 0x06,
    I4 = 0x07,
    U4 = 0x08,
    I8 = 0x09,
    U8 = 0x0a,
    R4 = 0x0b,
    R8 = 0x0c,
    LPSTR = 0x14,
    LPWSTR = 0x15,
    INT = 0x1f,
    UINT = 0x20,
    FUNC = 0x26,
    ARRAY = 0x2a,
    MAX = 0x50
}

impl TryFromCtx<'_> for NativeIntrinsic {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
            0x13 => BStr,
            0x19 => COMIUnknown,
            0x1c => COMInterface,
            0x28 => AsAny,
            0x30 => LPUTF8Str,
            bad => throw!("bad native instrinsic value {:#04x}", bad),
        };

        Ok((val, *offset))
    }
}
impl TryIntoCtx for NativeIntrinsic {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
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
                BStr => 0x13,
                COMIUnknown => 0x19,
                COMInterface => 0x1c,
                AsAny => 0x28,
                LPUTF8Str => 0x30,
            },
            offset,
            scroll::LE,
        )?;

        Ok(*offset)
    }
}
