use super::{
    super::metadata::{index, table},
    compressed, kinds,
};
use paste::paste;
use scroll::{ctx::TryFromCtx, Pread};

macro_rules! element_types {
    ($($name:ident = $val:literal,)+) => {
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
    PINNED = 0x45,
}

#[derive(Debug)]
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
                    _ => {
                        return Err(scroll::Error::Custom(
                            "bad token table specifier".to_string(),
                        ))
                    }
                }),
                index: (value >> 2) as usize,
            }),
            *offset,
        ))
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
        let mut sizes = Vec::with_capacity(num_sizes as usize);
        for _ in 0..num_sizes {
            let compressed::Unsigned(size) = from.gread(offset)?;
            sizes.push(size as usize);
        }

        let compressed::Unsigned(num_bounds) = from.gread(offset)?;
        let mut lower_bounds = Vec::with_capacity(num_bounds as usize);
        for _ in 0..num_bounds {
            let compressed::Signed(bound) = from.gread(offset)?;
            lower_bounds.push(bound as isize);
        }

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

#[derive(Debug)]
pub enum CustomMod {
    Required(TypeDefOrRefOrSpec),
    Optional(TypeDefOrRefOrSpec),
}

impl TryFromCtx<'_> for CustomMod {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(tag) = from.gread(offset)?;
        let token = from.gread(offset)?;

        Ok((
            match tag as u8 {
                ELEMENT_TYPE_CMOD_OPT => CustomMod::Optional(token),
                ELEMENT_TYPE_CMOD_REQD => CustomMod::Required(token),
                _ => {
                    return Err(scroll::Error::Custom(format!(
                        "bad modifier tag type {:#04x}",
                        tag
                    )))
                }
            },
            *offset,
        ))
    }
}

#[derive(Debug)]
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
    FnPtrDef(Box<kinds::MethodDefSig>),
    FnPtrRef(Box<kinds::MethodRefSig>),
    GenericInstClass(TypeDefOrRefOrSpec, Vec<Type>),
    GenericInstValueType(TypeDefOrRefOrSpec, Vec<Type>),
    MVar(u32),
    Object,
    Ptr(Option<CustomMod>, Box<Option<Type>>),
    String,
    SzArray(Option<CustomMod>, Box<Type>),
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
            ELEMENT_TYPE_FNPTR => {
                let prev_offset = *offset;
                match from.gread_with::<kinds::MethodDefSig>(offset, ()) {
                    Ok(m) => FnPtrDef(Box::new(m)),
                    Err(_) => {
                        *offset = prev_offset;
                        FnPtrRef(Box::new(from.gread(offset)?))
                    }
                }
            }
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
                    _ => {
                        return Err(scroll::Error::Custom(format!(
                            "bad generic instantiation tag {:#04x}",
                            next_tag
                        )))
                    }
                }
            }
            ELEMENT_TYPE_MVAR => {
                let compressed::Unsigned(number) = from.gread(offset)?;
                MVar(number)
            }
            ELEMENT_TYPE_OBJECT => Object,
            ELEMENT_TYPE_PTR => {
                let prev_offset = *offset;
                let opt_mod = from.gread(offset).ok();
                if opt_mod.is_none() {
                    *offset = prev_offset;
                }

                let next_tag: u8 = from.gread_with(offset, scroll::LE)?;
                let type_data = if next_tag == ELEMENT_TYPE_VOID {
                    None
                } else {
                    *offset -= 1;
                    Some(from.gread(offset)?)
                };

                Ptr(opt_mod, Box::new(type_data))
            }
            ELEMENT_TYPE_STRING => String,
            ELEMENT_TYPE_SZARRAY => {
                let prev_offset = *offset;
                let opt_mod = from.gread(offset).ok();
                if opt_mod.is_none() {
                    *offset = prev_offset;
                }

                let type_data = from.gread(offset)?;
                SzArray(opt_mod, Box::new(type_data))
            }
            ELEMENT_TYPE_VALUETYPE => ValueType(from.gread(offset)?),
            ELEMENT_TYPE_VAR => {
                let compressed::Unsigned(number) = from.gread(offset)?;
                Var(number)
            }
            _ => {
                return Err(scroll::Error::Custom(format!(
                    "bad type discriminator tag {:#04x}",
                    tag
                )))
            }
        };

        Ok((val, *offset))
    }
}

#[derive(Debug)]
// no idea what the hell any of this means
pub enum ParamType {
    Type(Type),
    ByRef(Type),
    TypedByRef,
}

#[derive(Debug)]
pub struct Param(pub Option<CustomMod>, pub ParamType);

impl TryFromCtx<'_> for Param {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let prev_offset = *offset;
        let opt_mod = from.gread(offset).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        let val = match tag {
            ELEMENT_TYPE_TYPEDBYREF => ParamType::TypedByRef,
            ELEMENT_TYPE_BYREF => ParamType::ByRef(from.gread(offset)?),
            _ => {
                *offset -= 1;
                ParamType::Type(from.gread(offset)?)
            }
        };

        Ok((Param(opt_mod, val), *offset))
    }
}

#[derive(Debug)]
pub enum RetTypeType {
    Type(Type),
    ByRef(Type),
    TypedByRef,
    Void,
}

#[derive(Debug)]
pub struct RetType(pub Option<CustomMod>, pub RetTypeType);

impl TryFromCtx<'_> for RetType {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let prev_offset = *offset;
        let opt_mod = from.gread(offset).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

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

        Ok((RetType(opt_mod, val), *offset))
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
    ARRAY = 0x2a
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
            bad => {
                return Err(scroll::Error::Custom(format!(
                    "bad native instrinsic value {:#04x}",
                    bad
                )))
            }
        };

        Ok((val, *offset))
    }
}
