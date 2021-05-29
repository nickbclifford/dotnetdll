use super::{
    super::metadata::{index, table},
    compressed, kinds,
};
use paste::paste;
use scroll::{ctx::TryFromCtx, Endian, Pread};

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

impl<'a> TryFromCtx<'a, Endian> for TypeDefOrRefOrSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(value) = from.gread_with(offset, ctx)?;

        Ok((
            TypeDefOrRefOrSpec(index::Token {
                table: match value & 0b11 {
                    0 => table::Kind::TypeDef,
                    1 => table::Kind::TypeRef,
                    2 => table::Kind::TypeSpec,
                    _ => {
                        return Err(scroll::Error::Custom(
                            "bad token table specifier".to_string(),
                        ))
                    }
                },
                index: (value >> 2) as usize,
            }),
            *offset,
        ))
    }
}

#[derive(Debug)]
pub struct ArrayShape {
    pub rank: usize,
    pub sizes: Vec<usize>,
    pub lower_bounds: Vec<isize>,
}

impl<'a> TryFromCtx<'a, Endian> for ArrayShape {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(rank) = from.gread_with(offset, ctx)?;

        let compressed::Unsigned(num_sizes) = from.gread_with(offset, ctx)?;
        let mut sizes = vec![];
        for _ in 0..num_sizes {
            let compressed::Unsigned(size) = from.gread_with(offset, ctx)?;
            sizes.push(size as usize);
        }

        let compressed::Unsigned(num_bounds) = from.gread_with(offset, ctx)?;
        let mut lower_bounds = vec![];
        for _ in 0..num_bounds {
            let compressed::Signed(bound) = from.gread_with(offset, ctx)?;
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

impl<'a> TryFromCtx<'a, Endian> for CustomMod {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let compressed::Unsigned(tag) = from.gread_with(offset, ctx)?;
        let token = from.gread_with(offset, ctx)?;

        Ok((
            match tag as u8 {
                ELEMENT_TYPE_CMOD_OPT => CustomMod::Optional(token),
                ELEMENT_TYPE_CMOD_REQD => CustomMod::Required(token),
                _ => return Err(scroll::Error::Custom("bad modifier tag type".to_string())),
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

impl<'a> TryFromCtx<'a, Endian> for Type {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, ctx)?;

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
                let type_data = from.gread_with(offset, ctx)?;
                let shape = from.gread_with(offset, ctx)?;
                Array(Box::new(type_data), shape)
            }
            ELEMENT_TYPE_CLASS => Class(from.gread_with(offset, ctx)?),
            ELEMENT_TYPE_FNPTR => {
                let prev_offset = *offset;
                match from.gread_with::<kinds::MethodDefSig>(offset, ctx) {
                    Ok(m) => FnPtrDef(Box::new(m)),
                    Err(_) => {
                        *offset = prev_offset;
                        FnPtrRef(Box::new(from.gread_with(offset, ctx)?))
                    }
                }
            }
            ELEMENT_TYPE_GENERICINST => {
                let next_tag: u8 = from.gread_with(offset, ctx)?;
                let token = from.gread_with(offset, ctx)?;

                let compressed::Unsigned(arg_count) = from.gread_with(offset, ctx)?;
                let mut types = vec![];
                for _ in 0..arg_count {
                    types.push(from.gread_with(offset, ctx)?);
                }

                match next_tag {
                    ELEMENT_TYPE_CLASS => GenericInstClass(token, types),
                    ELEMENT_TYPE_VALUETYPE => GenericInstValueType(token, types),
                    _ => {
                        return Err(scroll::Error::Custom(
                            "bad generic instantiation tag".to_string(),
                        ))
                    }
                }
            }
            ELEMENT_TYPE_MVAR => {
                let compressed::Unsigned(number) = from.gread_with(offset, ctx)?;
                MVar(number)
            }
            ELEMENT_TYPE_OBJECT => Object,
            ELEMENT_TYPE_PTR => {
                let prev_offset = *offset;
                let opt_mod = from.gread_with::<CustomMod>(offset, ctx).ok();
                if opt_mod.is_none() {
                    *offset = prev_offset;
                }

                let next_tag: u8 = from.gread_with(offset, ctx)?;
                let type_data = if next_tag == ELEMENT_TYPE_VOID {
                    None
                } else {
                    *offset -= 1;
                    Some(from.gread_with(offset, ctx)?)
                };

                Ptr(opt_mod, Box::new(type_data))
            }
            ELEMENT_TYPE_STRING => String,
            ELEMENT_TYPE_SZARRAY => {
                let prev_offset = *offset;
                let opt_mod = from.gread_with::<CustomMod>(offset, ctx).ok();
                if opt_mod.is_none() {
                    *offset = prev_offset;
                }

                let type_data = from.gread_with(offset, ctx)?;
                SzArray(opt_mod, Box::new(type_data))
            }
            ELEMENT_TYPE_VALUETYPE => ValueType(from.gread_with(offset, ctx)?),
            ELEMENT_TYPE_VAR => {
                let compressed::Unsigned(number) = from.gread_with(offset, ctx)?;
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

impl<'a> TryFromCtx<'a, Endian> for Param {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let prev_offset = *offset;
        let opt_mod = from.gread_with::<CustomMod>(offset, ctx).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

        let tag: u8 = from.gread_with(offset, ctx)?;
        let val = match tag {
            ELEMENT_TYPE_TYPEDBYREF => ParamType::TypedByRef,
            ELEMENT_TYPE_BYREF => ParamType::ByRef(from.gread_with(offset, ctx)?),
            _ => {
                *offset -= 1;
                ParamType::ByRef(from.gread_with(offset, ctx)?)
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

impl<'a> TryFromCtx<'a, Endian> for RetType {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let prev_offset = *offset;
        let opt_mod = from.gread_with::<CustomMod>(offset, ctx).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

        let tag: u8 = from.gread_with(offset, ctx)?;
        let val = match tag {
            ELEMENT_TYPE_VOID => RetTypeType::Void,
            ELEMENT_TYPE_TYPEDBYREF => RetTypeType::TypedByRef,
            ELEMENT_TYPE_BYREF => RetTypeType::ByRef(from.gread_with(offset, ctx)?),
            _ => {
                *offset -= 1;
                RetTypeType::ByRef(from.gread_with(offset, ctx)?)
            }
        };

        Ok((RetType(opt_mod, val), *offset))
    }
}
