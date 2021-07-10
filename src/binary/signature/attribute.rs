use super::encoded::*;
use scroll::{ctx::TryFromCtx, Pread};

pub struct SerString<'a>(pub Option<&'a str>);
impl<'a> TryFromCtx<'a> for SerString<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let len: u8 = from.gread_with(offset, scroll::LE)?;
        let val = if len == 0xFF {
            None
        } else if len == 0x00 {
            Some("")
        } else {
            Some(from.gread_with(offset, scroll::ctx::StrCtx::Length(len as usize))?)
        };

        Ok((SerString(val), *offset))
    }
}

#[derive(Debug, Clone)]
pub enum FieldOrPropType<'a> {
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
    String,
    Type,
    Object,
    Vector(Box<FieldOrPropType<'a>>),
    Enum(&'a str),
}

impl<'a> TryFromCtx<'a> for FieldOrPropType<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        use FieldOrPropType::*;

        let val = match from.gread_with::<u8>(offset, scroll::LE)? {
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
            ELEMENT_TYPE_STRING => String,
            ELEMENT_TYPE_SZARRAY => Vector(Box::new(from.gread(offset)?)),
            0x50 => Type,
            0x51 => Object,
            0x55 => Enum(
                from.gread::<SerString>(offset)?
                    .0
                    .ok_or(scroll::Error::Custom(
                        "null enum name encountered when parsing custom attribute".to_string(),
                    ))?,
            ),
            bad => throw!("bad custom attribute type tag {:#04x}", bad),
        };

        Ok((val, *offset))
    }
}

#[derive(Debug)]
pub enum IntegralParam {
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
}

#[derive(Debug)]
pub enum FixedArg<'a> {
    Boolean(bool),
    Char(char),
    Float32(f32),
    Float64(f64),
    String(Option<&'a str>),
    Integral(IntegralParam),
    Enum(&'a str, IntegralParam),
    Type(&'a str),
    Array(Option<Vec<FixedArg<'a>>>),
    Object(Box<FixedArg<'a>>),
}

#[derive(Debug)]
pub enum NamedArg<'a> {
    Field(&'a str, FixedArg<'a>),
    Property(&'a str, FixedArg<'a>),
}

#[derive(Debug)]
pub struct CustomAttributeData<'a> {
    pub constructor_args: Vec<FixedArg<'a>>,
    pub named_args: Vec<NamedArg<'a>>,
}
