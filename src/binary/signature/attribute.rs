use super::encoded::*;
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};

pub struct SerString<'a>(pub Option<&'a str>);
impl<'a> TryFromCtx<'a> for SerString<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let val = match from.gread_with(offset, scroll::LE)? {
            0xFF_u8 => None,
            0x00_u8 => Some(""),
            len => Some(from.gread_with(offset, scroll::ctx::StrCtx::Length(len as usize))?),
        };

        Ok((SerString(val), *offset))
    }
}
impl TryIntoCtx for SerString<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        match self.0 {
            Some(str) => {
                into.gwrite_with(str.len() as u8, offset, scroll::LE)?;
                into.gwrite(str, offset)?;
            }
            None => {
                into.gwrite_with(0xFF_u8, offset, scroll::LE)?;
            }
        }

        Ok(*offset)
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
            0x55 => Enum(from.gread::<SerString>(offset)?.0.ok_or_else(|| {
                scroll::Error::Custom("null enum name encountered when parsing custom attribute".to_string())
            })?),
            bad => throw!("bad custom attribute type tag {:#04x}", bad),
        };

        Ok((val, *offset))
    }
}
impl TryIntoCtx for FieldOrPropType<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        use FieldOrPropType::*;
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
            String => {
                into.gwrite_with(ELEMENT_TYPE_STRING, offset, scroll::LE)?;
            }
            Type => {
                into.gwrite_with(0x50_u8, offset, scroll::LE)?;
            }
            Object => {
                into.gwrite_with(0x51_u8, offset, scroll::LE)?;
            }
            Vector(t) => {
                into.gwrite_with(ELEMENT_TYPE_SZARRAY, offset, scroll::LE)?;
                into.gwrite(*t, offset)?;
            }
            Enum(n) => {
                into.gwrite_with(0x55_u8, offset, scroll::LE)?;
                into.gwrite(SerString(Some(n)), offset)?;
            }
        }

        Ok(*offset)
    }
}

#[derive(Debug, Copy, Clone)]
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
impl IntegralParam {
    pub fn argument_type(&self) -> FieldOrPropType {
        macro_rules! build_match {
            ($($variant:ident),*) => {
                match self {
                    $(
                        IntegralParam::$variant(_) => FieldOrPropType::$variant,
                    )*
                }
            }
        }

        build_match!(Int8, Int16, Int32, Int64, UInt8, UInt16, UInt32, UInt64)
    }
}
impl TryIntoCtx for IntegralParam {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        macro_rules! build_match {
            ($($variant:ident),*) => {
                match self {
                    $(
                        IntegralParam::$variant(val) => into.gwrite_with(val, offset, scroll::LE)?,
                    )*
                }
            }
        }

        build_match!(Int8, Int16, Int32, Int64, UInt8, UInt16, UInt32, UInt64);

        Ok(*offset)
    }
}

#[derive(Debug, Clone)]
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
impl<'a> FixedArg<'a> {
    pub fn argument_type(&'a self) -> FieldOrPropType<'a> {
        use FixedArg::*;
        match self {
            Boolean(_) => FieldOrPropType::Boolean,
            Char(_) => FieldOrPropType::Char,
            Float32(_) => FieldOrPropType::Float32,
            Float64(_) => FieldOrPropType::Float64,
            String(_) => FieldOrPropType::String,
            Integral(i) => i.argument_type(),
            Enum(name, _) => FieldOrPropType::Enum(name),
            Type(_) => FieldOrPropType::Type,
            // TODO: are these semantics correct?
            Array(t) => match t {
                Some(v) => FieldOrPropType::Vector(Box::new(v[0].argument_type())),
                None => panic!("null array attribute argument invalid in this context"),
            },
            Object(_) => FieldOrPropType::Object,
        }
    }
}
impl TryIntoCtx for FixedArg<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        use FixedArg::*;
        match self {
            Boolean(b) => {
                into.gwrite_with(if b { 1_u8 } else { 0_u8 }, offset, scroll::LE)?;
            }
            Char(c) => {
                into.gwrite_with(c as u16, offset, scroll::LE)?;
            }
            Float32(f) => {
                into.gwrite_with(f, offset, scroll::LE)?;
            }
            Float64(f) => {
                into.gwrite_with(f, offset, scroll::LE)?;
            }
            String(s) => {
                into.gwrite(SerString(s), offset)?;
            }
            Integral(i) => {
                into.gwrite(i, offset)?;
            }
            Enum(_, val) => {
                into.gwrite(val, offset)?;
            }
            Type(t) => {
                into.gwrite(SerString(Some(t)), offset)?;
            }
            Array(v) => match v {
                Some(vector) => {
                    into.gwrite_with(vector.len() as u32, offset, scroll::LE)?;
                    for value in vector {
                        into.gwrite(value, offset)?;
                    }
                }
                None => {
                    into.gwrite_with(u32::MAX, offset, scroll::LE)?;
                }
            },
            Object(b) => {
                into.gwrite(b.argument_type(), offset)?;
                into.gwrite(*b, offset)?;
            }
        }

        Ok(*offset)
    }
}

#[derive(Debug, Clone)]
pub enum NamedArg<'a> {
    Field(&'a str, FixedArg<'a>),
    Property(&'a str, FixedArg<'a>),
}
impl TryIntoCtx for NamedArg<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        use NamedArg::*;
        let (tag, name, arg) = match self {
            Field(n, a) => (0x53_u8, n, a),
            Property(n, a) => (0x54_u8, n, a),
        };

        into.gwrite_with(tag, offset, scroll::LE)?;
        into.gwrite(arg.argument_type(), offset)?;
        into.gwrite(SerString(Some(name)), offset)?;
        into.gwrite(arg, offset)?;

        Ok(*offset)
    }
}

#[derive(Debug)]
pub struct CustomAttributeData<'a> {
    pub constructor_args: Vec<FixedArg<'a>>,
    pub named_args: Vec<NamedArg<'a>>,
}
impl TryIntoCtx for CustomAttributeData<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(0x0001_u16, offset, scroll::LE)?;

        for a in self.constructor_args {
            into.gwrite(a, offset)?;
        }

        into.gwrite_with(self.named_args.len() as u16, offset, scroll::LE)?;

        for a in self.named_args {
            into.gwrite(a, offset)?;
        }

        Ok(*offset)
    }
}
