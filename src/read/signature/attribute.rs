use scroll::{ctx::TryFromCtx, Pread};

struct SerString<'a>(pub Option<&'a str>);
impl<'a> TryFromCtx<'a, ()> for SerString<'a> {
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
pub enum ValueParam<'a> {
    Bool(bool),
    Char(char),
    Float32(f32),
    Float64(f64),
    String(Option<&'a str>),
    Integral(IntegralParam),
}

#[derive(Debug)]
pub enum BoxedParam<'a> {
    Value(ValueParam<'a>),
    Enum(&'a str, IntegralParam),
    Array(Vec<BoxedParam<'a>>),
}

#[derive(Debug)]
pub enum Elem<'a> {
    Simple(ValueParam<'a>),
    Boxed(BoxedParam<'a>),
    Type(&'a str),
}

pub enum FixedArg<'a> {
    Array(Option<Vec<Elem<'a>>>),
    Scalar(Elem<'a>),
}

// TODO: attribute signatures require fully-resolved type knowledge for parsing
// not only dependent on constructor parameter types, but boxed types require full type name lookup
