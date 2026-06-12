use std::borrow::Cow;

use super::encoded::*;
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};

/// `SerString` payload used inside custom-attribute blobs.
///
/// `SerString` is encoded as a one-byte length followed by UTF-8 bytes. The special byte
/// value `0xFF` represents `null`; this maps to `None` in this type. An empty but non-null
/// string is encoded with length `0x00` and maps to `Some("")`.
///
/// ECMA-335, II.23.3.
pub struct SerString<'a>(pub Option<Cow<'a, str>>);
impl<'a> TryFromCtx<'a> for SerString<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let val = match from.gread_with(offset, scroll::LE)? {
            0xFF_u8 => None,
            0x00_u8 => Some("".into()),
            len => Some(
                from.gread_with::<&str>(offset, scroll::ctx::StrCtx::Length(len as usize))?
                    .into(),
            ),
        };

        Ok((SerString(val), *offset))
    }
}
try_into_ctx!(SerString<'_>, |self, into| {
    let offset = &mut 0;

    match &self.0 {
        Some(str) => {
            into.gwrite_with(str.len() as u8, offset, scroll::LE)?;
            into.gwrite(str.as_bytes(), offset)?;
        }
        None => {
            into.gwrite_with(0xFF_u8, offset, scroll::LE)?;
        }
    }

    Ok(*offset)
});

/// Type discriminator used by custom-attribute fixed arguments and named arguments.
///
/// This is the `FieldOrPropType` grammar from custom-attribute blob encoding.
///
/// - Primitive variants map to their corresponding `ELEMENT_TYPE_*` tags.
/// - [`FieldOrPropType::Type`] represents `System.Type` values, whose runtime value is encoded
///   as a [`SerString`].
/// - [`FieldOrPropType::Enum`] stores the enum's fully qualified type name.
///
/// ECMA-335, II.23.3.
#[derive(Debug, Clone)]
pub enum FieldOrPropType<'a> {
    /// `bool` (`ELEMENT_TYPE_BOOLEAN`).
    Boolean,
    /// UTF-16 code unit (`ELEMENT_TYPE_CHAR`).
    Char,
    /// Signed 8-bit integer (`ELEMENT_TYPE_I1`).
    Int8,
    /// Unsigned 8-bit integer (`ELEMENT_TYPE_U1`).
    UInt8,
    /// Signed 16-bit integer (`ELEMENT_TYPE_I2`).
    Int16,
    /// Unsigned 16-bit integer (`ELEMENT_TYPE_U2`).
    UInt16,
    /// Signed 32-bit integer (`ELEMENT_TYPE_I4`).
    Int32,
    /// Unsigned 32-bit integer (`ELEMENT_TYPE_U4`).
    UInt32,
    /// Signed 64-bit integer (`ELEMENT_TYPE_I8`).
    Int64,
    /// Unsigned 64-bit integer (`ELEMENT_TYPE_U8`).
    UInt64,
    /// 32-bit floating-point number (`ELEMENT_TYPE_R4`).
    Float32,
    /// 64-bit floating-point number (`ELEMENT_TYPE_R8`).
    Float64,
    /// `string` (`ELEMENT_TYPE_STRING`), stored as a [`SerString`] value.
    String,
    /// `System.Type` (`0x50`), stored as a [`SerString`] value naming the type.
    Type,
    /// Boxed object (`0x51`) with an inline type tag and value payload.
    Object,
    /// Single-dimensional zero-based array (`ELEMENT_TYPE_SZARRAY`) of another field/property type.
    Vector(Box<FieldOrPropType<'a>>),
    /// Enumeration type (`0x55`) identified by fully qualified type name.
    Enum(Cow<'a, str>),
}

impl<'a> TryFromCtx<'a> for FieldOrPropType<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], (): ()) -> Result<(Self, usize), Self::Error> {
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
try_into_ctx!(FieldOrPropType<'_>, |self, into| {
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
});

/// Integral value payload used by custom-attribute arguments.
///
/// This enum preserves the integer width and signedness from the blob so callers can
/// round-trip the original binary representation.
///
/// ECMA-335, II.23.3.
#[derive(Debug, Copy, Clone)]
pub enum IntegralParam {
    /// Signed 8-bit integer.
    Int8(i8),
    /// Signed 16-bit integer.
    Int16(i16),
    /// Signed 32-bit integer.
    Int32(i32),
    /// Signed 64-bit integer.
    Int64(i64),
    /// Unsigned 8-bit integer.
    UInt8(u8),
    /// Unsigned 16-bit integer.
    UInt16(u16),
    /// Unsigned 32-bit integer.
    UInt32(u32),
    /// Unsigned 64-bit integer.
    UInt64(u64),
}
impl IntegralParam {
    /// Returns the corresponding [`FieldOrPropType`] discriminator for this value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotnetdll::binary::signature::attribute::{FieldOrPropType, IntegralParam};
    ///
    /// fn as_i128(value: IntegralParam) -> i128 {
    ///     match value {
    ///         IntegralParam::Int8(v) => i128::from(v),
    ///         IntegralParam::Int16(v) => i128::from(v),
    ///         IntegralParam::Int32(v) => i128::from(v),
    ///         IntegralParam::Int64(v) => i128::from(v),
    ///         IntegralParam::UInt8(v) => i128::from(v),
    ///         IntegralParam::UInt16(v) => i128::from(v),
    ///         IntegralParam::UInt32(v) => i128::from(v),
    ///         IntegralParam::UInt64(v) => i128::from(v),
    ///     }
    /// }
    ///
    /// let arg = IntegralParam::UInt16(512);
    /// assert!(matches!(arg.argument_type(), FieldOrPropType::UInt16));
    /// assert_eq!(as_i128(arg), 512);
    /// ```
    pub fn argument_type(&self) -> FieldOrPropType<'_> {
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
try_into_ctx!(IntegralParam, |self, into| {
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
});

/// Fixed (positional) custom-attribute argument payload.
///
/// These values appear in constructor argument order immediately after the custom-attribute
/// prolog. The variant determines the exact binary payload encoding.
///
/// Values of this type are produced by
/// [`crate::resolved::attribute::Attribute::instantiation_data`] in
/// [`CustomAttributeData::constructor_args`], and are typically consumed via pattern matching.
///
/// # Examples
///
/// ```rust,no_run
/// use dotnetdll::binary::signature::attribute::{FixedArg, IntegralParam};
/// use dotnetdll::prelude::*;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let bytes = std::fs::read("MyAssembly.dll")?;
/// let resolution = Resolution::parse(&bytes, ReadOptions::default())?;
///
/// let attribute = resolution
///     .assembly
///     .as_ref()
///     .and_then(|assembly| assembly.attributes.first())
///     .expect("assembly has at least one custom attribute");
///
/// let decoded = attribute.instantiation_data(&AlwaysFailsResolver, &resolution)?;
///
/// for arg in decoded.constructor_args {
///     match arg {
///         FixedArg::Integral(IntegralParam::Int32(v)) => println!("int32: {v}"),
///         FixedArg::String(Some(s)) => println!("string: {s}"),
///         FixedArg::Array(_, Some(values)) => println!("array length: {}", values.len()),
///         other => println!("other fixed arg: {other:?}"),
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ECMA-335, II.23.3.
#[derive(Debug, Clone)]
pub enum FixedArg<'a> {
    /// Boolean value (`bool`).
    Boolean(bool),
    /// Character value (`char`).
    Char(char),
    /// 32-bit floating-point value.
    Float32(f32),
    /// 64-bit floating-point value.
    Float64(f64),
    /// String value encoded as `SerString`, where `None` is the `0xFF` null sentinel.
    String(Option<Cow<'a, str>>),
    /// Integral value payload.
    Integral(IntegralParam),
    /// Enum value encoded as `(enum type name, underlying integral value)`.
    Enum(Cow<'a, str>, IntegralParam),
    /// `System.Type` value encoded as a type-name string.
    Type(Cow<'a, str>),
    /// `SZARRAY` value encoded as `(element type, optional element list)`.
    ///
    /// `None` is encoded as `0xFFFFFFFF` (null array).
    Array(FieldOrPropType<'a>, Option<Vec<FixedArg<'a>>>),
    /// Boxed object value with inline discriminator and payload.
    Object(Box<FixedArg<'a>>),
}
impl FixedArg<'_> {
    /// Returns the [`FieldOrPropType`] discriminator used when this value is encoded.
    pub fn argument_type(&self) -> FieldOrPropType<'_> {
        use FixedArg::*;
        match self {
            Boolean(_) => FieldOrPropType::Boolean,
            Char(_) => FieldOrPropType::Char,
            Float32(_) => FieldOrPropType::Float32,
            Float64(_) => FieldOrPropType::Float64,
            String(_) => FieldOrPropType::String,
            Integral(i) => i.argument_type(),
            Enum(name, _) => FieldOrPropType::Enum(name.clone()),
            Type(_name) => FieldOrPropType::Type,
            Array(t, _) => FieldOrPropType::Vector(Box::new(t.clone())),
            Object(_) => FieldOrPropType::Object,
        }
    }
}

try_into_ctx!(FixedArg<'_>, |self, into| {
    let offset = &mut 0;

    use FixedArg::*;
    match self {
        Boolean(b) => {
            into.gwrite_with(b as u8, offset, scroll::LE)?;
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
        Array(_, v) => match v {
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
});

/// Named custom-attribute argument payload.
///
/// Named arguments are encoded after fixed constructor arguments and target either a field
/// (`0x53`) or property (`0x54`) on the custom-attribute type.
///
/// ECMA-335, II.23.3.
#[derive(Debug, Clone)]
pub enum NamedArg<'a> {
    /// Assign a field by `(name, value)`.
    Field(Cow<'a, str>, FixedArg<'a>),
    /// Assign a property by `(name, value)`.
    Property(Cow<'a, str>, FixedArg<'a>),
}
try_into_ctx!(NamedArg<'_>, |self, into| {
    let offset = &mut 0;

    use NamedArg::*;
    let (tag, name, arg) = match self {
        Field(n, a) => (0x53_u8, n, a),
        Property(n, a) => (0x54_u8, n, a),
    };

    into.gwrite_with(tag, offset, scroll::LE)?;
    into.gwrite(arg.argument_type(), offset)?;
    into.gwrite(SerString(Some(name.clone())), offset)?;
    into.gwrite(arg, offset)?;

    Ok(*offset)
});

/// Structured representation of a custom-attribute blob body.
///
/// The encoded form is:
///
/// 1. Prolog `0x0001` (`u16`),
/// 2. Fixed constructor arguments,
/// 3. Named-argument count (`u16`),
/// 4. Named arguments.
///
/// ECMA-335, II.23.3.
///
/// See also: [`crate::resolved::attribute::Attribute`].
#[derive(Debug)]
pub struct CustomAttributeData<'a> {
    /// Fixed constructor arguments in declaration order.
    pub constructor_args: Vec<FixedArg<'a>>,
    /// Trailing named field/property assignments.
    pub named_args: Vec<NamedArg<'a>>,
}
try_into_ctx!(CustomAttributeData<'_>, |self, into| {
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
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_args_write() -> Result<(), Box<dyn std::error::Error>> {
        use scroll::Pwrite;
        use FixedArg::*;
        use IntegralParam::*;
        use NamedArg::*;

        const SIZE: usize = 119;
        // retrieved from ildasm
        const DATA: [u8; SIZE] = [
            0x01, 0x00, 0x01, 0x61, 0x00, 0x04, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x09, 0x00, 0x00, 0x00, 0x1D, 0x51, 0x04, 0x00,
            0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00, 0x08, 0x05, 0x00, 0x00, 0x00, 0x1D, 0x51, 0x01, 0x00, 0x00, 0x00,
            0x08, 0x02, 0x00, 0x00, 0x00, 0x0E, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x55, 0x09,
            0x74, 0x65, 0x73, 0x74, 0x2E, 0x41, 0x73, 0x64, 0x66, 0x04, 0x00, 0x0E, 0x04, 0x6F, 0x6F, 0x70, 0x73, 0x02,
            0x00, 0x53, 0x08, 0x03, 0x59, 0x65, 0x73, 0x03, 0x00, 0x00, 0x00, 0x53, 0x51, 0x02, 0x4E, 0x6F, 0x55, 0x09,
            0x74, 0x65, 0x73, 0x74, 0x2E, 0x41, 0x73, 0x64, 0x66, 0x04, 0x00,
        ];

        let mut buf = [0_u8; SIZE];
        buf.pwrite(
            // Into<Box<_>> is a little less noisy here
            CustomAttributeData {
                constructor_args: vec![
                    Boolean(true),
                    Char('a'),
                    Integral(UInt16(4)),
                    Array(FieldOrPropType::Int32, None),
                    Array(
                        FieldOrPropType::Int32,
                        Some(vec![Integral(Int32(2)), Integral(Int32(4)), Integral(Int32(5))]),
                    ),
                    Object(Integral(Int32(9)).into()),
                    Object(
                        Array(
                            FieldOrPropType::Object,
                            Some(vec![
                                Object(Integral(Int32(2)).into()),
                                Object(Integral(Int32(5)).into()),
                                Object(
                                    Array(FieldOrPropType::Object, Some(vec![Object(Integral(Int32(2)).into())]))
                                        .into(),
                                ),
                                Object(String(None).into()),
                            ]),
                        )
                        .into(),
                    ),
                    Array(
                        FieldOrPropType::Object,
                        Some(vec![
                            Object(Integral(Int32(3)).into()),
                            Object(Enum("test.Asdf".into(), UInt16(4)).into()),
                            Object(String(Some("oops".into())).into()),
                        ]),
                    ),
                ],
                named_args: vec![
                    Field("Yes".into(), Integral(Int32(3))),
                    Field("No".into(), Object(Enum("test.Asdf".into(), UInt16(4)).into())),
                ],
            },
            0,
        )?;

        assert_eq!(buf, DATA);

        Ok(())
    }
}
