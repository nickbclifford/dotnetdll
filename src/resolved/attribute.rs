use scroll::{Pread, Pwrite, Result};
use scroll_buffer::DynamicBuffer;
use std::borrow::Cow;

use crate::binary::signature::{
    attribute::{self, *},
    compressed::Unsigned,
};
use crate::resolution::Resolution;

pub use attribute::{CustomAttributeData, FixedArg, IntegralParam, NamedArg};

use super::{
    members,
    signature::{Parameter, ParameterType},
    types::*,
};

macro_rules! throw {
    ($($arg:tt)*) => {
        return Err(scroll::Error::Custom(format!($($arg)*)))
    }
}

fn parse_from_type<'def, 'inst>(
    f_type: FieldOrPropType<'inst>,
    src: &'inst [u8],
    offset: &mut usize,
    resolve: &impl Fn(&str) -> Result<(&'def TypeDefinition<'def>, &'def Resolution<'def>)>,
) -> Result<FixedArg<'inst>> {
    use FieldOrPropType::*;
    Ok(match f_type {
        Boolean => FixedArg::Boolean(src.gread_with::<u8>(offset, scroll::LE)? == 1),
        Char => {
            let value = src.gread_with::<u16>(offset, scroll::LE)? as u32;
            match char::from_u32(value) {
                Some(c) => FixedArg::Char(c),
                None => throw!("invalid UTF-32 character {:#06x}", value),
            }
        }
        Int8 => FixedArg::Integral(IntegralParam::Int8(src.gread_with(offset, scroll::LE)?)),
        UInt8 => FixedArg::Integral(IntegralParam::UInt8(src.gread_with(offset, scroll::LE)?)),
        Int16 => FixedArg::Integral(IntegralParam::Int16(src.gread_with(offset, scroll::LE)?)),
        UInt16 => FixedArg::Integral(IntegralParam::UInt16(src.gread_with(offset, scroll::LE)?)),
        Int32 => FixedArg::Integral(IntegralParam::Int32(src.gread_with(offset, scroll::LE)?)),
        UInt32 => FixedArg::Integral(IntegralParam::UInt32(src.gread_with(offset, scroll::LE)?)),
        Int64 => FixedArg::Integral(IntegralParam::Int64(src.gread_with(offset, scroll::LE)?)),
        UInt64 => FixedArg::Integral(IntegralParam::UInt64(src.gread_with(offset, scroll::LE)?)),
        Float32 => FixedArg::Float32(src.gread_with(offset, scroll::LE)?),
        Float64 => FixedArg::Float64(src.gread_with(offset, scroll::LE)?),
        String => FixedArg::String(src.gread::<SerString>(offset)?.0),
        Type => match src.gread::<SerString>(offset)?.0 {
            Some(s) => FixedArg::Type(s),
            None => throw!("invalid null type name"),
        },
        Object => FixedArg::Object(Box::new(parse_from_type(src.gread(offset)?, src, offset, resolve)?)),
        Vector(t) => {
            let num_elem: u32 = src.gread_with(offset, scroll::LE)?;
            FixedArg::Array(if num_elem == u32::MAX {
                None
            } else {
                Some(
                    (0..num_elem)
                        .map(|_| parse_from_type(*t.clone(), src, offset, resolve))
                        .collect::<Result<_>>()?,
                )
            })
        }
        Enum(name) => {
            let t = process_def(resolve(name)?)?;
            match parse_from_type(t, src, offset, resolve)? {
                FixedArg::Integral(i) => FixedArg::Enum(name, i),
                bad => throw!("bad value {:?} for enum {}", bad, name),
            }
        }
    })
}

fn process_def<'def, 'inst>(
    (def, res): (&'def TypeDefinition<'def>, &'def Resolution<'def>),
) -> Result<FieldOrPropType<'inst>> {
    let Some(supertype) = &def.extends else { return Ok(FieldOrPropType::Object) };
    match supertype {
        TypeSource::User(u) if u.type_name(res) == "System.Enum" => def
            .fields
            .iter()
            .find(|f| f.name == "value__")
            .ok_or(format!("cannot find underlying type for enum {}", def.type_name()))
            .and_then(|f| match &f.return_type {
                MemberType::Base(b) => match &**b {
                    BaseType::Int8 => Ok(FieldOrPropType::Int8),
                    BaseType::UInt8 => Ok(FieldOrPropType::UInt8),
                    BaseType::Int16 => Ok(FieldOrPropType::Int16),
                    BaseType::UInt16 => Ok(FieldOrPropType::UInt16),
                    BaseType::Int32 => Ok(FieldOrPropType::Int32),
                    BaseType::UInt32 => Ok(FieldOrPropType::UInt32),
                    BaseType::Int64 => Ok(FieldOrPropType::Int64),
                    BaseType::UInt64 => Ok(FieldOrPropType::UInt64),
                    bad => Err(format!("invalid type {:?} in enum", bad)),
                },
                MemberType::TypeGeneric(_) => Err("invalid generic type in enum".to_string()),
            }),
        bad => Err(format!(
            "type {} must extend System.Enum for custom attributes, not {:?}",
            def.type_name(),
            bad
        )),
    }
    .map_err(scroll::Error::Custom)
}

fn method_to_type<'def, 'inst>(
    m: &'def MethodType,
    resolution: &'def Resolution<'def>,
    resolve: &impl Fn(&str) -> Result<(&'def TypeDefinition<'def>, &'def Resolution<'def>)>,
) -> Result<FieldOrPropType<'inst>> {
    match m {
        MethodType::Base(b) => {
            use BaseType::*;
            let t = match &**b {
                Type { source: ts, .. } => match ts {
                    TypeSource::User(t) => {
                        let name = t.type_name(resolution);
                        if name == "System.Type" {
                            FieldOrPropType::Type
                        } else {
                            process_def(resolve(&name)?)?
                        }
                    }
                    TypeSource::Generic { .. } => {
                        throw!("bad type {:?} in custom attribute constructor", ts)
                    }
                },
                Boolean => FieldOrPropType::Boolean,
                Char => FieldOrPropType::Char,
                Int8 => FieldOrPropType::Int8,
                UInt8 => FieldOrPropType::UInt8,
                Int16 => FieldOrPropType::Int16,
                UInt16 => FieldOrPropType::UInt16,
                Int32 => FieldOrPropType::Int32,
                UInt32 => FieldOrPropType::UInt32,
                Int64 => FieldOrPropType::Int64,
                UInt64 => FieldOrPropType::UInt64,
                Float32 => FieldOrPropType::Float32,
                Float64 => FieldOrPropType::Float64,
                String => FieldOrPropType::String,
                Object => FieldOrPropType::Object,
                Vector(_, v) => FieldOrPropType::Vector(Box::new(method_to_type(v, resolution, resolve)?)),
                bad => throw!("bad type {:?} in custom attribute constructor", bad),
            };

            Ok(t)
        }
        MethodType::TypeGeneric(_) => {
            throw!("type generic parameters are not allowed in custom attributes")
        }
        MethodType::MethodGeneric(_) => {
            throw!("method generic parameters are not allowed in custom attributes")
        }
    }
}

fn parse_named<'def, 'inst>(
    src: &'inst [u8],
    offset: &mut usize,
    resolve: &impl Fn(&str) -> Result<(&'def TypeDefinition<'def>, &'def Resolution<'def>)>,
) -> Result<Vec<NamedArg<'inst>>> {
    let num_named: u16 = src.gread_with(offset, scroll::LE)?;

    (0..num_named)
        .map(|_| {
            let kind: u8 = src.gread_with(offset, scroll::LE)?;
            let f_type: FieldOrPropType = src.gread(offset)?;
            let name = src
                .gread::<SerString>(offset)?
                .0
                .ok_or_else(|| scroll::Error::Custom("null string name found when parsing".to_string()))?;

            let value = parse_from_type(f_type, src, offset, resolve)?;

            Ok(match kind {
                0x53 => NamedArg::Field(name, value),
                0x54 => NamedArg::Property(name, value),
                bad => throw!("bad named argument tag {:#04x}", bad),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Attribute<'a> {
    pub constructor: members::UserMethod,
    pub(crate) value: Option<Cow<'a, [u8]>>,
}

impl<'a> Attribute<'a> {
    pub fn instantiation_data(
        &'a self,
        resolver: &'a impl Resolver<'a>,
        resolution: &'a Resolution<'a>,
    ) -> Result<CustomAttributeData<'a>> {
        let bytes = self
            .value
            .as_ref()
            .ok_or_else(|| scroll::Error::Custom("null data for custom attribute".to_string()))?;

        let offset = &mut 0;

        let prolog: u16 = bytes.gread_with(offset, scroll::LE)?;
        if prolog != 0x0001 {
            throw!("bad custom attribute data prolog {:#06x}", prolog);
        }

        use members::UserMethod;

        let sig = match &self.constructor {
            UserMethod::Definition(m) => &resolution[*m].signature,
            UserMethod::Reference(r) => &resolution[*r].signature,
        };

        let resolve = |s: &str| resolver.find_type(s).map_err(|e| scroll::Error::Custom(e.to_string()));

        let fixed = sig
            .parameters
            .iter()
            .map(|Parameter(_, param)| match param {
                ParameterType::Value(p_type) => {
                    parse_from_type(method_to_type(p_type, resolution, &resolve)?, bytes, offset, &resolve)
                }
                ParameterType::Ref(_) => {
                    throw!("ref parameters are not allowed in custom attributes")
                }
                ParameterType::TypedReference => {
                    throw!("TypedReference parameters are not allowed in custom attributes",)
                }
            })
            .collect::<Result<_>>()?;

        let named = parse_named(bytes, offset, &resolve)?;

        Ok(CustomAttributeData {
            constructor_args: fixed,
            named_args: named,
        })
    }

    pub fn new(constructor: members::UserMethod, data: CustomAttributeData<'a>) -> Self {
        let mut buffer = DynamicBuffer::with_increment(8);

        // currently, there are no explicit throws in attribute data TryIntoCtx impls
        // so since the buffer always expands, this should be infallible
        buffer.pwrite(data, 0).unwrap();

        Attribute {
            constructor,
            value: Some(buffer.into_vec().into()),
        }
    }
}

// we abstract away all the StandAloneSigs and TypeSpecs, so there's no good place to put attributes that belong to them
// it's not really possible to use those unless you're writing raw metadata though so we'll ignore them (for now)

#[derive(Debug, Clone)]
pub struct SecurityDeclaration<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub action: u16,
    pub(crate) value: Cow<'a, [u8]>,
}

#[derive(Debug, Clone)]
pub struct Permission<'a> {
    pub type_name: Cow<'a, str>,
    pub fields: Vec<NamedArg<'a>>,
}

impl<'a> SecurityDeclaration<'a> {
    pub fn requested_permissions(
        &'a self,
        resolver: &'a impl Resolver<'a>,
    ) -> Result<Vec<Permission<'a>>> {
        let offset = &mut 0;

        let value = self.value.as_ref();

        let period: u8 = value.gread_with(offset, scroll::LE)?;
        if period != b'.' {
            throw!("bad security permission set sentinel {:#04x}", period);
        }

        let Unsigned(num_attributes) = value.gread(offset)?;

        (0..num_attributes)
            .map(|_| {
                let type_name = value
                    .gread::<SerString>(offset)?
                    .0
                    .ok_or_else(|| {
                        scroll::Error::Custom("null attribute type name found when parsing security".to_string())
                    })?
                    .into();

                let fields = parse_named(value, offset, &|s| {
                    resolver.find_type(s).map_err(|e| scroll::Error::Custom(e.to_string()))
                })?;

                Ok(Permission { type_name, fields })
            })
            .collect()
    }

    pub fn new(attributes: Vec<Attribute<'a>>, action: u16, attrs: Vec<Permission<'a>>) -> Result<Self> {
        let mut buffer = DynamicBuffer::with_increment(8);
        let offset = &mut 0;

        buffer.gwrite_with(b'.', offset, scroll::LE)?;
        buffer.gwrite(Unsigned(attrs.len() as u32), offset)?;

        for attr in attrs {
            buffer.gwrite(SerString(Some(&attr.type_name)), offset)?;
            for arg in attr.fields {
                buffer.gwrite(arg, offset)?;
            }
        }

        Ok(SecurityDeclaration {
            attributes,
            action,
            value: buffer.into_vec().into(),
        })
    }
}
