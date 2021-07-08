use super::{
    members,
    signature::{Parameter, ParameterType},
    types::*,
};
use crate::{binary::signature::{attribute::*, compressed::Unsigned}, dll::Resolution};
use scroll::{Pread, Result};

fn parse_from_type<'def, 'inst>(
    f_type: FieldOrPropType<'inst>,
    src: &'inst [u8],
    offset: &mut usize,
    resolution: &'def Resolution<'def>,
    resolve: &impl Fn(&str) -> Result<(&'def TypeDefinition<'def>, &'def Resolution<'def>)>,
) -> Result<FixedArg<'inst>> {
    use FieldOrPropType::*;
    Ok(match f_type {
        Boolean => FixedArg::Boolean(src.gread_with::<u8>(offset, scroll::LE)? == 1),
        Char => FixedArg::Char(
            char::from_u32(src.gread_with::<u16>(offset, scroll::LE)? as u32)
                .ok_or(scroll::Error::Custom("invalid character".to_string()))?,
        ),
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
        Type => FixedArg::Type(
            src.gread::<SerString>(offset)?
                .0
                .ok_or(scroll::Error::Custom("invalid null type name".to_string()))?,
        ),
        Object => FixedArg::Object(Box::new(parse_from_type(
            src.gread(offset)?,
            src,
            offset,
            resolution,
            resolve,
        )?)),
        Vector(t) => {
            let num_elem: u32 = src.gread_with(offset, scroll::LE)?;
            FixedArg::Array(if num_elem == u32::MAX {
                None
            } else {
                let mut elems = Vec::with_capacity(num_elem as usize);
                for _ in 0..num_elem {
                    elems.push(parse_from_type(*t.clone(), src, offset, resolution, resolve)?);
                }
                Some(elems)
            })
        }
        Enum(name) => {
            let t = process_def(resolve(name)?)?;
            match parse_from_type(t, src, offset, resolution, resolve)? {
                FixedArg::Integral(i) => FixedArg::Enum(name, i),
                bad => {
                    return Err(scroll::Error::Custom(format!(
                        "bad value {:?} for enum {}",
                        bad, name
                    )))
                }
            }
        }
    })
}

fn process_def<'def, 'inst>((def, res): (&'def TypeDefinition<'def>, &'def Resolution<'def>)) -> Result<FieldOrPropType<'inst>> {
    let supertype = match &def.extends {
        Some(t) => t,
        None => return Ok(FieldOrPropType::Object),
    };
    match supertype {
        TypeSource::User(u) if u.type_name(res) == "System.Enum" => def
            .fields
            .iter()
            .find(|f| f.name == "value__")
            .ok_or(format!(
                "cannot find underlying type for enum {}",
                def.type_name()
            ))
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
    return match m {
        MethodType::Base(b) => {
            use BaseType::*;
            let t = match &**b {
                Type(ts) => match ts {
                    TypeSource::User(t) => {
                        let name = t.type_name(resolution);
                        if name == "System.Type" {
                            FieldOrPropType::Type
                        } else {
                            process_def(resolve(&name)?)?
                        }
                    }
                    TypeSource::Generic(g) => {
                        return Err(scroll::Error::Custom(format!(
                            "bad type {:?} in custom attribute constructor",
                            g
                        )))
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
                Vector(_, ref v) => FieldOrPropType::Vector(Box::new(method_to_type(v, resolution, resolve)?)),
                bad => {
                    return Err(scroll::Error::Custom(format!(
                        "bad type {:?} in custom attribute constructor",
                        bad
                    )))
                }
            };

            Ok(t)
        }
        MethodType::TypeGeneric(_) => Err(scroll::Error::Custom(
            "type generic parameters are not allowed in custom attributes".to_string(),
        )),
        MethodType::MethodGeneric(_) => Err(scroll::Error::Custom(
            "method generic parameters are not allowed in custom attributes".to_string(),
        )),
    };
}

fn parse_named<'def, 'inst>(
    src: &'inst [u8],
    offset: &mut usize,
    resolution: &'def Resolution<'def>,
    resolve: &impl Fn(&str) -> Result<(&'def TypeDefinition<'def>, &'def Resolution<'def>)>,
) -> Result<Vec<NamedArg<'inst>>> {
    let num_named: u16 = src.gread_with(offset, scroll::LE)?;
    let mut named = Vec::with_capacity(num_named as usize);

    for _ in 0..num_named {
        let kind: u8 = src.gread_with(offset, scroll::LE)?;
        let f_type: FieldOrPropType = src.gread(offset)?;
        let name = src
            .gread::<SerString>(offset)?
            .0
            .ok_or(scroll::Error::Custom(
                "null string name found when parsing".to_string(),
            ))?;

        let value = parse_from_type(f_type, src, offset, resolution, resolve)?;

        named.push(match kind {
            0x53 => NamedArg::Field(name, value),
            0x54 => NamedArg::Property(name, value),
            bad => {
                return Err(scroll::Error::Custom(format!(
                    "bad named argument tag {:#04x}",
                    bad
                )))
            }
        })
    }

    Ok(named)
}

#[derive(Debug, Clone)]
pub struct Attribute<'a> {
    pub constructor: members::UserMethod<'a>,
    value: Option<&'a [u8]>,
}

impl<'a> Attribute<'a> {
    pub fn instantiation_data(&self, resolver: &impl Resolver, resolution: &Resolution) -> Result<CustomAttributeData<'a>> {
        let bytes = self.value.ok_or(scroll::Error::Custom(
            "null data for custom attribute".to_string(),
        ))?;

        let offset = &mut 0;

        let prolog: u16 = bytes.gread_with(offset, scroll::LE)?;
        if prolog != 0x0001 {
            return Err(scroll::Error::Custom(format!(
                "bad custom attribute data prolog {:#06x}",
                prolog
            )));
        }

        let sig = self.constructor.signature(resolution);

        let mut fixed = Vec::with_capacity(sig.parameters.len());

        let resolve = |s: &str| {
            resolver
                .find_type(s)
                .map_err(|e| scroll::Error::Custom(e.to_string()))
        };

        for Parameter(_, param) in sig.parameters.iter() {
            match param {
                ParameterType::Value(p_type) => {
                    fixed.push(parse_from_type(
                        method_to_type(p_type, resolution, &resolve)?,
                        bytes,
                        offset,
                        resolution,
                        &resolve,
                    )?);
                }
                ParameterType::Ref(_) => {
                    return Err(scroll::Error::Custom(
                        "ref parameters are not allowed in custom attributes".to_string(),
                    ))
                }
                ParameterType::TypedReference => {
                    return Err(scroll::Error::Custom(
                        "TypedReference parameters are not allowed in custom attributes"
                            .to_string(),
                    ))
                }
            }
        }

        let named = parse_named(bytes, offset,resolution, &resolve)?;

        Ok(CustomAttributeData {
            constructor_args: fixed,
            named_args: named,
        })
    }
}

// we abstract away all the StandAloneSigs and TypeSpecs, so there's no good place to put attributes that belong to them
// it's not really possible to use those unless you're writing raw metadata though so we'll ignore them

#[derive(Debug)]
pub struct SecurityDeclaration<'a> {
    pub attributes: Vec<Attribute<'a>>,
    pub action: u16,
    value: &'a [u8],
}

#[derive(Debug)]
pub struct SecurityAttributeData<'a> {
    pub type_name: &'a str,
    pub fields: Vec<NamedArg<'a>>,
}

impl<'a> SecurityDeclaration<'a> {
    pub fn requested_permissions(
        &self,
        resolution: &Resolution,
        resolver: &impl Resolver,
    ) -> Result<Vec<SecurityAttributeData<'a>>> {
        let offset = &mut 0;

        let period: u8 = self.value.gread_with(offset, scroll::LE)?;
        if period != ('.' as u8) {
            return Err(scroll::Error::Custom(format!(
                "bad security permission set sentinel {:#04x}",
                period
            )));
        }

        let Unsigned(num_attributes) = self.value.gread(offset)?;

        let mut attrs = Vec::with_capacity(num_attributes as usize);

        for _ in 0..num_attributes {
            let type_name =
                self.value
                    .gread::<SerString>(offset)?
                    .0
                    .ok_or(scroll::Error::Custom(
                        "null attribute type name found when parsing security".to_string(),
                    ))?;

            let fields = parse_named(self.value, offset, resolution, &|s| {
                resolver
                    .find_type(s)
                    .map_err(|e| scroll::Error::Custom(e.to_string()))
            })?;

            attrs.push(SecurityAttributeData { type_name, fields })
        }

        Ok(attrs)
    }
}
