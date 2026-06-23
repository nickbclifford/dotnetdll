use scroll::{Pread, Pwrite, Result};
use scroll_buffer::DynamicBuffer;
use std::borrow::Cow;

use crate::{
    binary::signature::{
        attribute::{self, *},
        compressed::Unsigned,
    },
    dll::{ParseError, ResolveError},
    resolution::Resolution,
};

pub use attribute::{CustomAttributeData, FixedArg, IntegralParam, NamedArg};

use super::{
    members,
    signature::{Parameter, ParameterType},
    types::*,
};

fn parse_error(error: ParseError) -> scroll::Error {
    scroll::Error::Custom(error.to_string())
}

fn resolve_error(error: ResolveError) -> scroll::Error {
    scroll::Error::Custom(error.to_string())
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
                None => {
                    dll_bail!(parse_error(ParseError::BadStructure(
                        "invalid UTF-32 character in custom attribute",
                    )));
                }
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
            None => {
                dll_bail!(parse_error(ParseError::BadStructure(
                    "invalid null type name in custom attribute",
                )));
            }
        },
        Object => FixedArg::Object(Box::new(parse_from_type(src.gread(offset)?, src, offset, resolve)?)),
        Vector(t) => {
            let num_elem: u32 = src.gread_with(offset, scroll::LE)?;
            FixedArg::Array(
                *t.clone(),
                if num_elem == u32::MAX {
                    None
                } else {
                    Some(
                        (0..num_elem)
                            .map(|_| parse_from_type(*t.clone(), src, offset, resolve))
                            .collect::<Result<_>>()?,
                    )
                },
            )
        }
        Enum(name) => {
            let t = process_def(resolve(&name)?)?;
            match parse_from_type(t, src, offset, resolve)? {
                FixedArg::Enum(name, i) => FixedArg::Enum(name, i),
                _ => {
                    dll_bail!(parse_error(ParseError::BadStructure(
                        "bad enum value in custom attribute",
                    )));
                }
            }
        }
    })
}

fn process_def<'def, 'inst>(
    (def, res): (&'def TypeDefinition<'def>, &'def Resolution<'def>),
) -> Result<FieldOrPropType<'inst>> {
    let Some(supertype) = &def.extends else {
        return Ok(FieldOrPropType::Object);
    };

    match supertype {
        TypeSource::User(u) if u.type_name(res) == "System.Enum" => {
            let value_field = def.fields.iter().find(|f| f.name == "value__").ok_or_else(|| {
                parse_error(ParseError::BadStructure(
                    "cannot find underlying enum field for custom attribute",
                ))
            })?;

            match &value_field.return_type {
                MemberType::Base(b) => match &**b {
                    BaseType::Int8 => Ok(FieldOrPropType::Int8),
                    BaseType::UInt8 => Ok(FieldOrPropType::UInt8),
                    BaseType::Int16 => Ok(FieldOrPropType::Int16),
                    BaseType::UInt16 => Ok(FieldOrPropType::UInt16),
                    BaseType::Int32 => Ok(FieldOrPropType::Int32),
                    BaseType::UInt32 => Ok(FieldOrPropType::UInt32),
                    BaseType::Int64 => Ok(FieldOrPropType::Int64),
                    BaseType::UInt64 => Ok(FieldOrPropType::UInt64),
                    _ => Err(parse_error(ParseError::BadStructure(
                        "invalid enum underlying type in custom attribute",
                    ))),
                },
                MemberType::TypeGeneric(_) => Err(parse_error(ParseError::BadStructure(
                    "invalid generic enum underlying type in custom attribute",
                ))),
            }
        }
        _ => Err(parse_error(ParseError::BadStructure(
            "custom attribute enum type must extend System.Enum",
        ))),
    }
}

fn method_to_type<'def, 'inst>(
    m: &'def MethodType,
    resolution: &Resolution<'def>,
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
                        dll_bail!(parse_error(ParseError::BadStructure(
                            "bad type in custom attribute constructor",
                        )));
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
                _ => {
                    dll_bail!(parse_error(ParseError::BadStructure(
                        "bad type in custom attribute constructor",
                    )));
                }
            };

            Ok(t)
        }
        MethodType::TypeGeneric(_) => Err(parse_error(ParseError::BadStructure(
            "type generic parameters are not allowed in custom attributes",
        ))),
        MethodType::MethodGeneric(_) => Err(parse_error(ParseError::BadStructure(
            "method generic parameters are not allowed in custom attributes",
        ))),
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
            let name = src.gread::<SerString>(offset)?.0.ok_or_else(|| {
                parse_error(ParseError::BadStructure(
                    "null string name in custom attribute named argument",
                ))
            })?;

            let value = parse_from_type(f_type, src, offset, resolve)?;

            Ok(match kind {
                0x53 => NamedArg::Field(name, value),
                0x54 => NamedArg::Property(name, value),
                bad => {
                    dll_bail!(parse_error(ParseError::BadSignatureKind {
                        tag: bad,
                        context: "custom attribute named argument",
                    }));
                }
            })
        })
        .collect()
}

/// A custom attribute, which can be applied to many metadata elements.
///
/// See ECMA-335, II.22.10 (page 218) for more information.
///
/// The attribute value blob decodes into
/// [`crate::binary::signature::attribute::CustomAttributeData`].
#[derive(Debug, Clone)]
pub struct Attribute<'a> {
    /// The constructor method used to create this attribute.
    pub constructor: members::UserMethod,
    pub(crate) value: Option<Cow<'a, [u8]>>,
}

impl<'def, 'inst> Attribute<'inst> {
    /// Decodes the binary blob of the custom attribute into structured [`CustomAttributeData`].
    ///
    /// This requires a [`Resolver`] to find the types of enum values and named arguments.
    ///
    /// # Errors
    ///
    /// Returns an error when attribute blob data is missing/malformed or when a
    /// referenced enum/type name cannot be resolved through `resolver`.
    pub fn instantiation_data(
        &'inst self,
        resolver: &impl Resolver<'def>,
        resolution: &Resolution<'def>,
    ) -> Result<CustomAttributeData<'inst>> {
        let bytes = self
            .value
            .as_ref()
            .ok_or_else(|| parse_error(ParseError::BadStructure("null data for custom attribute")))?;

        let offset = &mut 0;

        let prolog: u16 = bytes.gread_with(offset, scroll::LE)?;
        if prolog != 0x0001 {
            dll_bail!(parse_error(ParseError::BadStructure(
                "bad custom attribute data prolog",
            )));
        }

        use members::UserMethod;

        let sig = match &self.constructor {
            UserMethod::Definition(m) => &resolution[*m].signature,
            UserMethod::Reference(r) => &resolution[*r].signature,
        };

        let resolve = |s: &str| {
            resolver.find_type(s).map_err(|_| {
                resolve_error(ResolveError::LazyLookupFailed(
                    "failed to resolve custom attribute type",
                ))
            })
        };

        let fixed = sig
            .parameters
            .iter()
            .map(|Parameter(_, param)| match param {
                ParameterType::Value(p_type) => {
                    parse_from_type(method_to_type(p_type, resolution, &resolve)?, bytes, offset, &resolve)
                }
                ParameterType::Ref(_) => Err(parse_error(ParseError::BadStructure(
                    "ref parameters are not allowed in custom attributes",
                ))),
                ParameterType::TypedReference => Err(parse_error(ParseError::BadStructure(
                    "TypedReference parameters are not allowed in custom attributes",
                ))),
            })
            .collect::<Result<_>>()?;

        let named = parse_named(bytes, offset, &resolve)?;

        Ok(CustomAttributeData {
            constructor_args: fixed,
            named_args: named,
        })
    }

    /// Creates a custom attribute from already-resolved constructor data.
    ///
    /// # Panics
    ///
    /// Panics only if serializing `data` into the crate's growable in-memory
    /// buffer fails. This is an internal invariant: `CustomAttributeData`'s
    /// writer currently has no semantic error paths, and the destination buffer
    /// expands as needed.
    pub fn new(constructor: members::UserMethod, data: CustomAttributeData<'inst>) -> Self {
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

/// Declarative security metadata attached to a type, method, or assembly.
///
/// This is dotnetdll's semantic view of a declarative security annotation: a security action
/// code plus a serialized permission set (`.permission` / `.permissionset` in ILAsm).
/// For named action values, see the `DeclarativeSecurityAction` enum documented at
/// <https://learn.microsoft.com/dotnet/api/system.reflection.declarativesecurityaction>.
///
/// Use [`Self::requested_permissions`] to decode the serialized permission set into
/// [`Permission`] values. For the physical metadata/blob encodings, see the `DeclSecurity`
/// table and custom-attribute named-argument format (`ECMA-335, II.22.11` and
/// `ECMA-335, II.23.3`).
#[derive(Debug, Clone)]
pub struct SecurityDeclaration<'a> {
    /// Custom attributes attached directly to the `DeclSecurity` row.
    pub attributes: Vec<Attribute<'a>>,
    /// `DeclSecurity::Action`, as the raw 2-byte security action code.
    ///
    /// For named action values, see
    /// <https://learn.microsoft.com/dotnet/api/system.reflection.declarativesecurityaction>
    /// (for example, `Demand = 2`, `Assert = 3`).
    pub action: u16,
    pub(crate) value: Cow<'a, [u8]>,
}

/// One decoded permission entry from a [`SecurityDeclaration`].
///
/// Each value corresponds to one permission item inside the declaration's serialized
/// `PermissionSet` blob.
#[derive(Debug, Clone)]
pub struct Permission<'a> {
    /// Fully qualified type name of the permission/attribute class.
    pub type_name: Cow<'a, str>,
    /// Named arguments (fields or properties) assigned on that permission entry.
    pub fields: Vec<NamedArg<'a>>,
}

impl<'a> SecurityDeclaration<'a> {
    /// Decodes the declaration's serialized `PermissionSet` blob.
    ///
    /// The decoded output is a list of [`Permission`] values in metadata order.
    ///
    /// # Errors
    ///
    /// Returns an error when the permission-set blob is malformed or when a
    /// referenced permission type cannot be resolved through `resolver`.
    pub fn requested_permissions(&'a self, resolver: &'a impl Resolver<'a>) -> Result<Vec<Permission<'a>>> {
        let offset = &mut 0;

        let value = self.value.as_ref();

        let period: u8 = value.gread_with(offset, scroll::LE)?;
        if period != b'.' {
            dll_bail!(parse_error(ParseError::BadStructure(
                "bad security permission set sentinel",
            )));
        }

        let Unsigned(num_attributes) = value.gread(offset)?;

        (0..num_attributes)
            .map(|_| {
                let type_name = value
                    .gread::<SerString>(offset)?
                    .0
                    .ok_or_else(|| {
                        parse_error(ParseError::BadStructure(
                            "null attribute type name in security declaration",
                        ))
                    })?
                    .into();

                let fields = parse_named(value, offset, &|s| {
                    resolver.find_type(s).map_err(|_| {
                        resolve_error(ResolveError::LazyLookupFailed(
                            "failed to resolve security declaration type",
                        ))
                    })
                })?;

                Ok(Permission { type_name, fields })
            })
            .collect()
    }

    /// Builds a new declarative security payload from decoded permissions.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload cannot be encoded into the serialized
    /// `PermissionSet` blob format.
    pub fn new(attributes: Vec<Attribute<'a>>, action: u16, attrs: Vec<Permission<'a>>) -> Result<Self> {
        let mut buffer = DynamicBuffer::with_increment(8);
        let offset = &mut 0;

        buffer.gwrite_with(b'.', offset, scroll::LE)?;
        buffer.gwrite(Unsigned(attrs.len() as u32), offset)?;

        for attr in attrs {
            buffer.gwrite(SerString(Some(attr.type_name.clone())), offset)?;
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
