use super::{compressed, encoded::*};
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};
use scroll_buffer::DynamicBuffer;

/// Calling convention bits stored in the low 5 bits of a method signature header byte.
///
/// This models the convention discriminator used by [`MethodDefSig`] and [`MethodRefSig`].
/// `Generic` carries the generic parameter count (`GENERIC` case) encoded immediately after
/// the header byte.
///
/// ECMA-335, II.23.2.1.
///
/// Re-exported for the semantic layer as [`crate::resolved::signature::CallingConvention`].
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum CallingConvention {
    /// Default managed calling convention (`0x0`).
    Default,
    /// Vararg calling convention (`0x5`).
    Vararg,
    /// Generic method signature marker (`0x10`) with generic arity.
    Generic(usize),
}

/// Binary method-definition signature (`MethodDefSig`) from the `#Blob` heap.
///
/// A method definition signature contains `HASTHIS`/`EXPLICITTHIS` flags, the
/// [`CallingConvention`], parameter count, return type, and parameter types.
///
/// ECMA-335, II.23.2.1.
#[derive(Debug, Clone)]
pub struct MethodDefSig {
    /// Whether the `HASTHIS` bit is set in the signature header byte.
    pub has_this: bool,
    /// Whether the `EXPLICITTHIS` bit is set in the signature header byte.
    pub explicit_this: bool,
    /// The method calling convention discriminator.
    pub calling_convention: CallingConvention,
    /// Encoded return type.
    pub ret_type: RetType,
    /// Encoded fixed parameter list.
    pub params: Vec<Param>,
}

fn build_method_def(
    from: &[u8],
    build_params: impl FnOnce(u32, &mut usize) -> scroll::Result<Vec<Param>>,
) -> scroll::Result<(MethodDefSig, usize)> {
    let offset = &mut 0;

    let tag: u8 = from.gread_with(offset, scroll::LE)?;

    let has_this = check_bitmask!(tag, 0x20);
    let explicit_this = check_bitmask!(tag, 0x40);

    let kind = match tag & 0x1f {
        0x10 => {
            let compressed::Unsigned(value) = from.gread(offset)?;
            CallingConvention::Generic(value as usize)
        }
        0x5 => CallingConvention::Vararg,
        0x0 => CallingConvention::Default,
        _ => throw!("bad method def kind tag {:#04x}", tag),
    };

    let compressed::Unsigned(param_count) = from.gread(offset)?;

    let ret_type = from.gread(offset)?;

    Ok((
        MethodDefSig {
            has_this,
            explicit_this,
            calling_convention: kind,
            ret_type,
            params: build_params(param_count, offset)?,
        },
        *offset,
    ))
}

macro_rules! write_method_def {
    (|$into:ident, $def:ident, $num_params:ident| $e:expr) => {
        fn write_method_def($into: &mut [u8], $def: MethodDefSig, $num_params: usize) -> scroll::Result<usize> {
            $e
        }
        fn write_method_def_dyn($into: &mut DynamicBuffer, $def: MethodDefSig, $num_params: usize) -> scroll::Result<usize> {
            $e
        }
    }
}

write_method_def!(|into, def, num_params| {
    let offset = &mut 0;

    use CallingConvention::*;

    let mut tag: u8 = match def.calling_convention {
        Default => 0x0,
        Vararg => 0x5,
        Generic(_) => 0x10,
    };
    if def.has_this {
        tag |= 0x20;
    }
    if def.explicit_this {
        tag |= 0x40;
    }

    into.gwrite_with(tag, offset, scroll::LE)?;

    if let Generic(n) = def.calling_convention {
        into.gwrite(compressed::Unsigned(n as u32), offset)?;
    }

    into.gwrite(compressed::Unsigned(num_params as u32), offset)?;

    into.gwrite(def.ret_type, offset)?;

    for p in def.params {
        into.gwrite(p, offset)?;
    }

    Ok(*offset)
});

impl TryFromCtx<'_> for MethodDefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        build_method_def(from, |len, offset| {
            let mut params = Vec::with_capacity(len as usize);
            for _ in 0..len {
                params.push(from.gread(offset)?);
            }
            Ok(params)
        })
    }
}
impl TryIntoCtx for MethodDefSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], (): ()) -> Result<usize, Self::Error> {
        let len = self.params.len();
        write_method_def(into, self, len)
    }
}
impl TryIntoCtx<(), DynamicBuffer> for MethodDefSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let len = self.params.len();
        write_method_def_dyn(into, self, len)
    }
}

fn build_params_with_varargs(len: &mut u32, from: &[u8], offset: &mut usize) -> scroll::Result<Vec<Param>> {
    let mut params = Vec::with_capacity(*len as usize);
    while *len > 0 {
        if from[*offset] == ELEMENT_TYPE_SENTINEL {
            *offset += 1;
            break;
        }

        params.push(from.gread(offset)?);
        *len -= 1;
    }
    Ok(params)
}

/// Binary method-reference signature (`MethodRefSig`) from the `#Blob` heap.
///
/// This shares the same fixed-prefix shape as [`MethodDefSig`], but for vararg calls it may
/// include additional parameters after an `ELEMENT_TYPE_SENTINEL` marker.
///
/// ECMA-335, II.23.2.2.
#[derive(Debug, Clone)]
pub struct MethodRefSig {
    /// Fixed method-signature prefix (`HASTHIS`, convention, return type, and fixed params).
    pub method_def: MethodDefSig,
    /// Optional vararg tail parameters that follow the sentinel marker.
    pub varargs: Vec<Param>,
}

impl TryFromCtx<'_> for MethodRefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let mut remaining_params = 0;
        let (method_def, mut offset) = build_method_def(from, |mut len, offset| {
            let params = build_params_with_varargs(&mut len, from, offset)?;
            remaining_params = len;
            Ok(params)
        })?;

        let mut varargs = Vec::with_capacity(remaining_params as usize);
        for _ in 0..remaining_params {
            varargs.push(from.gread(&mut offset)?);
        }

        Ok((MethodRefSig { method_def, varargs }, offset))
    }
}
macro_rules! ref_sig_impl {
    ($self:ident, $into:ident, $writer:ident) => {{
        let total_len = $self.method_def.params.len() + $self.varargs.len();

        let conv = $self.method_def.calling_convention;

        let offset = &mut $writer($into, $self.method_def, total_len)?;

        if conv == CallingConvention::Vararg {
            $into.gwrite_with(ELEMENT_TYPE_SENTINEL, offset, scroll::LE)?;

            for v in $self.varargs {
                $into.gwrite(v, offset)?;
            }
        }

        Ok(*offset)
    }};
}
impl TryIntoCtx for MethodRefSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], (): ()) -> Result<usize, Self::Error> {
        ref_sig_impl!(self, into, write_method_def)
    }
}
impl TryIntoCtx<(), DynamicBuffer> for MethodRefSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        ref_sig_impl!(self, into, write_method_def_dyn)
    }
}

/// Calling-convention discriminator for standalone method signatures (`calli` signatures).
///
/// Standalone signatures can be managed (`DefaultManaged`, `Vararg`) or unmanaged with an
/// explicit unmanaged convention (`Cdecl`, `Stdcall`, `Thiscall`, `Fastcall`,
/// `DefaultUnmanaged`).
///
/// ECMA-335, II.23.2.3.
///
/// Re-exported for the semantic layer as [`crate::resolved::signature::StandAloneCallingConvention`].
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum StandAloneCallingConvention {
    /// Managed default calling convention.
    DefaultManaged,
    /// Managed vararg calling convention.
    Vararg,
    /// Unmanaged C declaration calling convention.
    Cdecl,
    /// Unmanaged standard call calling convention.
    Stdcall,
    /// Unmanaged thiscall calling convention.
    Thiscall,
    /// Unmanaged fastcall calling convention.
    Fastcall,
    /// Unmanaged calling convention without a more specific subtype.
    DefaultUnmanaged,
}

impl PartialEq<StandAloneCallingConvention> for CallingConvention {
    fn eq(&self, other: &StandAloneCallingConvention) -> bool {
        matches!(
            (self, other),
            (CallingConvention::Default, StandAloneCallingConvention::DefaultManaged)
                | (CallingConvention::Vararg, StandAloneCallingConvention::Vararg)
        )
    }
}
impl PartialEq<CallingConvention> for StandAloneCallingConvention {
    fn eq(&self, other: &CallingConvention) -> bool {
        other.eq(self)
    }
}

/// Binary standalone method signature used by `calli` and method-body locals metadata.
///
/// This encoding includes method-style `HASTHIS`/`EXPLICITTHIS` flags plus a
/// [`StandAloneCallingConvention`] discriminator and optional vararg tail parameters.
///
/// ECMA-335, II.23.2.3.
#[derive(Debug, Clone)]
pub struct StandAloneMethodSig {
    /// Whether the `HASTHIS` bit is set.
    pub has_this: bool,
    /// Whether the `EXPLICITTHIS` bit is set.
    pub explicit_this: bool,
    /// Standalone signature calling convention.
    pub calling_convention: StandAloneCallingConvention,
    /// Encoded return type.
    pub ret_type: RetType,
    /// Fixed parameter list.
    pub params: Vec<Param>,
    /// Optional vararg tail parameters after the sentinel marker.
    pub varargs: Vec<Param>,
}

impl TryFromCtx<'_> for StandAloneMethodSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;

        let has_this = check_bitmask!(tag, 0x20);
        let explicit_this = check_bitmask!(tag, 0x40);

        use StandAloneCallingConvention::*;

        let calling_convention = match tag & 0xf {
            0 => DefaultManaged,
            1 => Cdecl,
            2 => Stdcall,
            3 => Thiscall,
            4 => Fastcall,
            5 => Vararg,
            9 => DefaultUnmanaged,
            bad => throw!("bad standalone method calling convention {:#03x}", bad),
        };

        let compressed::Unsigned(mut param_count) = from.gread(offset)?;

        let ret_type = from.gread(offset)?;

        let params = build_params_with_varargs(&mut param_count, from, offset)?;
        let mut varargs = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            varargs.push(from.gread(offset)?);
        }

        Ok((
            StandAloneMethodSig {
                has_this,
                explicit_this,
                calling_convention,
                ret_type,
                params,
                varargs,
            },
            *offset,
        ))
    }
}
try_into_ctx!(StandAloneMethodSig, |self, into| {
    let offset = &mut 0;

    let mut tag: u8 = 0;
    if self.has_this {
        tag |= 0x20;
    }
    if self.explicit_this {
        tag |= 0x40;
    }
    use StandAloneCallingConvention::*;
    tag |= match self.calling_convention {
        DefaultManaged => 0,
        Cdecl => 1,
        Stdcall => 2,
        Thiscall => 3,
        Fastcall => 4,
        Vararg => 5,
        DefaultUnmanaged => 9,
    };
    into.gwrite_with(tag, offset, scroll::LE)?;

    into.gwrite(
        compressed::Unsigned((self.params.len() + self.varargs.len()) as u32),
        offset,
    )?;

    into.gwrite(self.ret_type, offset)?;

    for p in self.params {
        into.gwrite(p, offset)?;
    }

    if self.calling_convention == Vararg && !self.varargs.is_empty() {
        into.gwrite_with(0x41_u8, offset, scroll::LE)?;
        for v in self.varargs {
            into.gwrite(v, offset)?;
        }
    }

    Ok(*offset)
});

/// Binary field signature (`FieldSig`) from the `#Blob` heap.
///
/// Field signatures begin with the `FIELD` prefix byte (`0x6`), followed by optional custom
/// modifiers and the field type.
///
/// ECMA-335, II.23.2.4.
#[derive(Debug)]
pub struct FieldSig {
    /// Optional required/optional custom modifiers that precede the field type.
    pub custom_modifiers: Vec<CustomMod>,
    // the standard is conflicting on whether or not byref types are allowed in fields
    //   ECMA-335, I.8.2.1.1 (page 20) says they cannot be used for field signatures
    //   ECMA-335, II.14.4.2 (page 171) says they are used in field types
    // however, since C# 11/.NET 7, ref fields are allowed in ref structs
    //   the System.Private.CoreLib implementation for System.TypedReference
    //   uses this feature for its value pointer field
    /// Whether `ELEMENT_TYPE_BYREF` is present before [`Self::field_type`].
    pub by_ref: bool,
    /// Encoded field type.
    pub field_type: Type,
}

impl TryFromCtx<'_> for FieldSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != 0x6 {
            throw!("bad field tag {:#04x}", tag);
        }

        let mods = all_custom_mods(from, offset);

        let by_ref = from[*offset] == ELEMENT_TYPE_BYREF;
        if by_ref {
            *offset += 1;
        }

        Ok((
            FieldSig {
                custom_modifiers: mods,
                by_ref,
                field_type: from.gread(offset)?,
            },
            *offset,
        ))
    }
}
try_into_ctx!(FieldSig, |self, into| {
    let offset = &mut 0;

    into.gwrite_with(0x6_u8, offset, scroll::LE)?;

    for m in self.custom_modifiers {
        into.gwrite(m, offset)?;
    }

    if self.by_ref {
        into.gwrite_with(ELEMENT_TYPE_BYREF, offset, scroll::LE)?;
    }

    into.gwrite(self.field_type, offset)?;

    Ok(*offset)
});

/// Binary property signature (`PropertySig`) from the `#Blob` heap.
///
/// Property signatures start with a property prefix (`0x8`, optionally with `HASTHIS`), then the
/// parameter count, property type, and any indexer parameters.
///
/// ECMA-335, II.23.2.5.
#[derive(Debug)]
pub struct PropertySig {
    /// Whether the property signature has the `HASTHIS` bit set.
    pub has_this: bool,
    /// Encoded property type.
    pub property_type: Param, // properties can have ref valuetypes, which the Param type covers
    /// Optional indexer-style parameters.
    pub params: Vec<Param>,
}

impl TryFromCtx<'_> for PropertySig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag & 0x8 != 0x8 {
            throw!("bad property signature tag {:#04x}", tag);
        }

        let has_this = check_bitmask!(tag, 0x20);

        let compressed::Unsigned(param_count) = from.gread(offset)?;

        let property_type = from.gread(offset)?;

        let mut params = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            params.push(from.gread(offset)?);
        }

        Ok((
            PropertySig {
                has_this,
                property_type,
                params,
            },
            *offset,
        ))
    }
}
try_into_ctx!(PropertySig, |self, into| {
    let offset = &mut 0;

    into.gwrite_with(if self.has_this { 0x28_u8 } else { 0x8_u8 }, offset, scroll::LE)?;

    into.gwrite(compressed::Unsigned(self.params.len() as u32), offset)?;

    // includes mods and type

    into.gwrite(self.property_type, offset)?;

    for p in self.params {
        into.gwrite(p, offset)?;
    }

    Ok(*offset)
});

/// One local variable entry inside a [`LocalVarSig`] blob.
///
/// Locals can be `typedref` (`TypedByRef`) or a regular local with optional custom modifiers,
/// `pinned`, and `byref` prefixes.
///
/// ECMA-335, II.23.2.6.
#[derive(Debug)]
pub enum LocalVar {
    /// A `typedref` local (`ELEMENT_TYPE_TYPEDBYREF`).
    TypedByRef,
    /// A regular local variable entry.
    Variable {
        /// Optional required/optional custom modifiers before the local type.
        custom_modifiers: Vec<CustomMod>,
        /// Whether the local has the `ELEMENT_TYPE_PINNED` prefix.
        pinned: bool,
        /// Whether the local has the `ELEMENT_TYPE_BYREF` prefix.
        by_ref: bool,
        /// Encoded local variable type.
        var_type: Type,
    },
}

/// Binary local-variable signature (`LocalVarSig`) from the `#Blob` heap.
///
/// Local variable signatures begin with the `LOCAL_SIG` prefix byte (`0x7`), then a compressed
/// local count and that many [`LocalVar`] entries.
///
/// ECMA-335, II.23.2.6.
#[derive(Debug)]
pub struct LocalVarSig(
    /// Encoded local variable entries.
    pub Vec<LocalVar>,
);

impl TryFromCtx<'_> for LocalVarSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != 0x7 {
            throw!("bad local var signature tag {:#04x}", tag);
        }

        let compressed::Unsigned(var_count) = from.gread(offset)?;

        let mut vars = Vec::with_capacity(var_count as usize);
        for _ in 0..var_count {
            vars.push(if from[*offset] == ELEMENT_TYPE_TYPEDBYREF {
                *offset += 1;
                LocalVar::TypedByRef
            } else {
                // the syntax diagram for mods and these flags in the spec is very confusing

                let mods = all_custom_mods(from, offset);

                let pinned = from[*offset] == ELEMENT_TYPE_PINNED;
                if pinned {
                    *offset += 1;
                }

                let by_ref = from[*offset] == ELEMENT_TYPE_BYREF;
                if by_ref {
                    *offset += 1;
                }

                LocalVar::Variable {
                    custom_modifiers: mods,
                    pinned,
                    by_ref,
                    var_type: from.gread(offset)?,
                }
            });
        }

        Ok((LocalVarSig(vars), *offset))
    }
}
impl TryIntoCtx<(), DynamicBuffer> for LocalVarSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        // tag
        into.gwrite_with(0x7u8, offset, scroll::LE)?;

        into.gwrite(compressed::Unsigned(self.0.len() as u32), offset)?;

        for var in self.0 {
            match var {
                LocalVar::TypedByRef => {
                    into.gwrite_with(ELEMENT_TYPE_TYPEDBYREF, offset, scroll::LE)?;
                }
                LocalVar::Variable {
                    custom_modifiers,
                    pinned,
                    by_ref,
                    var_type,
                } => {
                    for m in custom_modifiers {
                        into.gwrite(m, offset)?;
                    }

                    if pinned {
                        into.gwrite_with(ELEMENT_TYPE_PINNED, offset, scroll::LE)?;
                    }
                    if by_ref {
                        into.gwrite_with(ELEMENT_TYPE_BYREF, offset, scroll::LE)?;
                    }

                    into.gwrite(var_type, offset)?;
                }
            }
        }

        Ok(*offset)
    }
}

/// Binary method-specification signature (`MethodSpec`) used for generic method instantiation.
///
/// This blob starts with `GENERICINST` (`0x0a`), followed by a compressed argument count and the
/// instantiated generic argument types.
///
/// ECMA-335, II.23.2.15.
#[derive(Debug)]
pub struct MethodSpec(
    /// Generic type arguments supplied to the method instantiation.
    pub Vec<Type>,
);

impl TryFromCtx<'_> for MethodSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != 0x0a {
            throw!("bad method spec tag {:#04x}", tag);
        }

        let compressed::Unsigned(type_count) = from.gread(offset)?;

        let mut types = Vec::with_capacity(type_count as usize);
        for _ in 0..type_count {
            types.push(from.gread(offset)?);
        }

        Ok((MethodSpec(types), *offset))
    }
}
impl TryIntoCtx<(), DynamicBuffer> for MethodSpec {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(0x0a_u8, offset, scroll::LE)?;

        into.gwrite(compressed::Unsigned(self.0.len() as u32), offset)?;
        for t in self.0 {
            into.gwrite(t, offset)?;
        }

        Ok(*offset)
    }
}

/// Field marshal descriptor (`MarshalSpec`) stored in `FieldMarshal.NativeType` blobs.
///
/// This represents the native marshaling descriptor used by interop metadata. The encoding can be
/// a primitive native intrinsic or an array form with optional element/size metadata.
///
/// ECMA-335, II.23.4.
#[derive(Debug, Clone, Copy)]
pub enum MarshalSpec {
    /// A non-array native type.
    Primitive(NativeIntrinsic),
    /// Native array marshaling descriptor.
    Array {
        /// Native intrinsic element type (`None` when omitted / `NATIVE_TYPE_MAX`).
        element_type: Option<NativeIntrinsic>,
        /// 0-based parameter index supplying the element count.
        length_parameter: Option<usize>,
        /// Constant number of additional elements.
        additional_elements: Option<usize>,
    },
}

impl TryFromCtx<'_> for MarshalSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        use MarshalSpec::*;

        if from[*offset] == NATIVE_TYPE_ARRAY {
            *offset += 1;
        } else {
            return Ok((Primitive(from.gread(offset)?), *offset));
        }

        let element_type = if from[*offset] == NATIVE_TYPE_MAX {
            *offset += 1;
            None
        } else {
            Some(from.gread(offset)?)
        };
        let length_parameter = from.gread::<compressed::Unsigned>(offset).ok().map(|u| u.0 as usize);
        let additional_elements = from.gread::<compressed::Unsigned>(offset).ok().map(|u| u.0 as usize);

        Ok((
            Array {
                element_type,
                length_parameter,
                additional_elements,
            },
            *offset,
        ))
    }
}
try_into_ctx!(MarshalSpec, |self, into| {
    let offset = &mut 0;

    match self {
        MarshalSpec::Primitive(n) => {
            into.gwrite(n, offset)?;
        }
        MarshalSpec::Array {
            element_type,
            length_parameter,
            additional_elements,
        } => {
            match element_type {
                Some(t) => into.gwrite(t, offset)?,
                None => into.gwrite_with(NATIVE_TYPE_MAX, offset, scroll::LE)?,
            };

            if additional_elements.is_some() && length_parameter.is_none() {
                throw!("length parameter must be specified if additional elements is specified");
            }

            if let Some(p) = length_parameter {
                into.gwrite(compressed::Unsigned(p as u32), offset)?;
            }

            if let Some(n) = additional_elements {
                into.gwrite(compressed::Unsigned(n as u32), offset)?;
            }
        }
    }

    Ok(*offset)
});
