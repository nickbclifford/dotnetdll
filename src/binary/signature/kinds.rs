use super::{compressed, encoded::*};
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};
use scroll_buffer::DynamicBuffer;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum CallingConvention {
    Default,
    Vararg,
    Generic(usize),
}

#[derive(Debug, Clone)]
pub struct MethodDefSig {
    pub has_this: bool,
    pub explicit_this: bool,
    pub calling_convention: CallingConvention,
    pub ret_type: RetType,
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

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        build_method_def(from, |len, offset| {
            (0..len)
                .map(|_| from.gread(offset))
                .collect::<Result<_, _>>()
        })
    }
}
impl TryIntoCtx for MethodDefSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let len = self.params.len();
        write_method_def(into, self, len)
    }
}
impl TryIntoCtx<(), DynamicBuffer> for MethodDefSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, _: ()) -> Result<usize, Self::Error> {
        let len = self.params.len();
        write_method_def_dyn(into, self, len)
    }
}

fn build_params_with_varargs(
    len: &mut u32,
    from: &[u8],
    offset: &mut usize,
) -> scroll::Result<Vec<Param>> {
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

#[derive(Debug, Clone)]
pub struct MethodRefSig {
    pub method_def: MethodDefSig,
    pub varargs: Vec<Param>,
}

impl TryFromCtx<'_> for MethodRefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let mut remaining_params = 0;
        let (method_def, mut offset) = build_method_def(from, |mut len, offset| {
            let params = build_params_with_varargs(&mut len, from, offset)?;
            remaining_params = len;
            Ok(params)
        })?;

        let varargs = (0..remaining_params)
            .map(|_| from.gread(&mut offset))
            .collect::<Result<_, _>>()?;

        Ok((
            MethodRefSig {
                method_def,
                varargs,
            },
            offset,
        ))
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

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        ref_sig_impl!(self, into, write_method_def)
    }
}
impl TryIntoCtx<(), DynamicBuffer> for MethodRefSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, _: ()) -> Result<usize, Self::Error> {
        ref_sig_impl!(self, into, write_method_def_dyn)
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum StandAloneCallingConvention {
    DefaultManaged,
    Vararg,
    Cdecl,
    Stdcall,
    Thiscall,
    Fastcall,
    DefaultUnmanaged,
}

#[derive(Debug, Clone)]
pub struct StandAloneMethodSig {
    pub has_this: bool,
    pub explicit_this: bool,
    pub calling_convention: StandAloneCallingConvention,
    pub ret_type: RetType,
    pub params: Vec<Param>,
    pub varargs: Vec<Param>,
}

impl TryFromCtx<'_> for StandAloneMethodSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
        let varargs = (0..param_count)
            .map(|_| from.gread(offset))
            .collect::<Result<_, _>>()?;

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

#[derive(Debug)]
pub struct FieldSig(pub Vec<CustomMod>, pub Type);

impl TryFromCtx<'_> for FieldSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != 0x6 {
            throw!("bad field tag {:#04x}", tag);
        }

        let mods = all_custom_mods(from, offset);

        Ok((FieldSig(mods, from.gread(offset)?), *offset))
    }
}
try_into_ctx!(FieldSig, |self, into| {
    let offset = &mut 0;

    into.gwrite_with(0x6_u8, offset, scroll::LE)?;

    for m in self.0 {
        into.gwrite(m, offset)?;
    }

    into.gwrite(self.1, offset)?;

    Ok(*offset)
});

#[derive(Debug)]
pub struct PropertySig {
    pub has_this: bool,
    pub property_type: Param, // properties can have ref valuetypes, which the Param type covers
    pub params: Vec<Param>,
}

impl TryFromCtx<'_> for PropertySig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag & 0x8 != 0x8 {
            throw!("bad property signature tag {:#04x}", tag);
        }

        let has_this = check_bitmask!(tag, 0x20);

        let compressed::Unsigned(param_count) = from.gread(offset)?;

        let property_type = from.gread(offset)?;

        let params = (0..param_count)
            .map(|_| from.gread(offset))
            .collect::<scroll::Result<_>>()?;

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
impl TryIntoCtx for PropertySig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(
            if self.has_this { 0x28_u8 } else { 0x8_u8 },
            offset,
            scroll::LE,
        )?;

        into.gwrite(compressed::Unsigned(self.params.len() as u32), offset)?;

        // includes mods and type
        into.gwrite(self.property_type, offset)?;

        for p in self.params {
            into.gwrite(p, offset)?;
        }

        Ok(*offset)
    }
}

#[derive(Debug)]
pub enum LocalVar {
    TypedByRef,
    Variable {
        custom_modifiers: Vec<CustomMod>,
        pinned: bool,
        by_ref: bool,
        var_type: Type,
    },
}

#[derive(Debug)]
pub struct LocalVarSig(pub Vec<LocalVar>);

impl TryFromCtx<'_> for LocalVarSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != 0x7 {
            throw!("bad local var signature tag {:#04x}", tag);
        }

        let compressed::Unsigned(var_count) = from.gread(offset)?;

        let vars = (0..var_count)
            .map(|_| {
                Ok(if from[*offset] == ELEMENT_TYPE_TYPEDBYREF {
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
                })
            })
            .collect::<scroll::Result<_>>()?;

        Ok((LocalVarSig(vars), *offset))
    }
}
impl TryIntoCtx<(), DynamicBuffer> for LocalVarSig {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        // tag
        into.gwrite_with(0x7, offset, scroll::LE)?;

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

#[derive(Debug)]
pub struct MethodSpec(pub Vec<Type>);

impl TryFromCtx<'_> for MethodSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != 0x0a {
            throw!("bad method spec tag {:#04x}", tag);
        }

        let compressed::Unsigned(type_count) = from.gread(offset)?;

        let types = (0..type_count)
            .map(|_| from.gread(offset))
            .collect::<scroll::Result<_>>()?;

        Ok((MethodSpec(types), *offset))
    }
}
impl TryIntoCtx<(), DynamicBuffer> for MethodSpec {
    type Error = scroll::Error;

    fn try_into_ctx(self, into: &mut DynamicBuffer, _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(0x0a, offset, scroll::LE)?;

        into.gwrite(compressed::Unsigned(self.0.len() as u32), offset)?;
        for t in self.0 {
            into.gwrite(t, offset)?;
        }

        Ok(*offset)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MarshalSpec {
    Primitive(NativeIntrinsic),
    Array {
        element_type: Option<NativeIntrinsic>,
        length_parameter: Option<usize>,
        additional_elements: Option<usize>,
    },
}

impl TryFromCtx<'_> for MarshalSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
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
        let length_parameter = from
            .gread::<compressed::Unsigned>(offset)
            .ok()
            .map(|u| u.0 as usize);
        let additional_elements = from
            .gread::<compressed::Unsigned>(offset)
            .ok()
            .map(|u| u.0 as usize);

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
