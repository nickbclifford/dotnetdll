use super::{compressed, encoded::*};
use scroll::{ctx::TryFromCtx, Pread};

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

fn build_params_with_varargs(
    len: &mut u32,
    from: &[u8],
    offset: &mut usize,
) -> scroll::Result<Vec<Param>> {
    let mut params = vec![];
    while *len > 0 {
        if from[*offset] == ELEMENT_TYPE_SENTINEL {
            *offset += 1;
            break;
        } else {
            params.push(from.gread(offset)?);
            *len -= 1;
        }
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

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum StandAloneCallingConvention {
    DefaultManaged,
    Vararg,
    C,
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
            1 => C,
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

        let mods = all_custom_mods(from, offset)?;

        Ok((FieldSig(mods, from.gread(offset)?), *offset))
    }
}

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

        let mut vars = Vec::with_capacity(var_count as usize);
        for _ in 0..var_count {
            vars.push(if from[*offset] == ELEMENT_TYPE_TYPEDBYREF {
                *offset += 1;
                LocalVar::TypedByRef
            } else {
                let mods = all_custom_mods(from, offset)?;

                // the syntax diagram for these flags in the spec is very confusing

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

        let mut types = Vec::with_capacity(type_count as usize);
        for _ in 0..type_count {
            types.push(from.gread(offset)?);
        }

        Ok((MethodSpec(types), *offset))
    }
}

#[derive(Debug, Clone)]
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
