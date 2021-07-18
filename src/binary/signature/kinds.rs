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

impl TryFromCtx<'_> for MethodDefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        TryFromCtx::try_from_ctx(from, false)
    }
}

impl<'a> TryFromCtx<'a, bool> for MethodDefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], is_ref: bool) -> Result<(Self, usize), Self::Error> {
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

        let len = if is_ref { param_count / 2 } else { param_count };
        let mut params = Vec::with_capacity(len as usize);
        for _ in 0..len {
            params.push(from.gread(offset)?);
        }

        Ok((
            MethodDefSig {
                has_this,
                explicit_this,
                calling_convention: kind,
                ret_type,
                params,
            },
            *offset,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct MethodRefSig {
    pub method_def: MethodDefSig,
    pub varargs: Vec<Param>,
}

impl TryFromCtx<'_> for MethodRefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let method_def = from.gread_with::<MethodDefSig>(offset, true)?;

        let mut varargs = vec![];
        if method_def.calling_convention == CallingConvention::Vararg {
            let sentinel: u8 = from.gread_with(offset, scroll::LE)?;
            if sentinel == ELEMENT_TYPE_SENTINEL {
                for _ in 0..method_def.params.len() {
                    varargs.push(from.gread(offset)?);
                }
            } else {
                *offset -= 1;
            }
        }

        Ok((
            MethodRefSig {
                method_def,
                varargs,
            },
            *offset,
        ))
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum StandAloneCallingConvention {
    Default,
    Vararg,
    C,
    Stdcall,
    Thiscall,
    Fastcall,
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
            0 => Default,
            1 => C,
            2 => Stdcall,
            3 => Thiscall,
            4 => Fastcall,
            5 => Vararg,
            bad => throw!("bad standalone method calling convention {:#03x}", bad),
        };

        let compressed::Unsigned(param_count) = from.gread(offset)?;
        let count = if calling_convention == Vararg {
            param_count / 2
        } else {
            param_count
        };

        let ret_type = from.gread(offset)?;

        let mut params = Vec::with_capacity(count as usize);
        for _ in 0..count {
            params.push(from.gread(offset)?);
        }

        let mut varargs = vec![];
        if calling_convention == Vararg || calling_convention == C {
            let sentinel: u8 = from.gread_with(offset, scroll::LE)?;
            if sentinel == ELEMENT_TYPE_SENTINEL {
                for _ in 0..count {
                    varargs.push(from.gread(offset)?);
                }
            } else {
                *offset -= 1;
            }
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

#[derive(Debug)]
pub struct FieldSig(pub Option<CustomMod>, pub Type);

impl TryFromCtx<'_> for FieldSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != 0x6 {
            throw!("bad field tag {:#04x}", tag);
        }

        let prev_offset = *offset;
        let opt_mod = from.gread(offset).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

        Ok((FieldSig(opt_mod, from.gread(offset)?), *offset))
    }
}

#[derive(Debug)]
pub struct PropertySig {
    pub has_this: bool,
    pub custom_modifier: Option<CustomMod>,
    pub ret_type: Type,
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

        let prev_offset = *offset;
        let opt_mod = from.gread(offset).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

        let ret_type = from.gread(offset)?;

        let mut params = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            params.push(from.gread(offset)?);
        }

        Ok((
            PropertySig {
                has_this,
                custom_modifier: opt_mod,
                ret_type,
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
        custom_modifier: Option<CustomMod>,
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
            let var_tag: u8 = from.gread_with(offset, scroll::LE)?;
            vars.push(if var_tag == ELEMENT_TYPE_TYPEDBYREF {
                LocalVar::TypedByRef
            } else {
                // revert the var tag
                *offset -= 1;

                let prev_offset = *offset;
                let opt_mod = from.gread(offset).ok();
                if opt_mod.is_none() {
                    *offset = prev_offset;
                }

                // the syntax diagram for these flags in the spec is very confusing

                let pinned = match from.gread_with::<u8>(offset, scroll::LE) {
                    Ok(c) if c == ELEMENT_TYPE_PINNED => true,
                    _ => {
                        *offset -= 1;
                        false
                    }
                };

                let by_ref = match from.gread_with::<u8>(offset, scroll::LE) {
                    Ok(r) if r == ELEMENT_TYPE_BYREF => true,
                    _ => {
                        *offset -= 1;
                        false
                    }
                };

                LocalVar::Variable {
                    custom_modifier: opt_mod,
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
        element_type: NativeIntrinsic,
        length_parameter: Option<usize>,
        additional_elements: Option<usize>,
    },
}

impl TryFromCtx<'_> for MarshalSpec {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        use MarshalSpec::*;

        let tag: u8 = from.gread_with(offset, scroll::LE)?;
        if tag != NATIVE_TYPE_ARRAY {
            return Ok((Primitive(from.gread(offset)?), *offset));
        }

        let element_type = from.gread(offset)?;
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
