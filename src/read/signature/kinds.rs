use super::{compressed, encoded::*};
use scroll::{ctx::TryFromCtx, Endian, Pread};

#[derive(Debug, Eq, PartialEq)]
pub enum CallingConvention {
    Default,
    Vararg,
    Generic(usize),
}

#[derive(Debug)]
pub struct MethodDefSig {
    pub has_this: bool,
    pub explicit_this: bool,
    pub calling_convention: CallingConvention,
    pub ret_type: RetType,
    pub params: Vec<Param>,
}

impl<'a> TryFromCtx<'a, Endian> for MethodDefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        TryFromCtx::try_from_ctx(from, (ctx, false))
    }
}

impl<'a> TryFromCtx<'a, (Endian, bool)> for MethodDefSig {
    type Error = scroll::Error;

    fn try_from_ctx(
        from: &'a [u8],
        (ctx, is_ref): (Endian, bool),
    ) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, ctx)?;

        let has_this = tag & 0x20 == 0x20;
        let explicit_this = tag & 0x40 == 0x40;

        let kind = match tag & 0x1f {
            0x10 => {
                let compressed::Unsigned(value) = from.gread_with(offset, ctx)?;
                CallingConvention::Generic(value as usize)
            }
            0x5 => CallingConvention::Vararg,
            0x0 => CallingConvention::Default,
            _ => {
                return Err(scroll::Error::Custom(format!(
                    "bad method def kind tag {:#04x}",
                    tag
                )))
            }
        };

        let compressed::Unsigned(param_count) = from.gread_with(offset, ctx)?;

        let ret_type = from.gread_with(offset, ctx)?;

        let mut params = vec![];
        for _ in 0..(if is_ref { param_count / 2 } else { param_count }) {
            params.push(from.gread_with(offset, ctx)?);
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

#[derive(Debug)]
pub struct MethodRefSig {
    pub method_def: MethodDefSig,
    pub varargs: Vec<Param>,
}

impl<'a> TryFromCtx<'a, Endian> for MethodRefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let method_def: MethodDefSig = from.gread_with(offset, (ctx, true))?;

        let mut varargs = vec![];
        if method_def.calling_convention == CallingConvention::Vararg {
            let sentinel: u8 = from.gread_with(offset, ctx)?;
            if sentinel == ELEMENT_TYPE_SENTINEL {
                for _ in 0..method_def.params.len() {
                    varargs.push(from.gread_with(offset, ctx)?);
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

#[derive(Debug, Eq, PartialEq)]
pub enum StandAloneCallingConvention {
    Default,
    Vararg,
    C,
    Stdcall,
    Thiscall,
    Fastcall,
}

#[derive(Debug)]
pub struct StandAloneMethodSig {
    pub has_this: bool,
    pub explicit_this: bool,
    pub calling_convention: StandAloneCallingConvention,
    pub ret_type: RetType,
    pub params: Vec<Param>,
    pub varargs: Vec<Param>,
}

impl<'a> TryFromCtx<'a, Endian> for StandAloneMethodSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, ctx)?;

        let has_this = tag & 0x20 == 0x20;
        let explicit_this = tag & 0x40 == 0x40;

        use StandAloneCallingConvention::*;

        let calling_convention = match tag & 0xf {
            0 => Default,
            1 => C,
            2 => Stdcall,
            3 => Thiscall,
            4 => Fastcall,
            5 => Vararg,
            bad => {
                return Err(scroll::Error::Custom(format!(
                    "bad standalone method calling convention {:#03x}",
                    bad
                )))
            }
        };

        let compressed::Unsigned(param_count) = from.gread_with(offset, ctx)?;
        let count = if calling_convention == Vararg {
            param_count / 2
        } else {
            param_count
        };

        let ret_type = from.gread_with(offset, ctx)?;

        let mut params = vec![];
        for _ in 0..count {
            params.push(from.gread_with(offset, ctx)?);
        }

        let mut varargs = vec![];
        if calling_convention == Vararg || calling_convention == C {
            let sentinel: u8 = from.gread_with(offset, ctx)?;
            if sentinel == ELEMENT_TYPE_SENTINEL {
                for _ in 0..count {
                    varargs.push(from.gread_with(offset, ctx)?);
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

impl<'a> TryFromCtx<'a, Endian> for FieldSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, ctx)?;
        if tag != 0x6 {
            return Err(scroll::Error::Custom(format!("bad field tag {:#04x}", tag)));
        }

        let prev_offset = *offset;
        let opt_mod = from.gread_with::<CustomMod>(offset, ctx).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

        Ok((FieldSig(opt_mod, from.gread_with(offset, ctx)?), *offset))
    }
}

#[derive(Debug)]
pub struct PropertySig {
    pub has_this: bool,
    pub custom_modifier: Option<CustomMod>,
    pub ret_type: Type,
    pub params: Vec<Param>,
}

impl<'a> TryFromCtx<'a, Endian> for PropertySig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, ctx)?;
        if tag & 0x8 != 0x8 {
            return Err(scroll::Error::Custom(format!(
                "bad property signature tag {:#04x}",
                tag
            )));
        }

        let has_this = tag & 0x20 == 0x20;

        let compressed::Unsigned(param_count) = from.gread_with(offset, ctx)?;

        let prev_offset = *offset;
        let opt_mod = from.gread_with::<CustomMod>(offset, ctx).ok();
        if opt_mod.is_none() {
            *offset = prev_offset;
        }

        let ret_type = from.gread_with(offset, ctx)?;

        let mut params = vec![];
        for _ in 0..param_count {
            params.push(from.gread_with(offset, ctx)?);
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

impl<'a> TryFromCtx<'a, Endian> for LocalVarSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let tag: u8 = from.gread_with(offset, ctx)?;
        if tag != 0x7 {
            return Err(scroll::Error::Custom(format!(
                "bad local var signature tag {:#04x}",
                tag
            )));
        }

        let compressed::Unsigned(var_count) = from.gread_with(offset, ctx)?;

        let mut vars = vec![];
        for _ in 0..var_count {
            let var_tag: u8 = from.gread_with(offset, ctx)?;
            vars.push(if var_tag == ELEMENT_TYPE_TYPEDBYREF {
                LocalVar::TypedByRef
            } else {
                let prev_offset = *offset;
                let opt_mod = from.gread_with::<CustomMod>(offset, ctx).ok();
                if opt_mod.is_none() {
                    *offset = prev_offset;
                }

                let pinned = from.gread_with::<u8>(offset, ctx)? == ELEMENT_TYPE_PINNED;
                if !pinned {
                    *offset -= 1;
                }

                let by_ref = from.gread_with::<u8>(offset, ctx)? == ELEMENT_TYPE_BYREF;
                if !by_ref {
                    *offset -= 1;
                }

                LocalVar::Variable {
                    custom_modifier: opt_mod,
                    pinned,
                    by_ref,
                    var_type: from.gread_with(offset, ctx)?,
                }
            });
        }

        Ok((LocalVarSig(vars), *offset))
    }
}
