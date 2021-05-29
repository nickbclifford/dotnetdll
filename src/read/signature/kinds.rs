use super::{compressed, encoded};
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
    pub ret_type: encoded::RetType,
    pub params: Vec<encoded::Param>,
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

        let kind = if tag & 0x10 == 0x10 {
            let compressed::Unsigned(value) = from.gread_with(offset, ctx)?;
            CallingConvention::Generic(value as usize)
        } else if tag & 0x5 == 0x5 {
            CallingConvention::Vararg
        } else if tag & 0x0 == 0x0 {
            CallingConvention::Default
        } else {
            return Err(scroll::Error::Custom("bad method def kind tag".to_string()));
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
    pub varargs: Vec<encoded::Param>,
}

impl<'a> TryFromCtx<'a, Endian> for MethodRefSig {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let method_def: MethodDefSig = from.gread_with(offset, (ctx, true))?;

        let mut varargs = vec![];
        if method_def.calling_convention == CallingConvention::Vararg {
            let sentinel: u8 = from.gread_with(offset, ctx)?;
            if sentinel != encoded::ELEMENT_TYPE_SENTINEL {
                for _ in 0..method_def.params.len() {
                    varargs.push(from.gread_with(offset, ctx)?);
                }
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
