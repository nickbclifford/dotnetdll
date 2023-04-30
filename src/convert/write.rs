use super::TypeKind;
use crate::binary::signature::kinds::PropertySig;
use crate::dll::DLLError;
use crate::{
    binary::{
        heap::{BlobWriter, UserStringWriter, Writer},
        il::Instruction as BInstruction,
        metadata::{
            index::{Blob, MethodDefOrRef, Token, TokenTarget, TypeDefOrRef},
            table::{Kind, MethodSpec, StandAloneSig, TypeSpec},
        },
        signature::{
            encoded::{CustomMod, Param, ParamType, RetType, RetTypeType, Type as SType},
            kinds::{
                FieldSig, LocalVar, LocalVarSig, MethodDefSig, MethodRefSig, MethodSpec as MethodSpecSig,
                StandAloneMethodSig,
            },
        },
    },
    dll::Result,
    resolved::{
        il::*,
        members::{ExternalFieldReference, Field, FieldSource, MethodSource, Property, UserMethod},
        signature::*,
        types::*,
    },
};
use paste::paste;
use scroll::{ctx::TryIntoCtx, Pwrite};
use scroll_buffer::DynamicBuffer;
use std::collections::HashMap;

pub struct Context<'a> {
    pub blobs: &'a mut BlobWriter,
    pub specs: &'a mut Vec<TypeSpec>,
    pub type_cache: &'a mut HashMap<u64, TypeDefOrRef>,
    pub blob_scratch: &'a mut DynamicBuffer,
}

pub fn index(t: &impl TypeKind, ctx: &mut Context) -> Result<TypeDefOrRef> {
    let hash = crate::utils::hash(t);

    if let Some(&i) = ctx.type_cache.get(&hash) {
        return Ok(i);
    }

    let result = t.as_idx(ctx)?;

    ctx.type_cache.insert(hash, result);

    Ok(result)
}

pub fn user_index(t: UserType) -> TypeDefOrRef {
    match t {
        UserType::Definition(d) => TypeDefOrRef::TypeDef(d.0 + 1),
        UserType::Reference(r) => TypeDefOrRef::TypeRef(r.0 + 1),
    }
}

fn source_sig(value_kind: Option<ValueKind>, t: &TypeSource<impl TypeKind>, ctx: &mut Context) -> Result<SType> {
    let Some(value_kind) = value_kind else {
        return Err(DLLError::CLI(scroll::Error::Custom(
            "attempted to use type of unknown value kind inside a signature".to_string(),
        )))
    };
    Ok(match t {
        TypeSource::User(u) => match value_kind {
            ValueKind::Class => SType::Class(user_index(*u).into()),
            ValueKind::ValueType => SType::ValueType(user_index(*u).into()),
        },
        TypeSource::Generic { base, parameters } => {
            let base = user_index(*base).into();
            let params = parameters.iter().map(|g| g.as_sig(ctx)).collect::<Result<_>>()?;
            match value_kind {
                ValueKind::Class => SType::GenericInstClass(base, params),
                ValueKind::ValueType => SType::GenericInstValueType(base, params),
            }
        }
    })
}

pub fn source_index(
    value_kind: Option<ValueKind>,
    t: &TypeSource<impl TypeKind>,
    ctx: &mut Context,
) -> Result<TypeDefOrRef> {
    if let TypeSource::User(u) = t {
        Ok(user_index(*u))
    } else {
        into_index(source_sig(value_kind, t, ctx)?, ctx)
    }
}

pub fn base_index(base: &BaseType<impl TypeKind>, ctx: &mut Context) -> Result<TypeDefOrRef> {
    Ok(match base {
        BaseType::Type { value_kind, source } => source_index(*value_kind, source, ctx)?,
        rest => into_index(base_sig(rest, ctx)?, ctx)?,
    })
}

pub fn into_blob(sig: impl TryIntoCtx<(), DynamicBuffer, Error = scroll::Error>, ctx: &mut Context) -> Result<Blob> {
    ctx.blob_scratch.clear();

    ctx.blob_scratch.pwrite(sig, 0)?;

    Ok(ctx.blobs.write(ctx.blob_scratch.get())?)
}

pub(super) fn into_index(
    sig: impl TryIntoCtx<(), DynamicBuffer, Error = scroll::Error>,
    ctx: &mut Context,
) -> Result<TypeDefOrRef> {
    let len = ctx.specs.len();

    let t = TypeSpec {
        signature: into_blob(sig, ctx)?,
    };
    ctx.specs.push(t);

    Ok(TypeDefOrRef::TypeSpec(len + 1))
}

pub(super) fn base_sig(base: &BaseType<impl TypeKind>, ctx: &mut Context) -> Result<SType> {
    use BaseType::*;

    Ok(match base {
        Type { value_kind, source } => source_sig(*value_kind, source, ctx)?,
        Boolean => SType::Boolean,
        Char => SType::Char,
        Int8 => SType::Int8,
        UInt8 => SType::UInt8,
        Int16 => SType::Int16,
        UInt16 => SType::UInt16,
        Int32 => SType::Int32,
        UInt32 => SType::UInt32,
        Int64 => SType::Int64,
        UInt64 => SType::UInt64,
        Float32 => SType::Float32,
        Float64 => SType::Float64,
        IntPtr => SType::IntPtr,
        UIntPtr => SType::UIntPtr,
        Object => SType::Object,
        String => SType::String,
        Vector(m, t) => SType::SzArray(custom_modifiers(m), Box::new(t.as_sig(ctx)?)),
        Array(t, shape) => SType::Array(Box::new(t.as_sig(ctx)?), shape.clone()),
        ValuePointer(m, opt) => SType::Ptr(
            custom_modifiers(m),
            match opt {
                Some(t) => Some(Box::new(t.as_sig(ctx)?)),
                None => None,
            },
        ),
        FunctionPointer(sig) => SType::FnPtr(Box::new(maybe_unmanaged_method(sig, ctx)?)),
    })
}

fn maybe_unmanaged_method(sig: &MaybeUnmanagedMethod, ctx: &mut Context) -> Result<StandAloneMethodSig> {
    Ok(StandAloneMethodSig {
        has_this: sig.instance,
        explicit_this: sig.explicit_this,
        calling_convention: sig.calling_convention,
        ret_type: ret_type_sig(&sig.return_type, ctx)?,
        params: sig
            .parameters
            .iter()
            .map(|p| parameter_sig(p, ctx))
            .collect::<Result<_>>()?,
        varargs: sig
            .varargs
            .iter()
            .flatten()
            .map(|p| parameter_sig(p, ctx))
            .collect::<Result<_>>()?,
    })
}

pub fn custom_modifiers(mods: &[CustomTypeModifier]) -> Vec<CustomMod> {
    mods.iter()
        .map(|m| match m {
            CustomTypeModifier::Optional(t) => CustomMod::Optional(user_index(*t).into()),
            CustomTypeModifier::Required(t) => CustomMod::Required(user_index(*t).into()),
        })
        .collect()
}

fn parameter_sig(p: &Parameter, ctx: &mut Context) -> Result<Param> {
    Ok(Param(
        custom_modifiers(&p.0),
        match &p.1 {
            ParameterType::Value(v) => ParamType::Type(v.as_sig(ctx)?),
            ParameterType::Ref(r) => ParamType::ByRef(r.as_sig(ctx)?),
            ParameterType::TypedReference => ParamType::TypedByRef,
        },
    ))
}

// pub fn parameter(p: &Parameter, ctx: &mut Context) -> Result<Blob> {
//     into_blob(parameter_sig(p, ctx)?, ctx)
// }

fn ret_type_sig(r: &ReturnType, ctx: &mut Context) -> Result<RetType> {
    Ok(RetType(
        custom_modifiers(&r.0),
        match &r.1 {
            Some(ParameterType::Value(v)) => RetTypeType::Type(v.as_sig(ctx)?),
            Some(ParameterType::Ref(r)) => RetTypeType::ByRef(r.as_sig(ctx)?),
            Some(ParameterType::TypedReference) => RetTypeType::TypedByRef,
            None => RetTypeType::Void,
        },
    ))
}

fn method_def_sig(sig: &ManagedMethod, ctx: &mut Context) -> Result<MethodDefSig> {
    Ok(MethodDefSig {
        has_this: sig.instance,
        explicit_this: sig.explicit_this,
        calling_convention: sig.calling_convention,
        ret_type: ret_type_sig(&sig.return_type, ctx)?,
        params: sig
            .parameters
            .iter()
            .map(|p| parameter_sig(p, ctx))
            .collect::<Result<_>>()?,
    })
}

pub fn method_def(sig: &ManagedMethod, ctx: &mut Context) -> Result<Blob> {
    into_blob(method_def_sig(sig, ctx)?, ctx)
}

fn method_ref_sig(sig: &ManagedMethod, ctx: &mut Context) -> Result<MethodRefSig> {
    Ok(MethodRefSig {
        method_def: method_def_sig(sig, ctx)?,
        varargs: sig
            .varargs
            .iter()
            .flatten()
            .map(|p| parameter_sig(p, ctx))
            .collect::<Result<_>>()?,
    })
}

pub fn method_ref(sig: &ManagedMethod, ctx: &mut Context) -> Result<Blob> {
    into_blob(method_ref_sig(sig, ctx)?, ctx)
}

fn field_sig(f: &Field, ctx: &mut Context) -> Result<FieldSig> {
    Ok(FieldSig {
        custom_modifiers: custom_modifiers(&f.type_modifiers),
        by_ref: f.by_ref,
        field_type: f.return_type.as_sig(ctx)?,
    })
}

pub fn field_def(f: &Field, ctx: &mut Context) -> Result<Blob> {
    into_blob(field_sig(f, ctx)?, ctx)
}

fn field_ref_sig(f: &ExternalFieldReference, ctx: &mut Context) -> Result<FieldSig> {
    Ok(FieldSig {
        custom_modifiers: custom_modifiers(&f.custom_modifiers),
        by_ref: false,
        field_type: f.field_type.as_sig(ctx)?,
    })
}

pub fn field_ref(f: &ExternalFieldReference, ctx: &mut Context) -> Result<Blob> {
    into_blob(field_ref_sig(f, ctx)?, ctx)
}

fn property_sig(p: &Property, ctx: &mut Context) -> Result<PropertySig> {
    Ok(PropertySig {
        has_this: !p.static_member,
        property_type: parameter_sig(&p.property_type, ctx)?,
        params: p
            .parameters
            .iter()
            .map(|p| parameter_sig(p, ctx))
            .collect::<Result<_>>()?,
    })
}

pub fn property(p: &Property, ctx: &mut Context) -> Result<Blob> {
    into_blob(property_sig(p, ctx)?, ctx)
}

pub fn idx_with_modifiers(t: &impl TypeKind, mods: &[CustomTypeModifier], ctx: &mut Context) -> Result<TypeDefOrRef> {
    if let Some(BaseType::Type {
        source: TypeSource::User(u),
        ..
    }) = t.as_base()
    {
        Ok(user_index(*u))
    } else {
        let sig = t.as_sig(ctx)?;
        let mods = custom_modifiers(mods);

        struct Wrapper(Vec<CustomMod>, SType);
        impl TryIntoCtx<(), DynamicBuffer> for Wrapper {
            type Error = scroll::Error;

            fn try_into_ctx(self, buf: &mut DynamicBuffer, _: ()) -> std::result::Result<usize, Self::Error> {
                let offset = &mut 0;

                for m in self.0 {
                    buf.gwrite(m, offset)?;
                }
                buf.gwrite(self.1, offset)?;

                Ok(*offset)
            }
        }

        into_index(Wrapper(mods, sig), ctx)
    }
}

fn local_var_sig(vars: &[LocalVariable], ctx: &mut Context) -> Result<LocalVarSig> {
    Ok(LocalVarSig(
        vars.iter()
            .map(|v| {
                Ok(match v {
                    LocalVariable::TypedReference => LocalVar::TypedByRef,
                    LocalVariable::Variable {
                        custom_modifiers: cmod,
                        pinned,
                        by_ref,
                        var_type,
                    } => LocalVar::Variable {
                        custom_modifiers: custom_modifiers(cmod),
                        pinned: *pinned,
                        by_ref: *by_ref,
                        var_type: var_type.as_sig(ctx)?,
                    },
                })
            })
            .collect::<Result<_>>()?,
    ))
}

pub fn local_vars(vars: &[LocalVariable], ctx: &mut Context) -> Result<Blob> {
    into_blob(local_var_sig(vars, ctx)?, ctx)
}

pub struct MethodContext<'a, T, U> {
    pub stand_alone_sigs: &'a mut Vec<StandAloneSig>,
    pub method_specs: &'a mut Vec<MethodSpec>,
    pub userstrings: &'a mut UserStringWriter,
    pub user_method: &'a T,
    pub field_source: &'a U,
}

#[allow(clippy::too_many_lines)]
pub fn instruction(
    instruction: &Instruction,
    ctx: &mut Context,
    m_ctx: &mut MethodContext<'_, impl Fn(UserMethod) -> MethodDefOrRef, impl Fn(FieldSource) -> Token>,
) -> Result<BInstruction> {
    use Instruction::*;
    use NumberSign::*;

    fn check_mask(skip_type: bool, skip_range: bool, skip_null: bool) -> u8 {
        let mut mask = 0;
        if skip_type {
            mask |= 0x1;
        }
        if skip_range {
            mask |= 0x2;
        }
        if skip_null {
            mask |= 0x4;
        }
        mask
    }

    macro_rules! method_source {
        ($m:ident) => {
            match $m {
                MethodSource::User(u) => (m_ctx.user_method)(*u).into(),
                MethodSource::Generic(g) => {
                    let idx = m_ctx.method_specs.len() + 1;

                    m_ctx.method_specs.push(MethodSpec {
                        method: (m_ctx.user_method)(g.base),
                        instantiation: into_blob(
                            MethodSpecSig(
                                g.parameters
                                    .iter()
                                    .map(|t| t.as_sig(ctx))
                                    .collect::<Result<Vec<_>>>()?,
                            ),
                            ctx,
                        )?,
                    });

                    Token {
                        target: TokenTarget::Table(Kind::MethodSpec),
                        index: idx,
                    }
                }
            }
        };
    }

    macro_rules! stand_alone_sig {
        ($method_sig:ident) => {{
            let sig = maybe_unmanaged_method($method_sig, ctx)?;
            m_ctx.stand_alone_sigs.push(StandAloneSig {
                signature: into_blob(sig, ctx)?,
            });
            Token {
                target: TokenTarget::Table(Kind::StandAloneSig),
                index: m_ctx.stand_alone_sigs.len(),
            }
        }};
    }

    macro_rules! short {
        ($var:ident, $i:ty, $val:ident) => {
            paste! {
                match $i::try_from(*$val).ok() {
                    Some(u) => BInstruction::[<$var S>](u),
                    None => BInstruction::$var(*$val)
                }
            }
        };
    }

    macro_rules! make_convert {
        ($($src:ident => $dest:ident),+) => {
            paste! {
                macro_rules! convert {
                    ($t:ident) => {
                        match $t {
                            $(ConversionType::$src => BInstruction::[<Conv $dest>]),+
                        }
                    }
                }

                macro_rules! convert_overflow {
                    ($t:ident, $sign:ident) => {
                        match ($t, $sign) {
                            $(
                                (ConversionType::$src, Signed) => BInstruction::[<ConvOvf $dest>],
                            )+
                            $(
                                (ConversionType::$src, Unsigned) => BInstruction::[<ConvOvf $dest Un>]
                            ),+
                        }
                    }
                }
            }
        }
    }

    make_convert! {
        Int8 => I1,
        Int16 => I2,
        Int32 => I4,
        Int64 => I8,
        UInt8 => U1,
        UInt16 => U2,
        UInt32 => U4,
        UInt64 => U8,
        IntPtr => I,
        UIntPtr => U
    }

    macro_rules! indirect {
        ($unaligned:ident, $volatile:ident, $ty:ident, $enum:ty => $instr:ident, { $($src:ident => $dest:ident),+ }) => {
            paste! {
                match ($unaligned, $volatile) {
                    (None, false) => match $ty {
                        $($enum::$src => BInstruction::[<$instr $dest>]),+
                    },
                    (None, true) => match $ty {
                        $($enum::$src => BInstruction::[<Volatile $instr $dest>]),+
                    },
                    (Some(a), false) => match $ty {
                        $($enum::$src => BInstruction::[<Unaligned $instr $dest>](*a as u8)),+
                    },
                    (Some(a), true) => match $ty {
                        $($enum::$src => BInstruction::[<UnalignedVolatile $instr $dest>](*a as u8)),+
                    }
                }
            }
        }
    }

    macro_rules! element {
        ($t:expr, $r:expr, $n:expr, $e:ident, $ty:ident => $prefix:ident, { $($src:ident => $dest:ident),+ }) => {
            paste! {
                match ($t, $r, $n) {
                    (false, false, false) => match $e {
                        $(
                            $ty::$src => BInstruction::[<$prefix $dest>]
                        ),+
                    },
                    (t, r, n) => match $e {
                        $(
                            $ty::$src => BInstruction::[<Nocheck $prefix $dest>](check_mask(t, r, n))
                        ),+
                    }
                }
            }
        }
    }

    macro_rules! field {
        ($u:ident, $v:ident, $f:ident, $instr:ident) => {{
            let f = (m_ctx.field_source)(*$f);
            paste! {
                match ($u, $v) {
                    (None, false) => BInstruction::$instr(f),
                    (None, true) => BInstruction::[<Volatile $instr>](f),
                    (Some(a), false) => BInstruction::[<Unaligned $instr>](*a as u8, f),
                    (Some(a), true) => BInstruction::[<UnalignedVolatile $instr>](*a as u8, f),
                }
            }
        }};
    }

    Ok(match instruction {
        Add => BInstruction::Add,
        AddOverflow(Signed) => BInstruction::AddOvf,
        AddOverflow(Unsigned) => BInstruction::AddOvfUn,
        And => BInstruction::And,
        ArgumentList => BInstruction::Arglist,
        BranchEqual(o) => BInstruction::Beq(*o as i32),
        BranchGreaterOrEqual(Signed, o) => BInstruction::Bge(*o as i32),
        BranchGreaterOrEqual(Unsigned, o) => BInstruction::BgeUn(*o as i32),
        BranchGreater(Signed, o) => BInstruction::Bgt(*o as i32),
        BranchGreater(Unsigned, o) => BInstruction::BgtUn(*o as i32),
        BranchLessOrEqual(Signed, o) => BInstruction::Ble(*o as i32),
        BranchLessOrEqual(Unsigned, o) => BInstruction::BleUn(*o as i32),
        BranchLess(Signed, o) => BInstruction::Blt(*o as i32),
        BranchLess(Unsigned, o) => BInstruction::BltUn(*o as i32),
        BranchNotEqual(o) => BInstruction::BneUn(*o as i32),
        Branch(o) => BInstruction::Br(*o as i32),
        Breakpoint => BInstruction::Break,
        BranchFalsy(o) => BInstruction::Brfalse(*o as i32),
        BranchTruthy(o) => BInstruction::Brtrue(*o as i32),
        Call {
            tail_call: false,
            param0: method,
        } => BInstruction::Call(method_source!(method)),
        Call {
            tail_call: true,
            param0: method,
        } => BInstruction::TailCall(method_source!(method)),
        CallConstrained(constraint, method) => {
            BInstruction::ConstrainedCall(constraint.as_idx(ctx)?.into(), method_source!(method))
        }
        CallIndirect {
            tail_call: false,
            param0: signature,
        } => BInstruction::Calli(stand_alone_sig!(signature)),
        CallIndirect {
            tail_call: true,
            param0: signature,
        } => BInstruction::TailCalli(stand_alone_sig!(signature)),
        CompareEqual => BInstruction::Ceq,
        CompareGreater(Signed) => BInstruction::Cgt,
        CompareGreater(Unsigned) => BInstruction::CgtUn,
        CheckFinite => BInstruction::Ckfinite,
        CompareLess(Signed) => BInstruction::Clt,
        CompareLess(Unsigned) => BInstruction::CltUn,
        Convert(t) => convert!(t),
        ConvertOverflow(t, sign) => convert_overflow!(t, sign),
        ConvertFloat32 => BInstruction::ConvR4,
        ConvertFloat64 => BInstruction::ConvR8,
        ConvertUnsignedToFloat => BInstruction::ConvRUn,
        CopyMemoryBlock {
            unaligned: None,
            volatile: false,
        } => BInstruction::Cpblk,
        CopyMemoryBlock {
            unaligned: None,
            volatile: true,
        } => BInstruction::VolatileCpblk,
        CopyMemoryBlock {
            unaligned: Some(a),
            volatile: false,
        } => BInstruction::UnalignedCpblk(*a as u8),
        CopyMemoryBlock {
            unaligned: Some(a),
            volatile: true,
        } => BInstruction::UnalignedVolatileCpblk(*a as u8),
        Divide(Signed) => BInstruction::Div,
        Divide(Unsigned) => BInstruction::DivUn,
        Duplicate => BInstruction::Dup,
        EndFilter => BInstruction::Endfilter,
        EndFinally => BInstruction::Endfinally,
        InitializeMemoryBlock {
            unaligned: None,
            volatile: false,
        } => BInstruction::Initblk,
        InitializeMemoryBlock {
            unaligned: None,
            volatile: true,
        } => BInstruction::VolatileInitblk,
        InitializeMemoryBlock {
            unaligned: Some(a),
            volatile: false,
        } => BInstruction::UnalignedInitblk(*a as u8),
        InitializeMemoryBlock {
            unaligned: Some(a),
            volatile: true,
        } => BInstruction::UnalignedVolatileInitblk(*a as u8),
        Jump(m) => BInstruction::Jmp(method_source!(m)),
        LoadArgument(0) => BInstruction::Ldarg0,
        LoadArgument(1) => BInstruction::Ldarg1,
        LoadArgument(2) => BInstruction::Ldarg2,
        LoadArgument(3) => BInstruction::Ldarg3,
        LoadArgument(i) => short!(Ldarg, u8, i),
        LoadArgumentAddress(i) => short!(Ldarga, u8, i),
        LoadConstantInt32(0) => BInstruction::LdcI40,
        LoadConstantInt32(1) => BInstruction::LdcI41,
        LoadConstantInt32(2) => BInstruction::LdcI42,
        LoadConstantInt32(3) => BInstruction::LdcI43,
        LoadConstantInt32(4) => BInstruction::LdcI44,
        LoadConstantInt32(5) => BInstruction::LdcI45,
        LoadConstantInt32(6) => BInstruction::LdcI46,
        LoadConstantInt32(7) => BInstruction::LdcI47,
        LoadConstantInt32(8) => BInstruction::LdcI48,
        LoadConstantInt32(-1) => BInstruction::LdcI4M1,
        LoadConstantInt32(i) => short!(LdcI4, i8, i),
        LoadConstantInt64(i) => BInstruction::LdcI8(*i),
        LoadConstantFloat32(f) => BInstruction::LdcR4(*f),
        LoadConstantFloat64(f) => BInstruction::LdcR8(*f),
        LoadMethodPointer(m) => BInstruction::Ldftn(method_source!(m)),
        LoadIndirect {
            unaligned,
            volatile,
            param0: value_type,
        } => indirect!(unaligned, volatile, value_type, LoadType => Ldind, {
            Int8 => I1,
            Int16 => I2,
            Int32 => I4,
            Int64 => I8,
            UInt8 => U1,
            UInt16 => U2,
            UInt32 => U4,
            Float32 => R4,
            Float64 => R8,
            IntPtr => I,
            Object => Ref
        }),
        LoadLocal(0) => BInstruction::Ldloc0,
        LoadLocal(1) => BInstruction::Ldloc1,
        LoadLocal(2) => BInstruction::Ldloc2,
        LoadLocal(3) => BInstruction::Ldloc3,
        LoadLocal(i) => short!(Ldloc, u8, i),
        LoadLocalAddress(i) => short!(Ldloca, u8, i),
        LoadNull => BInstruction::Ldnull,
        Leave(o) => BInstruction::Leave(*o as i32),
        LocalMemoryAllocate => BInstruction::Localloc,
        Multiply => BInstruction::Mul,
        MultiplyOverflow(Signed) => BInstruction::MulOvf,
        MultiplyOverflow(Unsigned) => BInstruction::MulOvfUn,
        Negate => BInstruction::Neg,
        NoOperation => BInstruction::Nop,
        Not => BInstruction::Not,
        Or => BInstruction::Or,
        Pop => BInstruction::Pop,
        Remainder(Signed) => BInstruction::Rem,
        Remainder(Unsigned) => BInstruction::RemUn,
        Return => BInstruction::Ret,
        ShiftLeft => BInstruction::Shl,
        ShiftRight(Signed) => BInstruction::Shr,
        ShiftRight(Unsigned) => BInstruction::ShrUn,
        StoreArgument(i) => short!(Starg, u8, i),
        StoreIndirect {
            unaligned,
            volatile,
            param0: value_type,
        } => indirect!(unaligned, volatile, value_type, StoreType => Stind, {
            Int8 => I1,
            Int16 => I2,
            Int32 => I4,
            Int64 => I8,
            Float32 => R4,
            Float64 => R8,
            IntPtr => I,
            Object => Ref
        }),
        StoreLocal(0) => BInstruction::Stloc0,
        StoreLocal(1) => BInstruction::Stloc1,
        StoreLocal(2) => BInstruction::Stloc2,
        StoreLocal(3) => BInstruction::Stloc3,
        StoreLocal(i) => short!(Stloc, u8, i),
        Subtract => BInstruction::Sub,
        SubtractOverflow(Signed) => BInstruction::SubOvf,
        SubtractOverflow(Unsigned) => BInstruction::SubOvfUn,
        Switch(os) => BInstruction::Switch(os.iter().map(|&o| o as i32).collect()),
        Xor => BInstruction::Xor,

        BoxValue(t) => BInstruction::Box(t.as_idx(ctx)?.into()),
        CallVirtual {
            skip_null_check: false,
            param0: method,
        } => BInstruction::Callvirt(method_source!(method)),
        CallVirtual {
            skip_null_check: true,
            param0: method,
        } => BInstruction::NocheckCallvirt(check_mask(false, true, false), method_source!(method)),
        CallVirtualConstrained(constraint, method) => {
            BInstruction::ConstrainedCallvirt(constraint.as_idx(ctx)?.into(), method_source!(method))
        }
        CallVirtualTail(m) => BInstruction::TailCallvirt(method_source!(m)),
        CastClass {
            skip_type_check: false,
            param0: cast_type,
        } => BInstruction::Castclass(cast_type.as_idx(ctx)?.into()),
        CastClass {
            skip_type_check: true,
            param0: cast_type,
        } => BInstruction::NocheckCastclass(check_mask(true, false, false), cast_type.as_idx(ctx)?.into()),
        CopyObject(t) => BInstruction::Cpobj(t.as_idx(ctx)?.into()),
        InitializeForObject(t) => BInstruction::Initobj(t.as_idx(ctx)?.into()),
        IsInstance(t) => BInstruction::Isinst(t.as_idx(ctx)?.into()),
        LoadElement {
            skip_range_check: false,
            skip_null_check: false,
            param0: element_type,
        } => BInstruction::Ldelem(element_type.as_idx(ctx)?.into()),
        LoadElement {
            skip_range_check,
            skip_null_check,
            param0: element_type,
        } => BInstruction::NocheckLdelem(
            check_mask(false, *skip_range_check, *skip_null_check),
            element_type.as_idx(ctx)?.into(),
        ),
        LoadElementPrimitive {
            skip_range_check,
            skip_null_check,
            param0: element_type,
        } => {
            element!(false, *skip_range_check, *skip_null_check, element_type, LoadType => Ldelem, {
                Int8 => I1,
                Int16 => I2,
                Int32 => I4,
                Int64 => I8,
                UInt8 => U1,
                UInt16 => U2,
                UInt32 => U4,
                Float32 => R4,
                Float64 => R8,
                IntPtr => I,
                Object => Ref
            })
        }
        LoadElementAddress {
            skip_type_check: false,
            skip_range_check: false,
            skip_null_check: false,
            param0: element_type,
        } => BInstruction::Ldelema(element_type.as_idx(ctx)?.into()),
        LoadElementAddress {
            skip_type_check,
            skip_range_check,
            skip_null_check,
            param0: element_type,
        } => BInstruction::NocheckLdelema(
            check_mask(*skip_type_check, *skip_range_check, *skip_null_check),
            element_type.as_idx(ctx)?.into(),
        ),
        LoadElementAddressReadonly(t) => BInstruction::ReadonlyLdelema(t.as_idx(ctx)?.into()),
        LoadField {
            unaligned,
            volatile,
            param0: field,
        } => field!(unaligned, volatile, field, Ldfld),
        LoadFieldAddress(f) => BInstruction::Ldflda((m_ctx.field_source)(*f)),
        LoadFieldSkipNullCheck(f) => {
            BInstruction::NocheckLdfld(check_mask(false, false, true), (m_ctx.field_source)(*f))
        }
        LoadLength => BInstruction::Ldlen,
        LoadObject {
            unaligned: None,
            volatile: false,
            param0: object_type,
        } => BInstruction::Ldobj(object_type.as_idx(ctx)?.into()),
        LoadObject {
            unaligned: None,
            volatile: true,
            param0: object_type,
        } => BInstruction::VolatileLdobj(object_type.as_idx(ctx)?.into()),
        LoadObject {
            unaligned: Some(a),
            volatile: false,
            param0: object_type,
        } => BInstruction::UnalignedLdobj(*a as u8, object_type.as_idx(ctx)?.into()),
        LoadObject {
            unaligned: Some(a),
            volatile: true,
            param0: object_type,
        } => BInstruction::UnalignedVolatileLdobj(*a as u8, object_type.as_idx(ctx)?.into()),
        LoadStaticField {
            volatile: false,
            param0: field,
        } => BInstruction::Ldsfld((m_ctx.field_source)(*field)),
        LoadStaticField {
            volatile: true,
            param0: field,
        } => BInstruction::VolatileLdsfld((m_ctx.field_source)(*field)),
        LoadStaticFieldAddress(f) => BInstruction::Ldsflda((m_ctx.field_source)(*f)),
        LoadString(s) => BInstruction::Ldstr(Token {
            target: TokenTarget::UserString,
            index: m_ctx.userstrings.write(s)?,
        }),
        LoadTokenField(f) => BInstruction::Ldtoken((m_ctx.field_source)(*f)),
        LoadTokenMethod(m) => BInstruction::Ldtoken(method_source!(m)),
        LoadTokenType(t) => BInstruction::Ldtoken(t.as_idx(ctx)?.into()),
        LoadVirtualMethodPointer {
            skip_null_check: false,
            param0: method,
        } => BInstruction::Ldvirtftn(method_source!(method)),
        LoadVirtualMethodPointer {
            skip_null_check: true,
            param0: method,
        } => BInstruction::NocheckLdvirtftn(check_mask(false, false, true), method_source!(method)),
        MakeTypedReference(t) => BInstruction::Mkrefany(t.as_idx(ctx)?.into()),
        NewArray(t) => BInstruction::Newarr(t.as_idx(ctx)?.into()),
        NewObject(m) => BInstruction::Newobj((m_ctx.user_method)(*m).into()),
        ReadTypedReferenceType => BInstruction::Refanytype,
        ReadTypedReferenceValue(t) => BInstruction::Refanyval(t.as_idx(ctx)?.into()),
        Rethrow => BInstruction::Rethrow,
        Sizeof(t) => BInstruction::Sizeof(t.as_idx(ctx)?.into()),
        StoreElement {
            skip_type_check: false,
            skip_range_check: false,
            skip_null_check: false,
            param0: element_type,
        } => BInstruction::Stelem(element_type.as_idx(ctx)?.into()),
        StoreElement {
            skip_type_check,
            skip_range_check,
            skip_null_check,
            param0: element_type,
        } => BInstruction::NocheckStelem(
            check_mask(*skip_type_check, *skip_range_check, *skip_null_check),
            element_type.as_idx(ctx)?.into(),
        ),
        StoreElementPrimitive {
            skip_type_check,
            skip_range_check,
            skip_null_check,
            param0: element_type,
        } => element!(
            *skip_type_check,
            *skip_range_check,
            *skip_null_check,
            element_type,
            StoreType => Stelem,
            {
                Int8 => I1,
                Int16 => I2,
                Int32 => I4,
                Int64 => I8,
                Float32 => R4,
                Float64 => R8,
                IntPtr => I,
                Object => Ref
            }
        ),
        StoreField {
            unaligned,
            volatile,
            param0: field,
        } => field!(unaligned, volatile, field, Stfld),
        StoreFieldSkipNullCheck(f) => {
            BInstruction::NocheckStfld(check_mask(false, false, true), (m_ctx.field_source)(*f))
        }
        StoreObject {
            unaligned: None,
            volatile: false,
            param0: object_type,
        } => BInstruction::Stobj(object_type.as_idx(ctx)?.into()),
        StoreObject {
            unaligned: None,
            volatile: true,
            param0: object_type,
        } => BInstruction::VolatileStobj(object_type.as_idx(ctx)?.into()),
        StoreObject {
            unaligned: Some(a),
            volatile: false,
            param0: object_type,
        } => BInstruction::UnalignedStobj(*a as u8, object_type.as_idx(ctx)?.into()),
        StoreObject {
            unaligned: Some(a),
            volatile: true,
            param0: object_type,
        } => BInstruction::UnalignedVolatileStobj(*a as u8, object_type.as_idx(ctx)?.into()),
        StoreStaticField {
            volatile: false,
            param0: field,
        } => BInstruction::Stsfld((m_ctx.field_source)(*field)),
        StoreStaticField {
            volatile: true,
            param0: field,
        } => BInstruction::VolatileStsfld((m_ctx.field_source)(*field)),
        Throw => BInstruction::Throw,
        UnboxIntoAddress {
            skip_type_check: false,
            param0: unbox_type,
        } => BInstruction::Unbox(unbox_type.as_idx(ctx)?.into()),
        UnboxIntoAddress {
            skip_type_check: true,
            param0: unbox_type,
        } => BInstruction::NocheckUnbox(check_mask(true, false, false), unbox_type.as_idx(ctx)?.into()),
        UnboxIntoValue(t) => BInstruction::UnboxAny(t.as_idx(ctx)?.into()),
    })
}
