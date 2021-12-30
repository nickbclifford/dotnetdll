use crate::{
    binary::{
        heap::{BlobReader, HeapReader, UserStringReader},
        il,
        metadata::{
            index::{MethodDefOrRef, Token, TokenTarget, TypeDefOrRef},
            table::{Kind, MethodSpec, StandAloneSig, TypeSpec},
        },
        signature::{
            encoded::*,
            kinds::{
                MethodDefSig, MethodSpec as MethodSpecSig, StandAloneCallingConvention,
                StandAloneMethodSig,
            },
        },
    },
    dll::{DLLError, Result},
    resolution::*,
    resolved::{self, members::*, signature, types::*},
};
use scroll::Pread;
use std::collections::HashMap;

macro_rules! throw {
    ($($arg:tt)*) => {
        return Err(DLLError::CLI(scroll::Error::Custom(format!($($arg)*))))
    }
}

pub struct Context<'r, 'data: 'r> {
    pub def_len: usize,
    pub ref_len: usize,
    pub specs: &'r [TypeSpec],
    pub sigs: &'r [StandAloneSig],
    pub blobs: &'r BlobReader<'data>,
    pub userstrings: &'r UserStringReader<'data>,
}

pub fn user_type(TypeDefOrRefOrSpec(token): TypeDefOrRefOrSpec, ctx: &Context) -> Result<UserType> {
    use TokenTarget::*;
    let idx = token.index - 1;
    match token.target {
        Table(Kind::TypeDef) => {
            if idx < ctx.def_len {
                Ok(UserType::Definition(TypeIndex(idx)))
            } else {
                Err(format!(
                    "invalid type definition index {} for user type",
                    idx
                ))
            }
        }
        Table(Kind::TypeRef) => {
            if idx < ctx.ref_len {
                Ok(UserType::Reference(TypeRefIndex(idx)))
            } else {
                Err(format!(
                    "invalid type reference index {} for user type",
                    idx
                ))
            }
        }
        bad => Err(format!(
            "bad metadata token target {:?} for a user type",
            bad
        )),
    }
    .map_err(|e| DLLError::CLI(scroll::Error::Custom(e)))
}

pub fn custom_modifier(src: CustomMod, ctx: &Context) -> Result<CustomTypeModifier> {
    Ok(match src {
        CustomMod::Required(t) => CustomTypeModifier::Required(user_type(t, ctx)?),
        CustomMod::Optional(t) => CustomTypeModifier::Optional(user_type(t, ctx)?),
    })
}

fn base_type_sig<T>(
    sig: Type,
    enclosing: impl Fn(Type, &Context) -> Result<T>,
    ctx: &Context,
) -> Result<BaseType<T>> {
    use Type::*;

    let generic_inst = |tok, types: Vec<Type>, kind| -> Result<BaseType<T>> {
        Ok(BaseType::Type(TypeSource::Generic(GenericInstantiation {
            base_kind: kind,
            base: user_type(tok, ctx)?,
            parameters: types
                .into_iter()
                .map(|t| enclosing(t, ctx))
                .collect::<Result<_>>()?,
        })))
    };

    Ok(match sig {
        Boolean => BaseType::Boolean,
        Char => BaseType::Char,
        Int8 => BaseType::Int8,
        UInt8 => BaseType::UInt8,
        Int16 => BaseType::Int16,
        UInt16 => BaseType::UInt16,
        Int32 => BaseType::Int32,
        UInt32 => BaseType::UInt32,
        Int64 => BaseType::Int64,
        UInt64 => BaseType::UInt64,
        Float32 => BaseType::Float32,
        Float64 => BaseType::Float64,
        IntPtr => BaseType::IntPtr,
        UIntPtr => BaseType::UIntPtr,
        Object => BaseType::Object,
        String => BaseType::String,
        Array(t, shape) => BaseType::Array(enclosing(*t, ctx)?, shape),
        SzArray(cmod, t) => BaseType::Vector(
            cmod.into_iter()
                .map(|c| custom_modifier(c, ctx))
                .collect::<Result<_>>()?,
            enclosing(*t, ctx)?,
        ),
        Ptr(cmod, pt) => BaseType::ValuePointer(
            cmod.into_iter()
                .map(|c| custom_modifier(c, ctx))
                .collect::<Result<_>>()?,
            match pt {
                Some(t) => Some(enclosing(*t, ctx)?),
                None => None,
            },
        ),
        Class(tok) | ValueType(tok) => BaseType::Type(TypeSource::User(user_type(tok, ctx)?)),
        FnPtr(s) => BaseType::FunctionPointer(maybe_unmanaged_method(*s, ctx)?),
        GenericInstClass(tok, types) => generic_inst(tok, types, InstantiationKind::Class)?,
        GenericInstValueType(tok, types) => generic_inst(tok, types, InstantiationKind::ValueType)?,
        bad => throw!("invalid type signature for base type {:?}", bad),
    })
}

pub fn member_type_sig(sig: Type, ctx: &Context) -> Result<MemberType> {
    Ok(match sig {
        Type::Var(idx) => MemberType::TypeGeneric(idx as usize),
        rest => MemberType::Base(Box::new(base_type_sig(rest, member_type_sig, ctx)?)),
    })
}

pub fn method_type_sig(sig: Type, ctx: &Context) -> Result<MethodType> {
    Ok(match sig {
        Type::Var(idx) => MethodType::TypeGeneric(idx as usize),
        Type::MVar(idx) => MethodType::MethodGeneric(idx as usize),
        rest => MethodType::Base(Box::new(base_type_sig(rest, method_type_sig, ctx)?)),
    })
}

// TODO: replace these macros with trait dispatch

macro_rules! def_type_idx {
    (fn $name:ident uses $sig:ident -> $t:ident) => {
        pub fn $name(idx: TypeDefOrRef, ctx: &Context) -> Result<$t> {
            match idx {
                TypeDefOrRef::TypeDef(i) => {
                    let idx = i - 1;
                    if idx < ctx.def_len {
                        Ok($t::Base(Box::new(BaseType::Type(TypeSource::User(
                            UserType::Definition(TypeIndex(idx)),
                        )))))
                    } else {
                        Err(format!(
                            "invalid type definition index {} while parsing a type",
                            idx
                        ))
                    }
                }
                TypeDefOrRef::TypeRef(i) => {
                    let idx = i - 1;
                    if idx < ctx.ref_len {
                        Ok($t::Base(Box::new(BaseType::Type(TypeSource::User(
                            UserType::Reference(TypeRefIndex(idx)),
                        )))))
                    } else {
                        Err(format!(
                            "invalid type reference index {} while parsing a type",
                            idx
                        ))
                    }
                }
                TypeDefOrRef::TypeSpec(i) => {
                    let idx = i - 1;
                    match ctx.specs.get(idx) {
                        Some(s) => Ok($sig(ctx.blobs.at_index(s.signature)?.pread(0)?, ctx)?),
                        None => Err(format!(
                            "invalid type spec index {} while parsing a type",
                            idx
                        )),
                    }
                }
                TypeDefOrRef::Null => Err("invalid null type index".to_string()),
            }
            .map_err(|e| DLLError::CLI(scroll::Error::Custom(e)))
        }
    };
}

def_type_idx!(fn member_type_idx uses member_type_sig -> MemberType);
def_type_idx!(fn method_type_idx uses method_type_sig -> MethodType);

macro_rules! def_idx_with_mod {
    (fn $name:ident uses ($idx:ident, $sig:ident) -> $t:ident) => {
        pub fn $name(idx: TypeDefOrRef, ctx: &Context) -> Result<(Vec<CustomTypeModifier>, $t)> {
            if let TypeDefOrRef::TypeSpec(i) = idx {
                let t_idx = i - 1;
                match ctx.specs.get(t_idx) {
                    Some(s) => {
                        let blob = ctx.blobs.at_index(s.signature)?;
                        let mut offset = 0;
                        let mods = all_custom_mods(blob, &mut offset);

                        Ok((
                            mods.into_iter()
                                .map(|c| custom_modifier(c, ctx))
                                .collect::<Result<_>>()?,
                            $sig(blob.pread(offset)?, ctx)?,
                        ))
                    }
                    None => throw!("invalid type spec index {} while parsing a type", t_idx),
                }
            } else {
                Ok((vec![], $idx(idx, ctx)?))
            }
        }
    };
}

def_idx_with_mod!(fn member_type_idx_mod uses (member_type_idx, member_type_sig) -> MemberType);
def_idx_with_mod!(fn method_type_idx_mod uses (method_type_idx, method_type_sig) -> MethodType);

macro_rules! type_source_error {
    ($bind:ident) => {
        throw!("invalid type source {:?}", $bind)
    };
}

macro_rules! def_type_source {
    (fn $name:ident uses $idx:ident -> $t:ident) => {
        pub fn $name(idx: TypeDefOrRef, ctx: &Context) -> Result<TypeSource<$t>> {
            match $idx(idx, ctx)? {
                $t::Base(b) => match *b {
                    BaseType::Type(s) => Ok(s),
                    bad => type_source_error!(bad),
                },
                bad => type_source_error!(bad),
            }
        }
    };
}

def_type_source!(fn member_type_source uses member_type_idx -> MemberType);
// def_type_source!(fn method_type_source uses method_type_idx -> MethodType);

pub fn parameter(p: Param, ctx: &Context) -> Result<signature::Parameter> {
    use signature::ParameterType::*;

    Ok(signature::Parameter(
        p.0.into_iter()
            .map(|c| custom_modifier(c, ctx))
            .collect::<Result<_>>()?,
        match p.1 {
            ParamType::Type(t) => Value(method_type_sig(t, ctx)?),
            ParamType::ByRef(t) => Ref(method_type_sig(t, ctx)?),
            ParamType::TypedByRef => TypedReference,
        },
    ))
}

macro_rules! def_method_sig {
    (fn $name:ident($type:ty) -> $sig:ident) => {
        pub fn $name(sig: $type, ctx: &Context) -> Result<signature::$sig> {
            use signature::*;
            Ok($sig {
                instance: sig.has_this,
                explicit_this: sig.explicit_this,
                calling_convention: sig.calling_convention,
                parameters: sig
                    .params
                    .into_iter()
                    .map(|p| parameter(p, ctx))
                    .collect::<Result<_>>()?,
                return_type: ReturnType(
                    sig.ret_type
                        .0
                        .into_iter()
                        .map(|c| custom_modifier(c, ctx))
                        .collect::<Result<_>>()?,
                    match sig.ret_type.1 {
                        RetTypeType::Type(t) => {
                            Some(ParameterType::Value(method_type_sig(t, ctx)?))
                        }
                        RetTypeType::ByRef(t) => Some(ParameterType::Ref(method_type_sig(t, ctx)?)),
                        RetTypeType::TypedByRef => Some(ParameterType::TypedReference),
                        RetTypeType::Void => None,
                    },
                ),
                varargs: None,
            })
        }
    };
}

def_method_sig!(fn managed_method(MethodDefSig) -> ManagedMethod);
def_method_sig!(fn maybe_unmanaged_method(StandAloneMethodSig) -> MaybeUnmanagedMethod);

pub fn type_token(tok: Token, ctx: &Context) -> Result<MethodType> {
    use TokenTarget::*;
    match tok.target {
        Table(Kind::TypeDef) => method_type_idx(TypeDefOrRef::TypeDef(tok.index), ctx),
        Table(Kind::TypeRef) => method_type_idx(TypeDefOrRef::TypeRef(tok.index), ctx),
        Table(Kind::TypeSpec) => method_type_idx(TypeDefOrRef::TypeSpec(tok.index), ctx),
        bad => throw!("invalid token {:?} for method type", bad),
    }
}

pub struct MethodContext<'r> {
    pub field_map: &'r HashMap<usize, usize>,
    pub field_indices: &'r [FieldIndex],
    pub method_specs: &'r [MethodSpec],
    pub method_indices: &'r [MethodIndex],
    pub method_map: &'r HashMap<usize, usize>,
}

pub fn user_method(idx: MethodDefOrRef, ctx: &MethodContext) -> Result<UserMethod> {
    Ok(match idx {
        MethodDefOrRef::MethodDef(i) => {
            let m_idx = i - 1;
            match ctx.method_indices.get(m_idx) {
                Some(&m) => UserMethod::Definition(m),
                None => throw!("invalid method index {} for user method", m_idx),
            }
        }
        MethodDefOrRef::MemberRef(i) => {
            let r_idx = i - 1;
            match ctx.method_map.get(&r_idx) {
                Some(&m_idx) => UserMethod::Reference(MethodRefIndex(m_idx)),
                None => throw!("invalid member reference index {} for user method", r_idx),
            }
        }
        MethodDefOrRef::Null => throw!("invalid null index for user method"),
    })
}

fn user_method_token(tok: Token, ctx: &MethodContext) -> Result<UserMethod> {
    use TokenTarget::*;
    match tok.target {
        Table(Kind::MethodDef) => user_method(MethodDefOrRef::MethodDef(tok.index), ctx),
        Table(Kind::MemberRef) => user_method(MethodDefOrRef::MemberRef(tok.index), ctx),
        bad => throw!("invalid token {:?} for user method", bad),
    }
}

fn method_source<'r, 'data>(
    tok: Token,
    ctx: &Context<'r, 'data>,
    m_ctx: &MethodContext<'r>,
) -> Result<MethodSource> {
    use TokenTarget::*;
    Ok(match tok.target {
        Table(Kind::MethodSpec) => {
            let idx = tok.index - 1;
            match m_ctx.method_specs.get(idx) {
                Some(m) => MethodSource::Generic(GenericMethodInstantiation {
                    base: user_method(m.method, m_ctx)?,
                    parameters: ctx
                        .blobs
                        .at_index(m.instantiation)?
                        .pread::<MethodSpecSig>(0)?
                        .0
                        .into_iter()
                        .map(|t| method_type_sig(t, ctx))
                        .collect::<Result<_>>()?,
                }),
                None => throw!("invalid method spec index {} for method source", idx),
            }
        }
        _ => MethodSource::User(user_method_token(tok, m_ctx)?),
    })
}

fn field_source(tok: Token, ctx: &MethodContext) -> Result<FieldSource> {
    use TokenTarget::*;
    let idx = tok.index - 1;
    Ok(match tok.target {
        Table(Kind::Field) => match ctx.field_indices.get(idx) {
            Some(&i) => FieldSource::Definition(i),
            None => throw!("bad field index {} for field source", idx),
        },
        Table(Kind::MemberRef) => match ctx.field_map.get(&idx) {
            Some(&i) => FieldSource::Reference(FieldRefIndex(i)),
            None => throw!("bad member reference index {} for field source", idx),
        },
        bad => throw!("invalid token {:?} for field source", bad),
    })
}

pub fn instruction<'r, 'data>(
    instruction: il::Instruction,
    index: usize,
    all_offsets: &'r [usize],
    ctx: &Context<'r, 'data>,
    m_ctx: &MethodContext<'r>,
) -> Result<resolved::il::Instruction> {
    use il::Instruction::*;
    use resolved::il::*;

    macro_rules! alignment {
        ($i:expr) => {
            Some(match $i {
                1 => Alignment::Byte,
                2 => Alignment::Double,
                4 => Alignment::Quad,
                other => throw!("invalid {}-byte alignment specification", other),
            })
        };
    }

    macro_rules! call {
        ($t:ident | tailcall $tail:expr) => {
            Instruction::Call {
                tail_call: $tail,
                method: method_source($t, ctx, m_ctx)?,
            }
        };
    }

    macro_rules! calli {
        ($t:ident | tailcall $tail:expr) => {
            match $t.target {
                TokenTarget::Table(Kind::StandAloneSig) => {
                    let idx = $t.index - 1;
                    match ctx.sigs.get(idx) {
                        Some(s) => {
                            let sig: StandAloneMethodSig =
                                ctx.blobs.at_index(s.signature)?.pread(0)?;
                            let mut parsed = maybe_unmanaged_method(sig.clone(), ctx)?;
                            if matches!(
                                sig.calling_convention,
                                StandAloneCallingConvention::Vararg
                                    | StandAloneCallingConvention::Cdecl
                            ) {
                                parsed.varargs = Some(
                                    sig.varargs
                                        .into_iter()
                                        .map(|p| parameter(p, ctx))
                                        .collect::<Result<_>>()?,
                                );
                            }
                            Instruction::CallIndirect {
                                tail_call: $tail,
                                signature: parsed,
                            }
                        }
                        None => throw!("invalid signature index {} for calli instruction", idx),
                    }
                }
                bad => throw!("invalid metadata token {:?} for calli instruction", bad),
            }
        };
    }

    macro_rules! callvirt {
        ($token:ident | constraint $const:expr, nullcheck $null:expr, tailcall $tail:expr) => {
            Instruction::CallVirtual {
                constraint: $const,
                skip_null_check: $null,
                tail_call: $tail,
                method: method_source($token, ctx, m_ctx)?,
            }
        };
    }

    macro_rules! castclass {
        ($token:ident | typecheck $check:expr) => {
            Instruction::CastClass {
                skip_type_check: $check,
                cast_type: type_token($token, ctx)?,
            }
        };
    }

    macro_rules! cpblk {
        (unaligned $align:expr, volatile $vol:expr) => {
            Instruction::CopyMemoryBlock {
                unaligned: $align,
                volatile: $vol,
            }
        };
    }

    macro_rules! initblk {
        (unaligned $align:expr, volatile $vol:expr) => {
            Instruction::InitializeMemoryBlock {
                unaligned: $align,
                volatile: $vol,
            }
        };
    }

    macro_rules! ldelem {
        ($t:ident | rangecheck $range:expr, nullcheck $null:expr) => {
            Instruction::LoadElement {
                skip_range_check: $range,
                skip_null_check: $null,
                element_type: type_token($t, ctx)?,
            }
        };
    }

    macro_rules! ldelema {
        ($t:ident | typecheck $type:expr, rangecheck $range:expr, nullcheck $null:expr, readonly $read:expr) => {
            Instruction::LoadElementAddress {
                skip_type_check: $type,
                skip_range_check: $range,
                skip_null_check: $null,
                readonly: $read,
                element_type: type_token($t, ctx)?,
            }
        };
    }

    macro_rules! ldfld {
        ($t:ident | nullcheck $null:expr, unaligned $align:expr, volatile $vol:expr) => {
            Instruction::LoadField {
                skip_null_check: $null,
                unaligned: $align,
                volatile: $vol,
                field: field_source($t, m_ctx)?,
            }
        };
    }

    macro_rules! ldobj {
        ($t:ident | unaligned $align:expr, volatile $vol:expr) => {
            Instruction::LoadObject {
                unaligned: $align,
                volatile: $vol,
                object_type: type_token($t, ctx)?,
            }
        };
    }

    macro_rules! ldsfld {
        ($t:ident | volatile $vol:expr) => {
            Instruction::LoadStaticField {
                volatile: $vol,
                field: field_source($t, m_ctx)?,
            }
        };
    }

    macro_rules! ldvirtftn {
        ($t:ident | nullcheck $null:expr) => {
            Instruction::LoadVirtualMethodPointer {
                skip_null_check: $null,
                method: method_source($t, ctx, m_ctx)?,
            }
        };
    }

    macro_rules! load_indirect {
        ($t:ident | unaligned $align:expr, volatile $vol:expr) => {
            Instruction::LoadIndirect {
                unaligned: $align,
                volatile: $vol,
                value_type: LoadType::$t,
            }
        };
    }

    macro_rules! load_primitive {
        ($t:ident) => {
            Instruction::LoadElementPrimitive {
                skip_range_check: false,
                skip_null_check: false,
                element_type: LoadType::$t,
            }
        };
        ($t:ident | flags $f:expr) => {
            Instruction::LoadElementPrimitive {
                skip_range_check: check_bitmask!($f, 0x2),
                skip_null_check: check_bitmask!($f, 0x4),
                element_type: LoadType::$t,
            }
        };
    }

    macro_rules! stelem {
        ($t:ident | typecheck $type:expr, rangecheck $range:expr, nullcheck $null:expr) => {
            Instruction::StoreElement {
                skip_type_check: $type,
                skip_range_check: $range,
                skip_null_check: $null,
                element_type: type_token($t, ctx)?,
            }
        };
    }

    macro_rules! stfld {
        ($t:ident | nullcheck $null:expr, unaligned $align:expr, volatile $vol:expr) => {
            Instruction::StoreField {
                skip_null_check: $null,
                unaligned: $align,
                volatile: $vol,
                field: field_source($t, m_ctx)?,
            }
        };
    }

    macro_rules! stsfld {
        ($t:ident | volatile $vol:expr) => {
            Instruction::StoreStaticField {
                volatile: $vol,
                field: field_source($t, m_ctx)?,
            }
        };
    }

    macro_rules! stobj {
        ($t:ident | unaligned $align:expr, volatile $vol:expr) => {
            Instruction::StoreObject {
                unaligned: $align,
                volatile: $vol,
                object_type: type_token($t, ctx)?,
            }
        };
    }

    macro_rules! store_indirect {
        ($t:ident | unaligned $align:expr, volatile $vol:expr) => {
            Instruction::StoreIndirect {
                unaligned: $align,
                volatile: $vol,
                value_type: StoreType::$t,
            }
        };
    }

    macro_rules! store_primitive {
        ($t:ident) => {
            Instruction::StoreElementPrimitive {
                skip_type_check: false,
                skip_range_check: false,
                skip_null_check: false,
                element_type: StoreType::$t,
            }
        };
        ($t:ident | flags $f:expr) => {
            Instruction::StoreElementPrimitive {
                skip_type_check: check_bitmask!($f, 0x1),
                skip_range_check: check_bitmask!($f, 0x2),
                skip_null_check: check_bitmask!($f, 0x4),
                element_type: StoreType::$t,
            }
        };
    }

    macro_rules! unbox {
        ($t:ident | typecheck $type:expr) => {
            Instruction::UnboxIntoAddress {
                skip_type_check: $type,
                unbox_type: type_token($t, ctx)?,
            }
        };
    }

    let offset = all_offsets[index];
    let bytesize = instruction.bytesize();

    let convert_offset = |i: i32| -> Result<usize> {
        ((offset + bytesize) as i32 + i)
            .try_into()
            .ok()
            .and_then(|other: usize| all_offsets.iter().position(|&o| o == other))
            .ok_or_else(|| {
                DLLError::CLI(scroll::Error::Custom(format!(
                    "invalid instruction offset {}",
                    i
                )))
            })
    };

    Ok(match instruction {
        Add => Instruction::Add,
        AddOvf => Instruction::AddOverflow(NumberSign::Signed),
        AddOvfUn => Instruction::AddOverflow(NumberSign::Unsigned),
        And => Instruction::And,
        Arglist => Instruction::ArgumentList,
        Beq(i) => Instruction::BranchEqual(convert_offset(i)?),
        BeqS(i) => Instruction::BranchEqual(convert_offset(i as i32)?),
        Bge(i) => Instruction::BranchGreaterOrEqual(NumberSign::Signed, convert_offset(i)?),
        BgeS(i) => Instruction::BranchGreaterOrEqual(NumberSign::Signed, convert_offset(i as i32)?),
        BgeUn(i) => Instruction::BranchGreaterOrEqual(NumberSign::Unsigned, convert_offset(i)?),
        BgeUnS(i) => {
            Instruction::BranchGreaterOrEqual(NumberSign::Unsigned, convert_offset(i as i32)?)
        }
        Bgt(i) => Instruction::BranchGreater(NumberSign::Signed, convert_offset(i)?),
        BgtS(i) => Instruction::BranchGreater(NumberSign::Signed, convert_offset(i as i32)?),
        BgtUn(i) => Instruction::BranchGreater(NumberSign::Unsigned, convert_offset(i)?),
        BgtUnS(i) => Instruction::BranchGreater(NumberSign::Unsigned, convert_offset(i as i32)?),
        Ble(i) => Instruction::BranchLessOrEqual(NumberSign::Signed, convert_offset(i)?),
        BleS(i) => Instruction::BranchLessOrEqual(NumberSign::Signed, convert_offset(i as i32)?),
        BleUn(i) => Instruction::BranchLessOrEqual(NumberSign::Unsigned, convert_offset(i)?),
        BleUnS(i) => {
            Instruction::BranchLessOrEqual(NumberSign::Unsigned, convert_offset(i as i32)?)
        }
        Blt(i) => Instruction::BranchLess(NumberSign::Signed, convert_offset(i)?),
        BltS(i) => Instruction::BranchLess(NumberSign::Signed, convert_offset(i as i32)?),
        BltUn(i) => Instruction::BranchLess(NumberSign::Unsigned, convert_offset(i)?),
        BltUnS(i) => Instruction::BranchLess(NumberSign::Unsigned, convert_offset(i as i32)?),
        BneUn(i) => Instruction::BranchNotEqual(convert_offset(i)?),
        BneUnS(i) => Instruction::BranchNotEqual(convert_offset(i as i32)?),
        Box(t) => Instruction::Box(type_token(t, ctx)?),
        Br(i) => Instruction::Branch(convert_offset(i)?),
        BrS(i) => Instruction::Branch(convert_offset(i as i32)?),
        Break => Instruction::Breakpoint,
        Brfalse(i) => Instruction::BranchFalsy(convert_offset(i)?),
        BrfalseS(i) => Instruction::BranchFalsy(convert_offset(i as i32)?),
        Brtrue(i) => Instruction::BranchTruthy(convert_offset(i)?),
        BrtrueS(i) => Instruction::BranchTruthy(convert_offset(i as i32)?),
        Call(t) => call!(t | tailcall false),
        Calli(t) => calli!(t | tailcall false),
        Callvirt(t) => callvirt!(t | constraint None, nullcheck false, tailcall false),
        Castclass(t) => castclass!(t | typecheck false),
        Ceq => Instruction::CompareEqual,
        Cgt => Instruction::CompareGreater(NumberSign::Signed),
        CgtUn => Instruction::CompareGreater(NumberSign::Unsigned),
        Ckfinite => Instruction::CheckFinite,
        Clt => Instruction::CompareLess(NumberSign::Signed),
        CltUn => Instruction::CompareLess(NumberSign::Unsigned),
        ConvI => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::IntPtr,
            NumberSign::Signed,
        ),
        ConvI1 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::Int8,
            NumberSign::Signed,
        ),
        ConvI2 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::Int16,
            NumberSign::Signed,
        ),
        ConvI4 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::Int32,
            NumberSign::Signed,
        ),
        ConvI8 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::Int64,
            NumberSign::Signed,
        ),
        ConvOvfI => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::IntPtr,
            NumberSign::Signed,
        ),
        ConvOvfI1 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int8,
            NumberSign::Signed,
        ),
        ConvOvfI1Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int8,
            NumberSign::Unsigned,
        ),
        ConvOvfI2 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int16,
            NumberSign::Signed,
        ),
        ConvOvfI2Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int16,
            NumberSign::Unsigned,
        ),
        ConvOvfI4 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int32,
            NumberSign::Signed,
        ),
        ConvOvfI4Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int32,
            NumberSign::Unsigned,
        ),
        ConvOvfI8 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int64,
            NumberSign::Signed,
        ),
        ConvOvfI8Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::Int64,
            NumberSign::Unsigned,
        ),
        ConvOvfIUn => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::IntPtr,
            NumberSign::Unsigned,
        ),
        ConvOvfU => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UIntPtr,
            NumberSign::Signed,
        ),
        ConvOvfU1 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt8,
            NumberSign::Signed,
        ),
        ConvOvfU1Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt8,
            NumberSign::Unsigned,
        ),
        ConvOvfU2 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt16,
            NumberSign::Signed,
        ),
        ConvOvfU2Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt16,
            NumberSign::Unsigned,
        ),
        ConvOvfU4 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt32,
            NumberSign::Signed,
        ),
        ConvOvfU4Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt32,
            NumberSign::Unsigned,
        ),
        ConvOvfU8 => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt64,
            NumberSign::Signed,
        ),
        ConvOvfU8Un => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UInt64,
            NumberSign::Unsigned,
        ),
        ConvOvfUUn => Instruction::Convert(
            OverflowDetection::Check,
            ConversionType::UIntPtr,
            NumberSign::Unsigned,
        ),
        ConvR4 => Instruction::ConvertFloat32,
        ConvR8 => Instruction::ConvertFloat64,
        ConvRUn => Instruction::ConvertUnsignedToFloat,
        ConvU => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::UIntPtr,
            NumberSign::Signed,
        ),
        ConvU1 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::UInt8,
            NumberSign::Signed,
        ),
        ConvU2 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::UInt16,
            NumberSign::Signed,
        ),
        ConvU4 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::UInt32,
            NumberSign::Signed,
        ),
        ConvU8 => Instruction::Convert(
            OverflowDetection::NoCheck,
            ConversionType::UInt64,
            NumberSign::Signed,
        ),
        Cpblk => cpblk!(unaligned None, volatile false),
        Cpobj(t) => Instruction::CopyObject(type_token(t, ctx)?),
        Div => Instruction::Divide(NumberSign::Signed),
        DivUn => Instruction::Divide(NumberSign::Unsigned),
        Dup => Instruction::Duplicate,
        Endfilter => Instruction::EndFilter,
        Endfinally => Instruction::EndFinally,
        Initblk => initblk!(unaligned None, volatile false),
        Initobj(t) => Instruction::InitializeForObject(type_token(t, ctx)?),
        Isinst(t) => Instruction::IsInstance(type_token(t, ctx)?),
        Jmp(t) => Instruction::Jump(method_source(t, ctx, m_ctx)?),
        Ldarg(i) => Instruction::LoadArgument(i),
        Ldarg0 => Instruction::LoadArgument(0),
        Ldarg1 => Instruction::LoadArgument(1),
        Ldarg2 => Instruction::LoadArgument(2),
        Ldarg3 => Instruction::LoadArgument(3),
        LdargS(i) => Instruction::LoadArgument(i as u16),
        Ldarga(i) => Instruction::LoadArgumentAddress(i),
        LdargaS(i) => Instruction::LoadArgumentAddress(i as u16),
        LdcI4(c) => Instruction::LoadConstantInt32(c),
        LdcI40 => Instruction::LoadConstantInt32(0),
        LdcI41 => Instruction::LoadConstantInt32(1),
        LdcI42 => Instruction::LoadConstantInt32(2),
        LdcI43 => Instruction::LoadConstantInt32(3),
        LdcI44 => Instruction::LoadConstantInt32(4),
        LdcI45 => Instruction::LoadConstantInt32(5),
        LdcI46 => Instruction::LoadConstantInt32(6),
        LdcI47 => Instruction::LoadConstantInt32(7),
        LdcI48 => Instruction::LoadConstantInt32(8),
        LdcI4M1 => Instruction::LoadConstantInt32(-1),
        LdcI4S(c) => Instruction::LoadConstantInt32(c as i32),
        LdcI8(c) => Instruction::LoadConstantInt64(c),
        LdcR4(c) => Instruction::LoadConstantFloat32(c),
        LdcR8(c) => Instruction::LoadConstantFloat64(c),
        Ldelem(t) => ldelem!(t | rangecheck false, nullcheck false),
        LdelemI => load_primitive!(IntPtr),
        LdelemI1 => load_primitive!(Int8),
        LdelemI2 => load_primitive!(Int16),
        LdelemI4 => load_primitive!(Int32),
        LdelemI8 => load_primitive!(Int64),
        LdelemR4 => load_primitive!(Float32),
        LdelemR8 => load_primitive!(Float64),
        LdelemRef => load_primitive!(Object),
        LdelemU1 => load_primitive!(UInt8),
        LdelemU2 => load_primitive!(UInt16),
        LdelemU4 => load_primitive!(UInt32),
        Ldelema(t) => {
            ldelema!(t | typecheck false, rangecheck false, nullcheck false, readonly false)
        }
        Ldfld(t) => ldfld!(t | nullcheck false, unaligned None, volatile false),
        Ldflda(t) => Instruction::LoadFieldAddress(field_source(t, m_ctx)?),
        Ldftn(t) => Instruction::LoadMethodPointer(method_source(t, ctx, m_ctx)?),
        LdindI => load_indirect!(IntPtr | unaligned None, volatile false),
        LdindI1 => load_indirect!(Int8 | unaligned None, volatile false),
        LdindI2 => load_indirect!(Int16 | unaligned None, volatile false),
        LdindI4 => load_indirect!(Int32 | unaligned None, volatile false),
        LdindI8 => load_indirect!(Int64 | unaligned None, volatile false),
        LdindR4 => load_indirect!(Float32 | unaligned None, volatile false),
        LdindR8 => load_indirect!(Float64 | unaligned None, volatile false),
        LdindRef => load_indirect!(Object | unaligned None, volatile false),
        LdindU1 => load_indirect!(UInt8 | unaligned None, volatile false),
        LdindU2 => load_indirect!(UInt16 | unaligned None, volatile false),
        LdindU4 => load_indirect!(UInt32 | unaligned None, volatile false),
        Ldlen => Instruction::LoadLength,
        Ldloc(i) => Instruction::LoadLocalVariable(i),
        Ldloc0 => Instruction::LoadLocalVariable(0),
        Ldloc1 => Instruction::LoadLocalVariable(1),
        Ldloc2 => Instruction::LoadLocalVariable(2),
        Ldloc3 => Instruction::LoadLocalVariable(3),
        LdlocS(i) => Instruction::LoadLocalVariable(i as u16),
        Ldloca(i) => Instruction::LoadLocalVariableAddress(i),
        LdlocaS(i) => Instruction::LoadLocalVariableAddress(i as u16),
        Ldnull => Instruction::LoadNull,
        Ldobj(t) => ldobj!(t | unaligned None, volatile false),
        Ldsfld(t) => ldsfld!(t | volatile false),
        Ldsflda(t) => Instruction::LoadStaticFieldAddress(field_source(t, m_ctx)?),
        Ldstr(t) => match t.target {
            TokenTarget::UserString => Instruction::LoadString(ctx.userstrings.at_index(t.index)?),
            bad => throw!("invalid metadata token {:?} for ldstr instruction", bad),
        },
        Ldtoken(t) => {
            use TokenTarget::*;
            let idx = t.index - 1;
            match t.target {
                Table(Kind::MethodDef | Kind::MethodSpec) => {
                    Instruction::LoadTokenMethod(method_source(t, ctx, m_ctx)?)
                }
                Table(Kind::TypeDef | Kind::TypeRef | Kind::TypeSpec) => {
                    Instruction::LoadTokenType(type_token(t, ctx)?)
                }
                Table(Kind::Field) => Instruction::LoadTokenField(field_source(t, m_ctx)?),
                Table(Kind::MemberRef) => {
                    if m_ctx.field_map.contains_key(&idx) {
                        Instruction::LoadTokenField(field_source(t, m_ctx)?)
                    } else {
                        Instruction::LoadTokenMethod(method_source(t, ctx, m_ctx)?)
                    }
                }
                bad => throw!("invalid metadata token {:?} for ldtoken instruction", bad),
            }
        }
        Ldvirtftn(t) => ldvirtftn!(t | nullcheck false),
        Leave(i) => Instruction::Leave(convert_offset(i)?),
        LeaveS(i) => Instruction::Leave(convert_offset(i as i32)?),
        Localloc => Instruction::LocalMemoryAllocate,
        Mkrefany(t) => Instruction::MakeTypedReference(type_token(t, ctx)?),
        Mul => Instruction::Multiply,
        MulOvf => Instruction::MultiplyOverflow(NumberSign::Signed),
        MulOvfUn => Instruction::MultiplyOverflow(NumberSign::Unsigned),
        Neg => Instruction::Negate,
        Newarr(t) => Instruction::NewArray(type_token(t, ctx)?),
        Newobj(t) => Instruction::NewObject(user_method_token(t, m_ctx)?),
        Nop => Instruction::NoOperation,
        Not => Instruction::Not,
        Or => Instruction::Or,
        Pop => Instruction::Pop,
        Refanytype => Instruction::ReadTypedReferenceType,
        Refanyval(t) => Instruction::ReadTypedReferenceValue(type_token(t, ctx)?),
        Rem => Instruction::Remainder(NumberSign::Signed),
        RemUn => Instruction::Remainder(NumberSign::Unsigned),
        Ret => Instruction::Return,
        Rethrow => Instruction::Rethrow,
        Shl => Instruction::ShiftLeft,
        Shr => Instruction::ShiftRight(NumberSign::Signed),
        ShrUn => Instruction::ShiftRight(NumberSign::Unsigned),
        Sizeof(t) => Instruction::Sizeof(type_token(t, ctx)?),
        Starg(i) => Instruction::StoreArgument(i),
        StargS(i) => Instruction::StoreArgument(i as u16),
        Stelem(t) => stelem!(t | typecheck false, rangecheck false, nullcheck false),
        StelemI => store_primitive!(IntPtr),
        StelemI1 => store_primitive!(Int8),
        StelemI2 => store_primitive!(Int16),
        StelemI4 => store_primitive!(Int32),
        StelemI8 => store_primitive!(Int64),
        StelemR4 => store_primitive!(Float32),
        StelemR8 => store_primitive!(Float64),
        StelemRef => store_primitive!(Object),
        Stfld(t) => stfld!(t | nullcheck false, unaligned None, volatile false),
        StindI => store_indirect!(IntPtr | unaligned None, volatile false),
        StindI1 => store_indirect!(Int8 | unaligned None, volatile false),
        StindI2 => store_indirect!(Int16 | unaligned None, volatile false),
        StindI4 => store_indirect!(Int32 | unaligned None, volatile false),
        StindI8 => store_indirect!(Int64 | unaligned None, volatile false),
        StindR4 => store_indirect!(Float32 | unaligned None, volatile false),
        StindR8 => store_indirect!(Float64 | unaligned None, volatile false),
        StindRef => store_indirect!(Object | unaligned None, volatile false),
        Stloc(i) => Instruction::StoreLocal(i),
        Stloc0 => Instruction::StoreLocal(0),
        Stloc1 => Instruction::StoreLocal(1),
        Stloc2 => Instruction::StoreLocal(2),
        Stloc3 => Instruction::StoreLocal(3),
        StlocS(i) => Instruction::StoreLocal(i as u16),
        Stobj(t) => stobj!(t | unaligned None, volatile false),
        Stsfld(t) => stsfld!(t | volatile false),
        Sub => Instruction::Subtract,
        SubOvf => Instruction::SubtractOverflow(NumberSign::Signed),
        SubOvfUn => Instruction::SubtractOverflow(NumberSign::Unsigned),
        Switch(v) => Instruction::Switch(v.into_iter().map(convert_offset).collect::<Result<_>>()?),
        Throw => Instruction::Throw,
        Unbox(t) => unbox!(t | typecheck false),
        UnboxAny(t) => Instruction::UnboxIntoValue(type_token(t, ctx)?),
        Xor => Instruction::Xor,
        ConstrainedCallvirt(c, t) => {
            callvirt!(t | constraint Some(type_token(c, ctx)?), nullcheck false, tailcall false)
        }
        NocheckCallvirt(flags, t) => {
            callvirt!(t | constraint None, nullcheck check_bitmask!(flags, 0x4), tailcall false)
        }
        NocheckCastclass(flags, t) => castclass!(t | typecheck check_bitmask!(flags, 0x1)),
        NocheckLdelem(flags, t) => {
            ldelem!(t | rangecheck check_bitmask!(flags, 0x2), nullcheck check_bitmask!(flags, 0x4))
        }
        NocheckLdelemI(f) => load_primitive!(IntPtr | flags f),
        NocheckLdelemI1(f) => load_primitive!(Int8 | flags f),
        NocheckLdelemI2(f) => load_primitive!(Int16 | flags f),
        NocheckLdelemI4(f) => load_primitive!(Int32 | flags f),
        NocheckLdelemI8(f) => load_primitive!(Int64 | flags f),
        NocheckLdelemR4(f) => load_primitive!(Float32 | flags f),
        NocheckLdelemR8(f) => load_primitive!(Float64 | flags f),
        NocheckLdelemRef(f) => load_primitive!(Object | flags f),
        NocheckLdelemU1(f) => load_primitive!(UInt8 | flags f),
        NocheckLdelemU2(f) => load_primitive!(UInt16 | flags f),
        NocheckLdelemU4(f) => load_primitive!(UInt32 | flags f),
        NocheckLdelema(flags, t) => ldelema!(t |
            typecheck check_bitmask!(flags, 0x1),
            rangecheck check_bitmask!(flags, 0x2),
            nullcheck check_bitmask!(flags, 0x4),
            readonly false
        ),
        NocheckLdfld(flags, t) => {
            ldfld!(t | nullcheck check_bitmask!(flags, 0x4), unaligned None, volatile false)
        }
        NocheckLdvirtftn(flags, t) => ldvirtftn!(t | nullcheck check_bitmask!(flags, 0x4)),
        NocheckStelem(flags, t) => stelem!(t |
            typecheck check_bitmask!(flags, 0x1),
            rangecheck check_bitmask!(flags, 0x2),
            nullcheck check_bitmask!(flags, 0x4)
        ),
        NocheckStelemI(f) => store_primitive!(IntPtr | flags f),
        NocheckStelemI1(f) => store_primitive!(Int8 | flags f),
        NocheckStelemI2(f) => store_primitive!(Int16 | flags f),
        NocheckStelemI4(f) => store_primitive!(Int32 | flags f),
        NocheckStelemI8(f) => store_primitive!(Int64 | flags f),
        NocheckStelemR4(f) => store_primitive!(Float32 | flags f),
        NocheckStelemR8(f) => store_primitive!(Float64 | flags f),
        NocheckStelemRef(f) => store_primitive!(Object | flags f),
        NocheckStfld(flags, t) => {
            stfld!(t | nullcheck check_bitmask!(flags, 0x4), unaligned None, volatile false)
        }
        NocheckUnbox(flags, t) => unbox!(t | typecheck check_bitmask!(flags, 0x1)),
        ReadonlyLdelema(t) => ldelema!(t |
            typecheck false,
            rangecheck false,
            nullcheck false,
            readonly true
        ),
        TailCall(t) => call!(t | tailcall true),
        TailCalli(t) => calli!(t | tailcall true),
        TailCallvirt(t) => callvirt!(t | constraint None, nullcheck false, tailcall true),
        UnalignedCpblk(a) => cpblk!(unaligned alignment!(a), volatile false),
        UnalignedInitblk(a) => initblk!(unaligned alignment!(a), volatile false),
        UnalignedLdfld(a, t) => {
            ldfld!(t | nullcheck false, unaligned alignment!(a), volatile false)
        }
        UnalignedLdindI(a) => load_indirect!(IntPtr | unaligned alignment!(a), volatile false),
        UnalignedLdindI1(a) => load_indirect!(Int8 | unaligned alignment!(a), volatile false),
        UnalignedLdindI2(a) => load_indirect!(Int16 | unaligned alignment!(a), volatile false),
        UnalignedLdindI4(a) => load_indirect!(Int32 | unaligned alignment!(a), volatile false),
        UnalignedLdindI8(a) => load_indirect!(Int64 | unaligned alignment!(a), volatile false),
        UnalignedLdindR4(a) => load_indirect!(Float32 | unaligned alignment!(a), volatile false),
        UnalignedLdindR8(a) => load_indirect!(Float64 | unaligned alignment!(a), volatile false),
        UnalignedLdindRef(a) => load_indirect!(Object | unaligned alignment!(a), volatile false),
        UnalignedLdindU1(a) => load_indirect!(UInt8 | unaligned alignment!(a), volatile false),
        UnalignedLdindU2(a) => load_indirect!(UInt16 | unaligned alignment!(a), volatile false),
        UnalignedLdindU4(a) => load_indirect!(UInt32 | unaligned alignment!(a), volatile false),
        UnalignedLdobj(a, t) => ldobj!(t | unaligned alignment!(a), volatile false),
        UnalignedStfld(a, t) => {
            stfld!(t | nullcheck false, unaligned alignment!(a), volatile false)
        }
        UnalignedStindI(a) => store_indirect!(IntPtr | unaligned alignment!(a), volatile false),
        UnalignedStindI1(a) => store_indirect!(Int8 | unaligned alignment!(a), volatile false),
        UnalignedStindI2(a) => store_indirect!(Int16 | unaligned alignment!(a), volatile false),
        UnalignedStindI4(a) => store_indirect!(Int32 | unaligned alignment!(a), volatile false),
        UnalignedStindI8(a) => store_indirect!(Int64 | unaligned alignment!(a), volatile false),
        UnalignedStindR4(a) => store_indirect!(Float32 | unaligned alignment!(a), volatile false),
        UnalignedStindR8(a) => store_indirect!(Float64 | unaligned alignment!(a), volatile false),
        UnalignedStindRef(a) => store_indirect!(Object | unaligned alignment!(a), volatile false),
        UnalignedStobj(a, t) => stobj!(t | unaligned alignment!(a), volatile false),
        VolatileCpblk => cpblk!(unaligned None, volatile true),
        VolatileInitblk => initblk!(unaligned None, volatile true),
        VolatileLdfld(t) => ldfld!(t | nullcheck false, unaligned None, volatile true),
        VolatileLdindI => load_indirect!(IntPtr | unaligned None, volatile true),
        VolatileLdindI1 => load_indirect!(Int8 | unaligned None, volatile true),
        VolatileLdindI2 => load_indirect!(Int16 | unaligned None, volatile true),
        VolatileLdindI4 => load_indirect!(Int32 | unaligned None, volatile true),
        VolatileLdindI8 => load_indirect!(Int64 | unaligned None, volatile true),
        VolatileLdindR4 => load_indirect!(Float32 | unaligned None, volatile true),
        VolatileLdindR8 => load_indirect!(Float64 | unaligned None, volatile true),
        VolatileLdindRef => load_indirect!(Object | unaligned None, volatile true),
        VolatileLdindU1 => load_indirect!(UInt8 | unaligned None, volatile true),
        VolatileLdindU2 => load_indirect!(UInt16 | unaligned None, volatile true),
        VolatileLdindU4 => load_indirect!(UInt32 | unaligned None, volatile true),
        VolatileLdobj(t) => ldobj!(t | unaligned None, volatile true),
        VolatileLdsfld(t) => ldsfld!(t | volatile true),
        VolatileStfld(t) => stfld!(t | nullcheck false, unaligned None, volatile true),
        VolatileStindI => store_indirect!(IntPtr | unaligned None, volatile true),
        VolatileStindI1 => store_indirect!(Int8 | unaligned None, volatile true),
        VolatileStindI2 => store_indirect!(Int16 | unaligned None, volatile true),
        VolatileStindI4 => store_indirect!(Int32 | unaligned None, volatile true),
        VolatileStindI8 => store_indirect!(Int64 | unaligned None, volatile true),
        VolatileStindR4 => store_indirect!(Float32 | unaligned None, volatile true),
        VolatileStindR8 => store_indirect!(Float64 | unaligned None, volatile true),
        VolatileStindRef => store_indirect!(Object | unaligned None, volatile true),
        VolatileStobj(t) => stobj!(t | unaligned None, volatile true),
        VolatileStsfld(t) => stsfld!(t | volatile true),
        UnalignedVolatileCpblk(a) | VolatileUnalignedCpblk(a) => {
            cpblk!(unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileInitblk(a) | VolatileUnalignedInitblk(a) => {
            initblk!(unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdfld(a, t) | VolatileUnalignedLdfld(a, t) => {
            ldfld!(t | nullcheck false, unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindI(a) | VolatileUnalignedLdindI(a) => {
            load_indirect!(IntPtr | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindI1(a) | VolatileUnalignedLdindI1(a) => {
            load_indirect!(Int8 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindI2(a) | VolatileUnalignedLdindI2(a) => {
            load_indirect!(Int16 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindI4(a) | VolatileUnalignedLdindI4(a) => {
            load_indirect!(Int32 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindI8(a) | VolatileUnalignedLdindI8(a) => {
            load_indirect!(Int64 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindR4(a) | VolatileUnalignedLdindR4(a) => {
            load_indirect!(Float32 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindR8(a) | VolatileUnalignedLdindR8(a) => {
            load_indirect!(Float64 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindRef(a) | VolatileUnalignedLdindRef(a) => {
            load_indirect!(Object | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindU1(a) | VolatileUnalignedLdindU1(a) => {
            load_indirect!(UInt8 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindU2(a) | VolatileUnalignedLdindU2(a) => {
            load_indirect!(UInt16 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdindU4(a) | VolatileUnalignedLdindU4(a) => {
            load_indirect!(UInt32 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileLdobj(a, t) | VolatileUnalignedLdobj(a, t) => {
            ldobj!(t | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStfld(a, t) | VolatileUnalignedStfld(a, t) => {
            stfld!(t | nullcheck false, unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindI(a) | VolatileUnalignedStindI(a) => {
            store_indirect!(IntPtr | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindI1(a) | VolatileUnalignedStindI1(a) => {
            store_indirect!(Int8 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindI2(a) | VolatileUnalignedStindI2(a) => {
            store_indirect!(Int16 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindI4(a) | VolatileUnalignedStindI4(a) => {
            store_indirect!(Int32 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindI8(a) | VolatileUnalignedStindI8(a) => {
            store_indirect!(Int64 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindR4(a) | VolatileUnalignedStindR4(a) => {
            store_indirect!(Float32 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindR8(a) | VolatileUnalignedStindR8(a) => {
            store_indirect!(Float64 | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStindRef(a) | VolatileUnalignedStindRef(a) => {
            store_indirect!(Object | unaligned alignment!(a), volatile true)
        }
        UnalignedVolatileStobj(a, t) | VolatileUnalignedStobj(a, t) => {
            stobj!(t | unaligned alignment!(a), volatile true)
        }
    })
}
