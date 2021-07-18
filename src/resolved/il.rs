use super::{members::*, signature, types::*, ResolvedDebug};
use crate::resolution::Resolution;

#[derive(Debug)]
pub enum NumberSign {
    Signed,
    Unsigned,
}

#[derive(Debug)]
pub enum OverflowDetection {
    Check,
    NoCheck,
}

#[derive(Debug)]
pub enum ConversionType {
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    IntPtr,
    UIntPtr,
}

#[derive(Debug)]
pub enum Alignment {
    Byte,
    Double,
    Quad,
}

#[derive(Debug)]
pub enum LoadType {
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    Float32,
    Float64,
    IntPtr,
    Object,
}

#[derive(Debug)]
pub enum StoreType {
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    IntPtr,
    Object,
}

#[derive(Debug)]
pub enum Instruction<'a> {
    Add,
    AddOverflow(NumberSign),
    And,
    ArgumentList,
    BranchEqual(usize),
    BranchGreaterOrEqual(NumberSign, usize),
    BranchGreater(NumberSign, usize),
    BranchLessOrEqual(NumberSign, usize),
    BranchLess(NumberSign, usize),
    BranchNotEqual(usize),
    Branch(usize),
    Breakpoint,
    BranchFalsy(usize),
    BranchTruthy(usize),
    Call {
        tail_call: bool,
        method: MethodSource<'a>,
    },
    CallIndirect {
        tail_call: bool,
        signature: signature::MaybeUnmanagedMethod,
    },
    CompareEqual,
    CompareGreater(NumberSign),
    CheckFinite,
    CompareLess(NumberSign),
    Convert(OverflowDetection, ConversionType, NumberSign),
    ConvertFloat32,
    ConvertFloat64,
    ConvertUnsignedToFloat,
    CopyMemoryBlock {
        unaligned: Option<Alignment>,
        volatile: bool,
    },
    Divide(NumberSign),
    Duplicate,
    EndFilter,
    EndFinally,
    InitializeMemoryBlock {
        unaligned: Option<Alignment>,
        volatile: bool,
    },
    Jump(MethodSource<'a>),
    LoadArgument(u16),
    LoadArgumentAddress(u16),
    LoadConstantInt32(i32),
    LoadConstantInt64(i64),
    LoadConstantFloat32(f32),
    LoadConstantFloat64(f64),
    LoadMethodPointer(MethodSource<'a>),
    LoadIndirect {
        unaligned: Option<Alignment>,
        volatile: bool,
        value_type: LoadType,
    },
    LoadLocalVariable(u16),
    LoadLocalVariableAddress(u16),
    LoadNull,
    Leave(usize),
    LocalMemoryAllocate,
    Multiply,
    MultiplyOverflow(NumberSign),
    Negate,
    NoOperation,
    Not,
    Or,
    Pop,
    Remainder(NumberSign),
    Return,
    ShiftLeft,
    ShiftRight(NumberSign),
    StoreArgument(u16),
    StoreIndirect {
        unaligned: Option<Alignment>,
        volatile: bool,
        value_type: StoreType,
    },
    StoreLocal(u16),
    Subtract,
    SubtractOverflow(NumberSign),
    Switch(Vec<usize>),
    Xor,

    Box(MethodType),
    CallVirtual {
        constraint: Option<MethodType>,
        skip_null_check: bool,
        tail_call: bool,
        method: MethodSource<'a>,
    },
    CastClass {
        skip_type_check: bool,
        cast_type: MethodType,
    },
    CopyObject(MethodType),
    InitializeForObject(MethodType),
    IsInstance(MethodType),
    LoadElement {
        skip_range_check: bool,
        skip_null_check: bool,
        element_type: MethodType,
    },
    LoadElementPrimitive {
        skip_range_check: bool,
        skip_null_check: bool,
        element_type: LoadType,
    },
    LoadElementAddress {
        skip_type_check: bool,
        skip_range_check: bool,
        skip_null_check: bool,
        readonly: bool,
        element_type: MethodType,
    },
    LoadField {
        skip_null_check: bool,
        unaligned: Option<Alignment>,
        volatile: bool,
        field: FieldSource<'a>,
    },
    LoadFieldAddress(FieldSource<'a>),
    LoadLength,
    LoadObject {
        unaligned: Option<Alignment>,
        volatile: bool,
        object_type: MethodType,
    },
    LoadStaticField {
        volatile: bool,
        field: FieldSource<'a>,
    },
    LoadStaticFieldAddress(FieldSource<'a>),
    LoadString(String),
    LoadTokenField(FieldSource<'a>),
    LoadTokenMethod(MethodSource<'a>),
    LoadTokenType(MethodType),
    LoadVirtualMethodPointer {
        skip_null_check: bool,
        method: MethodSource<'a>,
    },
    MakeTypedReference(MethodType),
    NewArray(MethodType),
    NewObject(UserMethod<'a>), // constructors can't have generics
    ReadTypedReferenceType,
    ReadTypedReferenceValue(MethodType),
    Rethrow,
    Sizeof(MethodType),
    StoreElement {
        skip_type_check: bool,
        skip_range_check: bool,
        skip_null_check: bool,
        element_type: MethodType,
    },
    StoreElementPrimitive {
        skip_type_check: bool,
        skip_range_check: bool,
        skip_null_check: bool,
        element_type: StoreType,
    },
    StoreField {
        skip_null_check: bool,
        unaligned: Option<Alignment>,
        volatile: bool,
        field: FieldSource<'a>,
    },
    StoreObject {
        unaligned: Option<Alignment>,
        volatile: bool,
        object_type: MethodType,
    },
    StoreStaticField {
        volatile: bool,
        field: FieldSource<'a>,
    },
    Throw,
    UnboxIntoAddress {
        skip_type_check: bool,
        unbox_type: MethodType,
    },
    UnboxIntoValue(MethodType),
}
impl ResolvedDebug for Instruction<'_> {
    #[allow(unused_macros)]
    fn show(&self, res: &Resolution) -> String {
        use Instruction::*;

        macro_rules! modifiers {
            ($($body:expr),*) => {{
                let mut mods = vec![];

                macro_rules! align {
                    ($a:ident) => {
                        if let Some(a) = $a {
                            mods.push(format!("aligned({:?})", a));
                        }
                    };
                }

                macro_rules! constraint {
                    ($c:ident) => {
                        if let Some(c) = $c {
                            mods.push(format!("constraint {}", c.show(res)))
                        }
                    }
                }

                macro_rules! const_bool {
                    ($name:ident) => {
                        macro_rules! $name {
                            ($v:ident) => {
                                if *$v {
                                    mods.push(stringify!($name).to_string());
                                }
                            }
                        }
                    };
                }

                const_bool!(volatile);
                const_bool!(tail);
                const_bool!(notypecheck);
                const_bool!(norangecheck);
                const_bool!(nonullcheck);
                const_bool!(readonly);

                $($body;)*

                if mods.is_empty() {
                    String::new()
                } else {
                    format!("[{}]", mods.join(", "))
                }
            }};
        }

        match self {
            Call { tail_call, method } => {
                format!("Call{}({})", modifiers!(tail!(tail_call)), method.show(res))
            }
            CallIndirect {
                tail_call,
                signature,
            } => format!(
                "CallIndirect{}({})",
                modifiers!(tail!(tail_call)),
                signature.show(res)
            ),
            CopyMemoryBlock {
                unaligned,
                volatile,
            } => format!(
                "CopyMemoryBlock{}",
                modifiers!(align!(unaligned), volatile!(volatile))
            ),
            InitializeMemoryBlock {
                unaligned,
                volatile,
            } => format!(
                "InitializeMemoryBlock{}",
                modifiers!(align!(unaligned), volatile!(volatile))
            ),
            Jump(m) => format!("Jump({})", m.show(res)),
            LoadMethodPointer(m) => format!("LoadMethodPointer({})", m.show(res)),
            LoadIndirect {
                unaligned,
                volatile,
                value_type,
            } => format!(
                "LoadIndirect{}({:?})",
                modifiers!(align!(unaligned), volatile!(volatile)),
                value_type
            ),
            StoreIndirect {
                unaligned,
                volatile,
                value_type,
            } => format!(
                "StoreIndirect{}({:?})",
                modifiers!(align!(unaligned), volatile!(volatile)),
                value_type
            ),
            Box(t) => format!("Box({})", t.show(res)),
            CallVirtual {
                constraint,
                skip_null_check,
                tail_call,
                method,
            } => format!(
                "CallVirtual{}({})",
                modifiers!(
                    constraint!(constraint),
                    nonullcheck!(skip_null_check),
                    tail!(tail_call)
                ),
                method.show(res)
            ),
            CastClass {
                skip_type_check,
                cast_type,
            } => format!(
                "CastClass{}({})",
                modifiers!(notypecheck!(skip_type_check)),
                cast_type.show(res)
            ),
            CopyObject(t) => format!("CopyObject({})", t.show(res)),
            InitializeForObject(t) => format!("InitializeForObject({})", t.show(res)),
            IsInstance(t) => format!("IsInstance({})", t.show(res)),
            LoadElement {
                skip_range_check,
                skip_null_check,
                element_type,
            } => format!(
                "LoadElement{}({})",
                modifiers!(
                    norangecheck!(skip_range_check),
                    nonullcheck!(skip_null_check)
                ),
                element_type.show(res)
            ),
            LoadElementPrimitive {
                skip_range_check,
                skip_null_check,
                element_type,
            } => format!(
                "LoadElementPrimitive{}({:?})",
                modifiers!(
                    norangecheck!(skip_range_check),
                    nonullcheck!(skip_null_check)
                ),
                element_type
            ),
            LoadElementAddress {
                skip_type_check,
                skip_range_check,
                skip_null_check,
                readonly,
                element_type,
            } => format!(
                "LoadElementAddress{}({})",
                modifiers!(
                    notypecheck!(skip_type_check),
                    norangecheck!(skip_range_check),
                    nonullcheck!(skip_null_check),
                    readonly!(readonly)
                ),
                element_type.show(res)
            ),
            LoadField {
                skip_null_check,
                unaligned,
                volatile,
                field,
            } => format!(
                "LoadField{}({})",
                modifiers!(
                    nonullcheck!(skip_null_check),
                    align!(unaligned),
                    volatile!(volatile)
                ),
                field.show(res)
            ),
            LoadFieldAddress(f) => format!("LoadFieldAddress({})", f.show(res)),
            LoadObject {
                unaligned,
                volatile,
                object_type,
            } => format!(
                "LoadObject{}({})",
                modifiers!(align!(unaligned), volatile!(volatile)),
                object_type.show(res)
            ),
            LoadStaticField { volatile, field } => format!(
                "LoadStaticField{}({})",
                modifiers!(volatile!(volatile)),
                field.show(res)
            ),
            LoadStaticFieldAddress(f) => format!("LoadStaticFieldAddress({})", f.show(res)),
            LoadTokenField(f) => format!("LoadTokenField({})", f.show(res)),
            LoadTokenMethod(m) => format!("LoadTokenMethod({})", m.show(res)),
            LoadTokenType(t) => format!("LoadTokenType({})", t.show(res)),
            LoadVirtualMethodPointer {
                skip_null_check,
                method,
            } => format!(
                "LoadVirtualMethodPointer{}({})",
                modifiers!(nonullcheck!(skip_null_check)),
                method.show(res)
            ),
            MakeTypedReference(t) => format!("MakeTypedReference({})", t.show(res)),
            NewArray(t) => format!("NewArray({})", t.show(res)),
            NewObject(m) => format!("NewObject({})", m.show(res)),
            ReadTypedReferenceValue(t) => format!("ReadTypedReferenceValue({})", t.show(res)),
            Sizeof(t) => format!("Sizeof({})", t.show(res)),
            StoreElement {
                skip_type_check,
                skip_range_check,
                skip_null_check,
                element_type,
            } => format!(
                "StoreElement{}({})",
                modifiers!(
                    notypecheck!(skip_type_check),
                    norangecheck!(skip_range_check),
                    nonullcheck!(skip_null_check)
                ),
                element_type.show(res)
            ),
            StoreElementPrimitive {
                skip_type_check,
                skip_range_check,
                skip_null_check,
                element_type,
            } => format!(
                "StoreElementPrimitive{}({:?})",
                modifiers!(
                    notypecheck!(skip_type_check),
                    norangecheck!(skip_range_check),
                    nonullcheck!(skip_null_check)
                ),
                element_type
            ),
            StoreField {
                skip_null_check,
                unaligned,
                volatile,
                field,
            } => format!(
                "StoreField{}({})",
                modifiers!(
                    nonullcheck!(skip_null_check),
                    align!(unaligned),
                    volatile!(volatile)
                ),
                field.show(res)
            ),
            StoreObject {
                unaligned,
                volatile,
                object_type,
            } => format!(
                "StoreObject{}({})",
                modifiers!(align!(unaligned), volatile!(volatile)),
                object_type.show(res)
            ),
            StoreStaticField { volatile, field } => format!(
                "StoreStaticField{}({})",
                modifiers!(volatile!(volatile)),
                field.show(res)
            ),
            UnboxIntoAddress {
                skip_type_check,
                unbox_type,
            } => format!(
                "UnboxIntoAddress{}({})",
                modifiers!(notypecheck!(skip_type_check)),
                unbox_type.show(res),
            ),
            UnboxIntoValue(t) => format!("UnboxIntoValue({})", t.show(res)),
            rest => format!("{:?}", rest),
        }
    }
}
