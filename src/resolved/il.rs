use super::{members::*, signature, types::*, ResolvedDebug};
use crate::resolution::Resolution;

#[derive(Debug, Copy, Clone)]
pub enum NumberSign {
    Signed,
    Unsigned,
}

#[derive(Debug, Copy, Clone)]
pub enum OverflowDetection {
    Check,
    NoCheck,
}

#[derive(Debug, Copy, Clone)]
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

#[derive(Debug, Copy, Clone)]
pub enum Alignment {
    Byte,
    Double,
    Quad,
}
impl From<Alignment> for u8 {
    fn from(a: Alignment) -> Self {
        use Alignment::*;
        match a {
            Byte => 1,
            Double => 2,
            Quad => 4,
        }
    }
}

#[derive(Debug, Copy, Clone)]
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

#[derive(Debug, Copy, Clone)]
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

#[derive(Debug, Clone)]
pub enum Instruction {
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
        method: MethodSource,
    },
    CallIndirect {
        tail_call: bool,
        signature: signature::MaybeUnmanagedMethod,
    },
    CompareEqual,
    CompareGreater(NumberSign),
    CheckFinite,
    CompareLess(NumberSign),
    Convert(ConversionType),
    ConvertOverflow(ConversionType, NumberSign),
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
    Jump(MethodSource),
    LoadArgument(u16),
    LoadArgumentAddress(u16),
    LoadConstantInt32(i32),
    LoadConstantInt64(i64),
    LoadConstantFloat32(f32),
    LoadConstantFloat64(f64),
    LoadMethodPointer(MethodSource),
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
        skip_null_check: bool,
        method: MethodSource,
    },
    CallVirtualConstrained {
        constraint: MethodType,
        method: MethodSource,
    },
    CallVirtualTail(MethodSource),
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
        element_type: MethodType,
    },
    LoadElementAddressReadonly(MethodType),
    LoadField {
        unaligned: Option<Alignment>,
        volatile: bool,
        field: FieldSource,
    },
    LoadFieldAddress(FieldSource),
    LoadFieldSkipNullCheck(FieldSource),
    LoadLength,
    LoadObject {
        unaligned: Option<Alignment>,
        volatile: bool,
        object_type: MethodType,
    },
    LoadStaticField {
        volatile: bool,
        field: FieldSource,
    },
    LoadStaticFieldAddress(FieldSource),
    LoadString(Vec<u16>), // not necessarily a valid UTF-16 string, just 16-bit encoded chars
    LoadTokenField(FieldSource),
    LoadTokenMethod(MethodSource),
    LoadTokenType(MethodType),
    LoadVirtualMethodPointer {
        skip_null_check: bool,
        method: MethodSource,
    },
    MakeTypedReference(MethodType),
    NewArray(MethodType),
    NewObject(UserMethod), // constructors can't have generics
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
        unaligned: Option<Alignment>,
        volatile: bool,
        field: FieldSource,
    },
    StoreFieldSkipNullCheck(FieldSource),
    StoreObject {
        unaligned: Option<Alignment>,
        volatile: bool,
        object_type: MethodType,
    },
    StoreStaticField {
        volatile: bool,
        field: FieldSource,
    },
    Throw,
    UnboxIntoAddress {
        skip_type_check: bool,
        unbox_type: MethodType,
    },
    UnboxIntoValue(MethodType),
}
impl ResolvedDebug for Instruction {
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
                skip_null_check,
                method,
            } => format!(
                "CallVirtual{}({})",
                modifiers!(nonullcheck!(skip_null_check)),
                method.show(res)
            ),
            CallVirtualConstrained { constraint, method } => format!(
                "CallVirtualConstrained({}, {})",
                constraint.show(res),
                method.show(res)
            ),
            CallVirtualTail(m) => format!("CallVirtualTail({})", m.show(res)),
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
                element_type,
            } => format!(
                "LoadElementAddress{}({})",
                modifiers!(
                    notypecheck!(skip_type_check),
                    norangecheck!(skip_range_check),
                    nonullcheck!(skip_null_check)
                ),
                element_type.show(res)
            ),
            LoadElementAddressReadonly(t) => format!("LoadElementAddressReadonly({})", t.show(res)),
            LoadField {
                unaligned,
                volatile,
                field,
            } => format!(
                "LoadField{}({})",
                modifiers!(align!(unaligned), volatile!(volatile)),
                field.show(res)
            ),
            LoadFieldAddress(f) => format!("LoadFieldAddress({})", f.show(res)),
            LoadFieldSkipNullCheck(f) => format!("LoadFieldSkipNullCheck({})", f.show(res)),
            LoadObject {
                unaligned,
                volatile,
                object_type,
            } => format!(
                "LoadObject{}({})",
                modifiers!(align!(unaligned), volatile!(volatile)),
                object_type.show(res)
            ),
            LoadString(c) => format!("LoadString(\"{}\")", String::from_utf16_lossy(c)),
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
                unaligned,
                volatile,
                field,
            } => format!(
                "StoreField{}({})",
                modifiers!(align!(unaligned), volatile!(volatile)),
                field.show(res)
            ),
            StoreFieldSkipNullCheck(f) => format!("StoreFieldSkipNullCheck({})", f.show(res)),
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
