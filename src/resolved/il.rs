use super::{members::*, signature, types::*};

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
    BranchEqual(isize),
    BranchGreaterOrEqual(NumberSign, isize),
    BranchGreater(NumberSign, isize),
    BranchLessOrEqual(NumberSign, isize),
    BranchLess(NumberSign, isize),
    BranchNotEqual(isize),
    Branch(isize),
    Breakpoint,
    BranchFalsy(isize),
    BranchTruthy(isize),
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
        unaligned: bool,
        volatile: bool,
    },
    Divide(NumberSign),
    Duplicate,
    EndFilter,
    EndFinally,
    InitializeMemoryBlock {
        unaligned: bool,
        volatile: bool,
    },
    Jump(UserMethod<'a>), // the standard suggests this doesn't work with generics?
    LoadArgument(u16),
    LoadArgumentAddress(u16),
    LoadConstantInt32(i32),
    LoadConstantInt64(i64),
    LoadConstantFloat32(f32),
    LoadConstantFloat64(f64),
    LoadMethodPointer(UserMethod<'a>), // ditto
    LoadIndirect {
        unaligned: bool,
        volatile: bool,
        value_type: LoadType,
    },
    LoadLocalVariable(u16),
    LoadLocalVariableAddress(u16),
    LoadNull,
    Leave(isize),
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
        unaligned: bool,
        volatile: bool,
        value_type: StoreType,
    },
    StoreLocal(u16),
    Subtract,
    SubtractOverflow(NumberSign),
    Switch(Vec<isize>),
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
        unaligned: bool,
        volatile: bool,
        field: FieldSource<'a>,
    },
    LoadFieldAddress(FieldSource<'a>),
    LoadLength,
    LoadObject {
        unaligned: bool,
        volatile: bool,
        object_type: MethodType,
    },
    LoadStaticField {
        volatile: bool,
        field: FieldSource<'a>,
    },
    LoadStaticFieldAddress(FieldSource<'a>),
    LoadString(&'a str),
    LoadTokenField(FieldSource<'a>),
    LoadTokenMethod(MethodSource<'a>),
    LoadTokenType(MethodType),
    LoadVirtualMethodPointer {
        skip_null_check: bool,
        method: MethodSource<'a>,
    },
    MakeTypedReference(TypeSource<MethodType>),
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
        unaligned: bool,
        volatile: bool,
        field: FieldSource<'a>,
    },
    StoreObject {
        unaligned: bool,
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
