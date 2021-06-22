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
        method: &'a Method<'a>,
    },
    CallIndirect {
        tail_call: bool,
        signature: signature::MaybeUnmanagedMethod<'a>,
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
    Jump(&'a Method<'a>),
    LoadArgument(u16),
    LoadArgumentAddress(u16),
    LoadConstantInt32(i32),
    LoadConstantInt64(i64),
    LoadConstantFloat32(f32),
    LoadConstantFloat64(f64),
    LoadMethodPointer(&'a Method<'a>),
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

    Box(MethodType<'a>),
    CallVirtual {
        constraint: Option<MethodType<'a>>,
        skip_null_check: bool,
        tail_call: bool,
        method: &'a Method<'a>,
    },
    CastClass {
        skip_type_check: bool,
        cast_type: MethodType<'a>,
    },
    CopyObject(MethodType<'a>),
    InitializeForObject(MethodType<'a>),
    IsInstance(MethodType<'a>),
    LoadElement {
        skip_range_check: bool,
        skip_null_check: bool,
        element_type: MethodType<'a>,
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
        element_type: MethodType<'a>,
    },
    LoadField {
        skip_null_check: bool,
        unaligned: bool,
        volatile: bool,
        field: &'a Field<'a>,
    },
    LoadFieldAddress(&'a Field<'a>),
    LoadLength,
    LoadObject {
        unaligned: bool,
        volatile: bool,
        object_type: MethodType<'a>,
    },
    LoadStaticField {
        volatile: bool,
        field: &'a Field<'a>,
    },
    LoadStaticFieldAddress(&'a Field<'a>),
    LoadString(&'a str),
    LoadTokenField(&'a Field<'a>),
    LoadTokenMethod(&'a Method<'a>),
    LoadTokenType(MethodType<'a>),
    LoadVirtualMethodPointer {
        skip_null_check: bool,
        method: &'a Method<'a>,
    },
    MakeTypedReferenceUser(UserType<'a>),
    MakeTypedReferenceGeneric(GenericInstantiation<'a, MethodType<'a>>),
    NewArray(MethodType<'a>),
    NewObject(&'a Method<'a>), // constructor
    ReadTypedReferenceType,
    ReadTypedReferenceValue(MethodType<'a>),
    Rethrow,
    Sizeof(MethodType<'a>),
    StoreElement {
        skip_type_check: bool,
        skip_range_check: bool,
        skip_null_check: bool,
        element_type: MethodType<'a>,
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
        field: &'a Field<'a>,
    },
    StoreObject {
        unaligned: bool,
        volatile: bool,
        object_type: MethodType<'a>,
    },
    StoreStaticField {
        volatile: bool,
        field: &'a Field<'a>,
    },
    Throw,
    UnboxIntoAddress {
        skip_type_check: bool,
        unbox_type: MethodType<'a>,
    },
    UnboxIntoValue(MethodType<'a>),
}
