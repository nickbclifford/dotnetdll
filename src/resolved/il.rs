use super::{members::*, signature, types::*, ResolvedDebug};
use crate::resolution::Resolution;

use dotnetdll_macros::r_instructions;
use num_derive::FromPrimitive;

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

#[derive(Debug, Copy, Clone, FromPrimitive)]
pub enum Alignment {
    Byte = 1,
    Double = 2,
    Quad = 4,
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

trait InstructionFlag {
    fn show(&self) -> Option<String>;
}
impl InstructionFlag for Option<Alignment> {
    fn show(&self) -> Option<String> {
        self.map(|a| format!("aligned({:?})", a))
    }
}
impl InstructionFlag for (&'static str, bool) {
    fn show(&self) -> Option<String> {
        if self.1 {
            Some(self.0.to_string())
        } else {
            None
        }
    }
}
fn show_flags<'a>(flags: impl IntoIterator<Item = &'a dyn InstructionFlag>) -> String {
    let set_flags: Vec<_> = flags.into_iter().flat_map(InstructionFlag::show).collect();
    if set_flags.is_empty() {
        String::new()
    } else {
        format!("[{}]", set_flags.join(", "))
    }
}

trait InstructionShow {
    fn show(&self, _res: &Resolution) -> String;
}
impl<T: ResolvedDebug> InstructionShow for T {
    fn show(&self, res: &Resolution) -> String {
        self.show(res)
    }
}
macro_rules! impl_debug {
    ($($t:ty),*) => {
        $(
            impl InstructionShow for $t {
                fn show(&self, _res: &Resolution) -> String {
                    format!("{:?}", self)
                }
            }
        )*
    }
}
// can't just impl<T: Debug> since no specialization yet
impl_debug!(
    NumberSign,
    ConversionType,
    LoadType,
    StoreType,
    u16,
    i32,
    i64,
    f32,
    f64,
    usize,
    Vec<usize>
);
// special impl: UTF-16 LoadString
impl InstructionShow for Vec<u16> {
    fn show(&self, _res: &Resolution) -> String {
        format!("{:?}", String::from_utf16_lossy(self))
    }
}

r_instructions! {
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
    #[flags(tail_call)]
    Call(MethodSource),
    #[flags(tail_call)]
    CallIndirect(signature::MaybeUnmanagedMethod),
    CompareEqual,
    CompareGreater(NumberSign),
    CheckFinite,
    CompareLess(NumberSign),
    Convert(ConversionType),
    ConvertOverflow(ConversionType, NumberSign),
    ConvertFloat32,
    ConvertFloat64,
    ConvertUnsignedToFloat,
    #[flags(unaligned, volatile)]
    CopyMemoryBlock,
    Divide(NumberSign),
    Duplicate,
    EndFilter,
    EndFinally,
    #[flags(unaligned, volatile)]
    InitializeMemoryBlock,
    Jump(MethodSource),
    LoadArgument(u16),
    LoadArgumentAddress(u16),
    LoadConstantInt32(i32),
    LoadConstantInt64(i64),
    LoadConstantFloat32(f32),
    LoadConstantFloat64(f64),
    LoadMethodPointer(MethodSource),
    #[flags(unaligned, volatile)]
    LoadIndirect(LoadType),
    LoadLocal(u16),
    LoadLocalAddress(u16),
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
    #[flags(unaligned, volatile)]
    StoreIndirect(StoreType),
    StoreLocal(u16),
    Subtract,
    SubtractOverflow(NumberSign),
    Switch(Vec<usize>),
    Xor,

    BoxValue(MethodType),
    #[flags(null)]
    CallVirtual(MethodSource),
    CallVirtualConstrained(MethodType, MethodSource),
    CallVirtualTail(MethodSource),
    #[flags(type)]
    CastClass(MethodType),
    CopyObject(MethodType),
    InitializeForObject(MethodType),
    IsInstance(MethodType),
    #[flags(range, null)]
    LoadElement(MethodType),
    #[flags(range, null)]
    LoadElementPrimitive(LoadType),
    #[flags(type, range, null)]
    LoadElementAddress(MethodType),
    LoadElementAddressReadonly(MethodType),
    #[flags(unaligned, volatile)]
    LoadField(FieldSource),
    LoadFieldAddress(FieldSource),
    LoadFieldSkipNullCheck(FieldSource),
    LoadLength,
    #[flags(unaligned, volatile)]
    LoadObject(MethodType),
    #[flags(volatile)]
    LoadStaticField(FieldSource),
    LoadStaticFieldAddress(FieldSource),
    #[skip_constructor]
    LoadString(Vec<u16>),
    LoadTokenField(FieldSource),
    LoadTokenMethod(MethodSource),
    LoadTokenType(MethodType),
    #[flags(null)]
    LoadVirtualMethodPointer(MethodSource),
    MakeTypedReference(MethodType),
    NewArray(MethodType),
    NewObject(UserMethod),
    ReadTypedReferenceType,
    ReadTypedReferenceValue(MethodType),
    Rethrow,
    Sizeof(MethodType),
    #[flags(type, range, null)]
    StoreElement(MethodType),
    #[flags(type, range, null)]
    StoreElementPrimitive(StoreType),
    #[flags(unaligned, volatile)]
    StoreField(FieldSource),
    StoreFieldSkipNullCheck(FieldSource),
    #[flags(unaligned, volatile)]
    StoreObject(MethodType),
    #[flags(volatile)]
    StoreStaticField(FieldSource),
    Throw,
    #[flags(type)]
    UnboxIntoAddress(MethodType),
    UnboxIntoValue(MethodType)
}

impl Instruction {
    pub fn load_string(s: impl AsRef<str>) -> Self {
        Instruction::LoadString(s.as_ref().encode_utf16().collect())
    }
}
