//! CIL (Common Intermediate Language) instruction representation.
//!
//! This module provides the [`Instruction`] enum, which represents all CIL opcodes
//! at a high level. Branch targets use instruction indices (not byte offsets) -
//! the library handles offset calculation during serialization.
//!
//! # Instruction Reference
//!
//! [`Instruction`] variants follow verb-style naming patterns that map directly to CIL
//! opcode families:
//!
//! - **Branching and exception flow:** `Branch*`, `Compare*`, `Switch`, `Leave`,
//!   `Return`, `Throw`, and `Rethrow` map to control-flow instructions (`br*`, `b*`,
//!   `c*`, `switch`, `leave`, `ret`, `throw`, `rethrow`). (ECMA-335, III.3)
//! - **Load/store and stack movement:** `LoadArgument*`/`StoreArgument*`,
//!   `LoadLocal*`/`StoreLocal*`, `LoadConstant*`, `LoadNull`, `Duplicate`, and `Pop`
//!   cover argument/local/stack transfers (`ldarg*`, `starg*`, `ldloc*`, `stloc*`,
//!   `ldc.*`, `ldnull`, `dup`, `pop`). (ECMA-335, III.3)
//! - **Arithmetic and bitwise:** `Add*`, `Subtract*`, `Multiply*`, `Divide`,
//!   `Remainder`, `And`, `Or`, `Xor`, `Shift*`, `Negate`, and `Not` map to numeric
//!   opcode groups; [`NumberSign`] and [`OverflowDetection`] select `.un` and `.ovf`
//!   forms. (ECMA-335, III.3)
//! - **Conversions:** `Convert*` maps to `conv.*` families; [`ConversionType`]
//!   selects the integral target, and signedness/overflow options select `.un`/
//!   `.ovf` forms. (ECMA-335, III.3.27; ECMA-335, III.3.28; ECMA-335, III.3.29)
//! - **Object model and metadata tokens:** `Call*`, `BoxValue`, `UnboxInto*`,
//!   `CastClass`, `IsInstance`, `NewArray`, `NewObject`, `LoadToken*`,
//!   `MakeTypedReference`, and `ReadTypedReference*` cover method dispatch, object
//!   conversion, allocation, and token loads. (ECMA-335, III.4)
//! - **Prefix instructions and memory access flags:** `LoadIndirect`/`StoreIndirect`,
//!   `LoadElement*`/`StoreElement*`, `LoadField*`/`StoreField*`, `LoadObject`/
//!   `StoreObject`, `CopyMemoryBlock`, and `InitializeMemoryBlock` expose
//!   `unaligned.`, `volatile.`, and `no.` prefix-style behavior as instruction
//!   metadata/constructor options. (ECMA-335, III.2; ECMA-335, III.3; ECMA-335,
//!   III.4)
//!
//! For exact stack transition, verification, and encoding rules, consult the opcode
//! definitions in Partition III; this API keeps those instruction families typed and
//! ergonomic without changing their semantics.
//!
//! # Examples
//!
//! ## Basic instructions
//!
//! ```rust
//! use dotnetdll::prelude::*;
//!
//! let instructions = vec![
//!     Instruction::LoadConstantInt32(42),
//!     Instruction::LoadConstantInt32(8),
//!     Instruction::Add,
//!     Instruction::Return,
//! ];
//! ```
//!
//! ## Using the `asm!` macro with labels
//!
//! The [`crate::asm!`] macro makes it easier to construct IL sequences with labels:
//!
//! Note: within `asm!`, `@label` introduces a *label definition* (it does **not** mean
//! “clone this variable”). Other proc macros in this crate (e.g. [`crate::resolved::types::ctype!`]
//! and [`crate::resolved::signature::msig!`]) use `@var` for variable substitution via
//! `var.clone()`.
//!
//! ```rust
//! use dotnetdll::prelude::*;
//! # let mut res = Resolution::new(Module::new("test"));
//! # let type_idx = res.type_definition_index(0).unwrap();
//! # let field = res.push_field(type_idx, Field::static_member(Accessibility::Public, "test", ctype! { bool }));
//!
//! // Labels are defined with `@label_name` on an instruction and used by name
//! let body = asm! {
//!     LoadConstantInt32 0;
//!     BranchFalsy else_branch;
//!     LoadString "condition was true".encode_utf16().collect();
//!     Branch end;
//!     @else_branch NoOperation;
//!     LoadString "condition was false".encode_utf16().collect();
//!     @end Return;
//! };
//! ```
//!
//! ## Conditional branching
//!
//! ```rust
//! use dotnetdll::prelude::*;
//!
//! // Compare two values and branch
//! let (instructions, loop_start, loop_end) = asm! {
//!     + loop_start NoOperation;
//!     LoadLocal 0;           // Load loop counter
//!     LoadConstantInt32 10;
//!     BranchLess NumberSign::Signed, loop_end;
//!
//!     // Loop body here
//!     LoadLocal 0;
//!     LoadConstantInt32 1;
//!     Add;
//!     StoreLocal 0;
//!
//!     Branch loop_start;
//!     + loop_end Return;
//! };
//! ```
//!
//! ## Worked example: field access + virtual call
//!
//! This pattern is common in property getters and helper methods: load `this`, read an
//! instance field, then invoke an instance method via `callvirt` semantics.
//!
//! ```rust
//! use dotnetdll::prelude::*;
//!
//! let mut res = Resolution::new(Module::new("example"));
//! let mscorlib = res.push_assembly_reference(ExternalAssemblyReference::new("mscorlib"));
//! let object_ref = res.push_type_reference(type_ref! { System.Object in #mscorlib });
//!
//! let parent = res.type_definition_index(0).unwrap();
//! let value_field = res.push_field(
//!     parent,
//!     Field::instance(Accessibility::Private, "_value", ctype! { object }),
//! );
//!
//! let object_type: MethodType = BaseType::class(object_ref).into();
//! let to_string = res.push_method_reference(method_ref! { string #object_type::ToString() });
//!
//! let describe = res.push_method(
//!     parent,
//!     Method::new(
//!         Accessibility::Public,
//!         msig! { string () },
//!         "Describe",
//!         Some(body::Method::new(asm! {
//!             LoadArgument 0;       // `this`
//!             load_field value_field;
//!             call_virtual to_string;
//!             Return;
//!         }))
//!     )
//! );
//! # let _ = describe;
//! ```

use super::{ResolvedDebug, members::*, signature, types::*};
use crate::resolution::Resolution;

use dotnetdll_macros::r_instructions;
use num_derive::FromPrimitive;

/// Selects signed vs unsigned interpretation for CIL instruction families that have `.un`
/// forms.
///
/// This affects comparisons/branches (`cgt` vs `cgt.un`, `bge` vs `bge.un`), some integer
/// arithmetic (`div`/`rem`), and right shift behavior (`shr` sign-extension vs `shr.un`
/// zero-fill). (ECMA-335, III.3.9; ECMA-335, III.3.23; ECMA-335, III.3.60)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NumberSign {
    /// Use the signed/default opcode semantics.
    Signed,
    /// Use the unsigned (or unordered, for floating-point comparisons) opcode semantics.
    Unsigned,
}

/// Controls whether numeric operations use `ovf` overflow-checking instruction forms.
///
/// Checked forms throw `System.OverflowException` when the result cannot be represented;
/// unchecked forms use the non-`ovf` opcode behavior. (ECMA-335, III.3.2; ECMA-335, III.3.28;
/// ECMA-335, III.3.49; ECMA-335, III.3.65)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum OverflowDetection {
    /// Use overflow-checking forms (for example `add.ovf`, `mul.ovf`, or `conv.ovf.*`).
    Check,
    /// Use non-checking forms that do not throw overflow exceptions.
    NoCheck,
}

/// Target integer type used by the `conv.*` instruction families.
///
/// This enum covers the integral targets used by `conv.<to type>`, `conv.ovf.<to type>`, and
/// `conv.ovf.<to type>.un`. Floating-point conversions use dedicated instructions in
/// [`Instruction`] (`ConvertFloat32`, `ConvertFloat64`, `ConvertUnsignedToFloat`).
/// (ECMA-335, III.3.27; ECMA-335, III.3.28; ECMA-335, III.3.29)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConversionType {
    /// `conv.i1`
    Int8,
    /// `conv.u1`
    UInt8,
    /// `conv.i2`
    Int16,
    /// `conv.u2`
    UInt16,
    /// `conv.i4`
    Int32,
    /// `conv.u4`
    UInt32,
    /// `conv.i8`
    Int64,
    /// `conv.u8`
    UInt64,
    /// `conv.i`
    IntPtr,
    /// `conv.u`
    UIntPtr,
}

/// Alignment hint value for the `unaligned.` instruction prefix.
///
/// The encoded alignment operand is limited to 1, 2, or 4 bytes. (ECMA-335, III.2.5)
#[derive(Debug, Copy, Clone, FromPrimitive, Eq, PartialEq)]
pub enum Alignment {
    /// 1-byte alignment (`unaligned. 1`).
    Byte = 1,
    /// 2-byte alignment (`unaligned. 2`).
    Double = 2,
    /// 4-byte alignment (`unaligned. 4`).
    Quad = 4,
}

/// Element/value type selector for primitive indirect and array load instructions.
///
/// Used by `ldind.*` and `ldelem.*` instruction families. (ECMA-335, III.3.42; ECMA-335,
/// III.4.8)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum LoadType {
    /// `*.i1`
    Int8,
    /// `*.u1`
    UInt8,
    /// `*.i2`
    Int16,
    /// `*.u2`
    UInt16,
    /// `*.i4`
    Int32,
    /// `*.u4`
    UInt32,
    /// `*.i8` (also used for unsigned 64-bit loads in CIL).
    Int64,
    /// `*.r4`
    Float32,
    /// `*.r8`
    Float64,
    /// `*.i` (native-sized integer)
    IntPtr,
    /// `*.ref` (object reference)
    Object,
}

/// Element/value type selector for primitive indirect and array store instructions.
///
/// Used by `stind.*` and `stelem.*` instruction families. (ECMA-335, III.3.62; ECMA-335,
/// III.4.27)
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StoreType {
    /// `*.i1`
    Int8,
    /// `*.i2`
    Int16,
    /// `*.i4`
    Int32,
    /// `*.i8`
    Int64,
    /// `*.r4`
    Float32,
    /// `*.r8`
    Float64,
    /// `*.i` (native-sized integer)
    IntPtr,
    /// `*.ref` (object reference)
    Object,
}

type Flag = Option<String>;
trait InstructionFlag {
    fn show(self) -> Flag;
}
impl InstructionFlag for Option<Alignment> {
    fn show(self) -> Flag {
        self.map(|a| format!("aligned({:?})", a))
    }
}
impl InstructionFlag for (&'static str, bool) {
    fn show(self) -> Flag {
        if self.1 { Some(self.0.to_string()) } else { None }
    }
}
fn show_flags(flags: impl IntoIterator<Item = Flag>) -> String {
    let set_flags: Vec<_> = flags.into_iter().flatten().collect();
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
    CallConstrained(MethodType, MethodSource),
    #[flags(tail_call)]
    CallIndirect(signature::MaybeUnmanagedMethod<MethodType>),
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

#[macro_export]
macro_rules! asm {
    ($ins:ident) => {
        Instruction::$ins
    };
    ($ins:ident $($param:expr),+) => {
        Instruction::$ins($($param),+)
    };
    ($($(@ $label:ident)? $(+ $label_export:ident)? $ins:ident $($param:expr),*;)*) => {{
        let mut _counter = 0;
        $(
            $(let $label = _counter;)?
            $(let $label_export = _counter;)?
            _counter += 1;
        )*

        let _ins = vec![
            $(
                $crate::asm! { $ins $($param),* }
            ),*
        ];

        (_ins
            $(
                $(
                    ,$label_export
                )?
            )*
        )
    }};
}
