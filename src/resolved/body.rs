use super::{
    il::Instruction,
    types::{LocalVariable, MethodType},
};

/// Header settings for a resolved IL method body.
///
/// This controls the method-body header emitted when writing a [`Method`] to a PE/CLI image.
/// See ECMA-335, II.25.4.2.
///
/// The physical method-body header encoding is represented by [`crate::binary::method::Header`].
#[derive(Debug, Clone)]
pub struct Header {
    /// If `true`, all locals are zero-initialized before the first instruction executes.
    ///
    /// This corresponds to the ILAsm `.locals init` directive.
    pub initialize_locals: bool,
    /// Maximum evaluation-stack depth (`maxstack`) required by this method body.
    ///
    /// The default is `8`, which is the implicit stack limit used by tiny method headers.
    /// See ECMA-335, II.25.4.2.
    pub maximum_stack_size: usize,
    /// Local-variable declarations for the method body.
    ///
    /// These are encoded as a local-variable signature when the assembly is written.
    pub local_variables: Vec<LocalVariable>,
}
impl Default for Header {
    fn default() -> Self {
        Self {
            initialize_locals: false,
            maximum_stack_size: 8,
            local_variables: vec![],
        }
    }
}

/// A decoded managed method body.
///
/// This is the high-level representation stored in
/// [`crate::resolved::members::Method::body`]. That field is typically `None` for abstract
/// methods and external (for example, P/Invoke) methods that do not carry an IL body.
///
/// The physical method-body encoding is represented by [`crate::binary::method::Method`].
#[derive(Debug, Clone, Default)]
pub struct Method {
    /// Header metadata for the method body.
    pub header: Header,
    /// Instruction stream for the method.
    pub instructions: Vec<Instruction>,
    /// Additional method data sections (for example, exception handlers).
    pub data_sections: Vec<DataSection>,
}
impl Method {
    /// Creates a method body with no locals and default [`Header`] settings.
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self {
            instructions,
            ..Method::default()
        }
    }

    /// Creates a method body with explicit locals.
    ///
    /// This stores `locals` in [`Header::local_variables`] and sets
    /// [`Header::initialize_locals`] to `true`.
    pub fn with_locals(locals: Vec<LocalVariable>, instructions: Vec<Instruction>) -> Self {
        let mut m = Method::new(instructions);
        m.header.local_variables = locals;
        m.header.initialize_locals = true;
        m
    }
}

/// A method-body data section.
///
/// Exception-handler sections map to CLI exception clauses. The section layout is defined in
/// ECMA-335, II.25.4.5.
///
/// The physical encoding is represented by [`crate::binary::method::DataSection`].
#[derive(Debug, Clone)]
pub enum DataSection {
    /// A section kind not currently interpreted by `dotnetdll`, preserved by shape only.
    Unrecognized { fat: bool, size: usize },
    /// Exception-handler clauses attached to the method body.
    ExceptionHandlers(Vec<Exception>),
}

/// A single exception-handling clause.
///
/// Handler semantics are defined by the CLI exception model (ECMA-335, I.12.4.2), while the
/// corresponding method data-section encoding uses ECMA-335, II.25.4.5.
///
/// The physical encoding is represented by [`crate::binary::method::Exception`].
#[derive(Debug, Clone)]
pub struct Exception {
    /// Clause kind (`catch`, `filter`, `finally`, or `fault`).
    pub kind: ExceptionKind,
    /// Start of the protected `try` region as an instruction index.
    pub try_offset: usize,
    /// Length of the `try` region in number of instructions.
    pub try_length: usize,
    /// Start of the handler region as an instruction index.
    pub handler_offset: usize,
    /// Length of the handler region in number of instructions.
    pub handler_length: usize,
}

/// Exception-handler behavior for an [`Exception`] clause.
///
/// Conceptual behavior is defined in ECMA-335, I.12.4.2. Binary clause tags and payload layout are
/// defined in ECMA-335, II.25.4.5.
#[derive(Debug, Clone)]
pub enum ExceptionKind {
    /// Catches exceptions assignable to the given type.
    TypedException(MethodType),
    /// Uses a user-defined filter block; `offset` is the filter start instruction index.
    Filter { offset: usize },
    /// Runs when control leaves the protected region, whether normally or due to an exception.
    Finally,
    /// Runs only when an exception leaves the protected region (unlike [`Self::Finally`]).
    Fault,
}
