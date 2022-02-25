use super::{
    il::Instruction,
    types::{LocalVariable, MethodType},
};

#[derive(Debug, Clone)]
pub struct Header {
    pub initialize_locals: bool,
    pub maximum_stack_size: usize,
    pub local_variables: Vec<LocalVariable>,
}

#[derive(Debug, Clone)]
pub struct Method {
    pub header: Header,
    pub instructions: Vec<Instruction>,
    pub data_sections: Vec<DataSection>,
}

#[derive(Debug, Clone)]
pub enum DataSection {
    Unrecognized { fat: bool, size: usize },
    ExceptionHandlers(Vec<Exception>),
}

#[derive(Debug, Clone)]
pub struct Exception {
    pub kind: ExceptionKind,
    pub try_offset: usize,
    pub try_length: usize,
    pub handler_offset: usize,
    pub handler_length: usize,
}

#[derive(Debug, Clone)]
pub enum ExceptionKind {
    TypedException(MethodType),
    Filter { offset: usize },
    Finally,
    Fault,
}
