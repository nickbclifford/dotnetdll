use super::{
    il::Instruction,
    types::{LocalVariable, MethodType},
};

#[derive(Debug)]
pub struct Header {
    pub initialize_locals: bool,
    pub maximum_stack_size: usize,
    pub local_variables: Vec<LocalVariable>,
}

#[derive(Debug)]
pub struct Method<'a> {
    pub header: Header,
    pub body: Vec<Instruction<'a>>,
    pub data_sections: Vec<DataSection>,
}

#[derive(Debug)]
pub enum DataSection {
    Unrecognized,
    ExceptionHandlers(Vec<Exception>),
}

#[derive(Debug)]
pub struct Exception {
    pub kind: ExceptionKind,
    pub try_offset: usize,
    pub try_length: usize,
    pub handler_offset: usize,
    pub handler_length: usize,
}

#[derive(Debug)]
pub enum ExceptionKind {
    TypedException(MethodType),
    Filter { offset: usize },
    Finally,
    Fault,
}
