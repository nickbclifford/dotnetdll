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
impl Default for Header {
    fn default() -> Self {
        Self {
            initialize_locals: false,
            maximum_stack_size: 8,
            local_variables: vec![],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Method {
    pub header: Header,
    pub instructions: Vec<Instruction>,
    pub data_sections: Vec<DataSection>,
}
impl Method {
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self {
            instructions,
            ..Method::default()
        }
    }

    pub fn with_locals(locals: Vec<LocalVariable>, instructions: Vec<Instruction>) -> Self {
        let mut m = Method::new(instructions);
        m.header.local_variables = locals;
        m.header.initialize_locals = true;
        m
    }
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
