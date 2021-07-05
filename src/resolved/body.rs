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
    pub exception: bool,
    pub filter: bool,
    pub finally: bool,
    pub fault: bool,
    pub try_offset: usize,
    pub try_length: usize,
    pub handler_offset: usize,
    pub handler_length: usize,
    pub class: MethodType, // not sure about this one
    pub filter_offset: usize,
}
