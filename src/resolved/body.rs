use super::{
    il::Instruction,
    types::{LocalVariable, MethodType},
};

#[derive(Debug)]
pub struct Header<'a> {
    pub initialize_locals: bool,
    pub maximum_stack_size: usize,
    pub local_variables: Vec<LocalVariable<'a>>,
}

#[derive(Debug)]
pub struct Method<'a> {
    pub header: Header<'a>,
    pub body: Vec<Instruction<'a>>,
    pub data_sections: Vec<DataSection<'a>>,
}

#[derive(Debug)]
pub enum DataSection<'a> {
    Unrecognized,
    ExceptionHandlers(Vec<Exception<'a>>),
}

#[derive(Debug)]
pub struct Exception<'a> {
    pub exception: bool,
    pub filter: bool,
    pub finally: bool,
    pub fault: bool,
    pub try_offset: usize,
    pub try_length: usize,
    pub handler_offset: usize,
    pub handler_length: usize,
    pub class: MethodType<'a>, // not sure about this one
    pub filter_offset: usize,
}
