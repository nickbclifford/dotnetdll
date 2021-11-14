use super::resolved::*;
use std::ops::{Index, IndexMut};

// TODO: how will consumers get indices when writing from scratch?

#[derive(Debug, Clone)]
pub struct Resolution<'a> {
    pub assembly: Option<assembly::Assembly<'a>>,
    pub assembly_references: Vec<assembly::ExternalAssemblyReference<'a>>,
    pub entry_point: Option<EntryPoint>,
    pub exported_types: Vec<types::ExportedType<'a>>,
    pub field_references: Vec<members::ExternalFieldReference<'a>>,
    pub files: Vec<module::File<'a>>,
    pub manifest_resources: Vec<resource::ManifestResource<'a>>,
    pub method_references: Vec<members::ExternalMethodReference<'a>>,
    pub module: module::Module<'a>,
    pub module_references: Vec<module::ExternalModuleReference<'a>>,
    pub type_definitions: Vec<types::TypeDefinition<'a>>,
    pub type_references: Vec<types::ExternalTypeReference<'a>>,
}

impl Resolution<'_> {
    pub fn new(module: module::Module) -> Resolution {
        Resolution {
            assembly: None,
            assembly_references: vec![],
            entry_point: None,
            exported_types: vec![],
            field_references: vec![],
            files: vec![],
            manifest_resources: vec![],
            method_references: vec![],
            module,
            module_references: vec![],
            type_definitions: vec![],
            type_references: vec![]
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum EntryPoint {
    Method(MethodIndex),
    File(FileIndex),
}

macro_rules! basic_index {
    ($name:ident indexes $field:ident as $t:ty) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $name(pub(crate) usize);

        impl<'a> Index<$name> for Resolution<'a> {
            type Output = $t;

            fn index(&self, index: $name) -> &Self::Output {
                &self.$field[index.0]
            }
        }
        impl<'a> IndexMut<$name> for Resolution<'a> {
            fn index_mut(&mut self, index: $name) -> &mut Self::Output {
                &mut self.$field[index.0]
            }
        }
    };
}

basic_index!(AssemblyRefIndex indexes assembly_references as assembly::ExternalAssemblyReference<'a>);
basic_index!(ExportedTypeIndex indexes exported_types as types::ExportedType<'a>);
basic_index!(FieldRefIndex indexes field_references as members::ExternalFieldReference<'a>);
basic_index!(FileIndex indexes files as module::File<'a>);
basic_index!(MethodRefIndex indexes method_references as members::ExternalMethodReference<'a>);
basic_index!(ModuleRefIndex indexes module_references as module::ExternalModuleReference<'a>);
basic_index!(TypeIndex indexes type_definitions as types::TypeDefinition<'a>);
basic_index!(TypeRefIndex indexes type_references as types::ExternalTypeReference<'a>);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FieldIndex {
    pub(crate) parent_type: TypeIndex,
    pub(crate) field: usize,
}
impl<'a> Index<FieldIndex> for Resolution<'a> {
    type Output = members::Field<'a>;

    fn index(&self, index: FieldIndex) -> &Self::Output {
        &self[index.parent_type].fields[index.field]
    }
}
impl<'a> IndexMut<FieldIndex> for Resolution<'a> {
    fn index_mut(&mut self, index: FieldIndex) -> &mut Self::Output {
        &mut self[index.parent_type].fields[index.field]
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MethodMemberIndex {
    Method(usize),
    PropertyGetter(usize),
    PropertySetter(usize),
    PropertyOther { property: usize, other: usize },
    EventAdd(usize),
    EventRemove(usize),
    EventRaise(usize),
    EventOther { event: usize, other: usize },
}
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct MethodIndex {
    pub(crate) parent_type: TypeIndex,
    pub(crate) member: MethodMemberIndex,
}

impl<'a> Index<MethodIndex> for Resolution<'a> {
    type Output = members::Method<'a>;

    fn index(&self, index: MethodIndex) -> &Self::Output {
        let parent = &self[index.parent_type];

        use MethodMemberIndex::*;
        match index.member {
            Method(i) => &parent.methods[i],
            PropertyGetter(i) => parent.properties[i].getter.as_ref().unwrap(),
            PropertySetter(i) => parent.properties[i].setter.as_ref().unwrap(),
            PropertyOther { property, other } => &parent.properties[property].other[other],
            EventAdd(i) => &parent.events[i].add_listener,
            EventRemove(i) => &parent.events[i].remove_listener,
            EventRaise(i) => parent.events[i].raise_event.as_ref().unwrap(),
            EventOther { event, other } => &parent.events[event].other[other],
        }
    }
}
impl<'a> IndexMut<MethodIndex> for Resolution<'a> {
    fn index_mut(&mut self, index: MethodIndex) -> &mut Self::Output {
        let parent = &mut self[index.parent_type];

        use MethodMemberIndex::*;
        match index.member {
            Method(i) => &mut parent.methods[i],
            PropertyGetter(i) => parent.properties[i].getter.as_mut().unwrap(),
            PropertySetter(i) => parent.properties[i].setter.as_mut().unwrap(),
            PropertyOther { property, other } => &mut parent.properties[property].other[other],
            EventAdd(i) => &mut parent.events[i].add_listener,
            EventRemove(i) => &mut parent.events[i].remove_listener,
            EventRaise(i) => parent.events[i].raise_event.as_mut().unwrap(),
            EventOther { event, other } => &mut parent.events[event].other[other],
        }
    }
}
