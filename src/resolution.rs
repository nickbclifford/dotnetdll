use super::resolved::*;
use std::cell::RefCell;
use std::ops::{Index, IndexMut};
use std::rc::Rc;

pub struct Resolution<'a> {
    pub assembly: Option<assembly::Assembly<'a>>,
    pub assembly_references: Vec<Rc<RefCell<assembly::ExternalAssemblyReference<'a>>>>,
    pub manifest_resources: Vec<resource::ManifestResource<'a>>,
    pub module: module::Module<'a>,
    pub module_references: Vec<Rc<RefCell<module::ExternalModuleReference<'a>>>>,
    pub type_definitions: Vec<types::TypeDefinition<'a>>,
    pub type_references: Vec<types::ExternalTypeReference<'a>>,
    // TODO
}

#[derive(Debug, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
pub struct MethodIndex {
    pub parent_type: usize,
    pub member: MethodMemberIndex,
}

impl<'a> Index<MethodIndex> for Resolution<'a> {
    type Output = members::Method<'a>;

    fn index(&self, index: MethodIndex) -> &Self::Output {
        let parent = &self.type_definitions[index.parent_type];

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
        let parent = &mut self.type_definitions[index.parent_type];

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
