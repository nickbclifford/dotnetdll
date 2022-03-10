use super::resolved::*;
use dotnetdll_macros::From;
use paste::paste;
use std::ops::{Index, IndexMut};

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
            type_references: vec![],
        }
    }

    pub fn push_global_module_type(&mut self) -> TypeIndex {
        self.push_type_definition(types::TypeDefinition::new(None, "<Module>".into()))
    }
}

#[derive(Debug, Copy, Clone, From)]
pub enum EntryPoint {
    Method(MethodIndex),
    File(FileIndex),
}

// for all these indices, the value inside is private, so users cannot manually construct one
// we also check during resolution that the index we assign is always valid
// these both imply that indexing with these newtypes will always succeed
// we can take advantage of this semantic guarantee to do unchecked zero-cost indexing (opt-in)

fn slice_index<T>(s: &[T], index: usize) -> &T {
    if cfg!(feature = "unchecked_indexing") {
        unsafe { s.get_unchecked(index) }
    } else {
        &s[index]
    }
}
fn slice_index_mut<T>(s: &mut [T], index: usize) -> &mut T {
    if cfg!(feature = "unchecked_indexing") {
        unsafe { s.get_unchecked_mut(index) }
    } else {
        &mut s[index]
    }
}
fn unwrap<T>(o: Option<T>) -> T {
    if cfg!(feature = "unchecked_indexing") {
        unsafe { o.unwrap_unchecked() }
    } else {
        o.unwrap()
    }
}

macro_rules! basic_index {
    ($name:ident indexes $field:ident as $t:ty) => {
        paste! {
            #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
            pub struct $name(pub(crate) usize);

            impl<'a> Index<$name> for Resolution<'a> {
                type Output = $t;

                fn index(&self, index: $name) -> &Self::Output {
                    slice_index(&self.[<$field s>], index.0)
                }
            }
            impl<'a> IndexMut<$name> for Resolution<'a> {
                fn index_mut(&mut self, index: $name) -> &mut Self::Output {
                    slice_index_mut(&mut self.[<$field s>], index.0)
                }
            }
            impl<'a> Resolution<'a> {
                pub fn [<push_ $field>](&mut self, val: $t) -> $name {
                    self.[<$field s>].push(val);
                    $name(self.[<$field s>].len() - 1)
                }

                pub fn [<$field _index>](&self, index: usize) -> Option<$name> {
                    if index < self.[<$field s>].len() {
                        Some($name(index))
                    } else {
                        None
                    }
                }

                pub fn [<enumerate_ $field s>](&self) -> impl Iterator<Item = ($name, &$t)> {
                    self.[<$field s>].iter().enumerate().map(|(i, f)| ($name(i), f))
                }
            }
        }
    };
}

basic_index!(AssemblyRefIndex indexes assembly_reference as assembly::ExternalAssemblyReference<'a>);
basic_index!(ExportedTypeIndex indexes exported_type as types::ExportedType<'a>);
basic_index!(FieldRefIndex indexes field_reference as members::ExternalFieldReference<'a>);
basic_index!(FileIndex indexes file as module::File<'a>);
basic_index!(MethodRefIndex indexes method_reference as members::ExternalMethodReference<'a>);
basic_index!(ModuleRefIndex indexes module_reference as module::ExternalModuleReference<'a>);
basic_index!(TypeIndex indexes type_definition as types::TypeDefinition<'a>);
basic_index!(TypeRefIndex indexes type_reference as types::ExternalTypeReference<'a>);

macro_rules! internal_index {
    ($name:ident indexes $sing:ident / $plural:ident as $t:ty) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name {
            pub(crate) parent_type: TypeIndex,
            pub(crate) $sing: usize,
        }

        impl<'a> Index<$name> for Resolution<'a> {
            type Output = $t;

            fn index(&self, index: $name) -> &Self::Output {
                slice_index(&self[index.parent_type].$plural, index.$sing)
            }
        }

        impl<'a> IndexMut<$name> for Resolution<'a> {
            fn index_mut(&mut self, index: $name) -> &mut Self::Output {
                slice_index_mut(&mut self[index.parent_type].$plural, index.$sing)
            }
        }

        impl<'a> Resolution<'a> {
            paste! {
                pub fn [<push_ $sing>](&mut self, parent: TypeIndex, $sing: $t) -> $name {
                    let $plural = &mut self[parent].$plural;
                    $plural.push($sing);
                    $name {
                        parent_type: parent,
                        $sing: $plural.len() - 1
                    }
                }

                pub fn [<$sing _index>](&self, parent: TypeIndex, index: usize) -> Option<$name> {
                    if index < self[parent].$plural.len() {
                        Some($name {
                            parent_type: parent,
                            $sing: index,
                        })
                    } else {
                        None
                    }
                }

                pub fn [<enumerate_ $plural>](&self, parent: TypeIndex) -> impl Iterator<Item = ($name, &$t)> {
                    self[parent].$plural.iter().enumerate().map(move |(i, f)| ($name {
                        parent_type: parent,
                        $sing: i
                    }, f))
                }
            }
        }
    };
}

internal_index!(FieldIndex indexes field / fields as members::Field<'a>);
internal_index!(PropertyIndex indexes property / properties as members::Property<'a>);
internal_index!(EventIndex indexes event / events as members::Event<'a>);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
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
            Method(i) => slice_index(&parent.methods, i),
            PropertyGetter(i) => unwrap(slice_index(&parent.properties, i).getter.as_ref()),
            PropertySetter(i) => unwrap(slice_index(&parent.properties, i).setter.as_ref()),
            PropertyOther { property, other } => slice_index(&slice_index(&parent.properties, property).other, other),
            EventAdd(i) => &slice_index(&parent.events, i).add_listener,
            EventRemove(i) => &slice_index(&parent.events, i).remove_listener,
            EventRaise(i) => unwrap(slice_index(&parent.events, i).raise_event.as_ref()),
            EventOther { event, other } => slice_index(&slice_index(&parent.events, event).other, other),
        }
    }
}
impl<'a> IndexMut<MethodIndex> for Resolution<'a> {
    fn index_mut(&mut self, index: MethodIndex) -> &mut Self::Output {
        let parent = &mut self[index.parent_type];

        use MethodMemberIndex::*;
        match index.member {
            Method(i) => slice_index_mut(&mut parent.methods, i),
            PropertyGetter(i) => unwrap(slice_index_mut(&mut parent.properties, i).getter.as_mut()),
            PropertySetter(i) => unwrap(slice_index_mut(&mut parent.properties, i).setter.as_mut()),
            PropertyOther { property, other } => {
                slice_index_mut(&mut slice_index_mut(&mut parent.properties, property).other, other)
            }
            EventAdd(i) => &mut slice_index_mut(&mut parent.events, i).add_listener,
            EventRemove(i) => &mut slice_index_mut(&mut parent.events, i).remove_listener,
            EventRaise(i) => unwrap(slice_index_mut(&mut parent.events, i).raise_event.as_mut()),
            EventOther { event, other } => {
                slice_index_mut(&mut slice_index_mut(&mut parent.events, event).other, other)
            }
        }
    }
}
impl<'a> Resolution<'a> {
    pub fn push_method(&mut self, parent: TypeIndex, method: members::Method<'a>) -> MethodIndex {
        let methods = &mut self[parent].methods;
        methods.push(method);
        MethodIndex {
            parent_type: parent,
            member: MethodMemberIndex::Method(methods.len() - 1),
        }
    }
    pub fn method_index(&self, parent: TypeIndex, index: usize) -> Option<MethodIndex> {
        if index < self[parent].methods.len() {
            Some(MethodIndex {
                parent_type: parent,
                member: MethodMemberIndex::Method(index),
            })
        } else {
            None
        }
    }
    pub fn enumerate_methods(&self, parent: TypeIndex) -> impl Iterator<Item = (MethodIndex, &members::Method<'a>)> {
        self[parent].methods.iter().enumerate().map(move |(i, f)| {
            (
                MethodIndex {
                    parent_type: parent,
                    member: MethodMemberIndex::Method(i),
                },
                f,
            )
        })
    }

    pub fn set_property_getter(&mut self, property: PropertyIndex, method: members::Method<'a>) -> MethodIndex {
        self[property].getter = Some(method);
        MethodIndex {
            parent_type: property.parent_type,
            member: MethodMemberIndex::PropertyGetter(property.property),
        }
    }
    pub fn property_getter_index(&self, property: PropertyIndex) -> Option<MethodIndex> {
        if self[property].getter.is_some() {
            Some(MethodIndex {
                parent_type: property.parent_type,
                member: MethodMemberIndex::PropertyGetter(property.property),
            })
        } else {
            None
        }
    }

    pub fn set_property_setter(&mut self, property: PropertyIndex, method: members::Method<'a>) -> MethodIndex {
        self[property].setter = Some(method);
        MethodIndex {
            parent_type: property.parent_type,
            member: MethodMemberIndex::PropertySetter(property.property),
        }
    }
    pub fn property_setter_index(&self, property: PropertyIndex) -> Option<MethodIndex> {
        if self[property].setter.is_some() {
            Some(MethodIndex {
                parent_type: property.parent_type,
                member: MethodMemberIndex::PropertySetter(property.property),
            })
        } else {
            None
        }
    }

    pub fn push_property_other(&mut self, property: PropertyIndex, method: members::Method<'a>) -> MethodIndex {
        let methods = &mut self[property].other;
        methods.push(method);
        MethodIndex {
            parent_type: property.parent_type,
            member: MethodMemberIndex::PropertyOther {
                property: property.property,
                other: methods.len() - 1,
            },
        }
    }
    pub fn property_other_index(&self, property: PropertyIndex, index: usize) -> Option<MethodIndex> {
        if index < self[property].other.len() {
            Some(MethodIndex {
                parent_type: property.parent_type,
                member: MethodMemberIndex::PropertyOther {
                    property: property.property,
                    other: index,
                },
            })
        } else {
            None
        }
    }

    pub fn event_add_index(&self, event: EventIndex) -> MethodIndex {
        MethodIndex {
            parent_type: event.parent_type,
            member: MethodMemberIndex::EventAdd(event.event),
        }
    }

    pub fn event_remove_index(&self, event: EventIndex) -> MethodIndex {
        MethodIndex {
            parent_type: event.parent_type,
            member: MethodMemberIndex::EventRemove(event.event),
        }
    }

    pub fn set_event_raise(&mut self, event: EventIndex, method: members::Method<'a>) -> MethodIndex {
        self[event].raise_event = Some(method);
        MethodIndex {
            parent_type: event.parent_type,
            member: MethodMemberIndex::EventRaise(event.event),
        }
    }
    pub fn event_raise_index(&self, event: EventIndex) -> Option<MethodIndex> {
        if self[event].raise_event.is_some() {
            Some(MethodIndex {
                parent_type: event.parent_type,
                member: MethodMemberIndex::EventRaise(event.event),
            })
        } else {
            None
        }
    }

    pub fn push_event_other(&mut self, event: EventIndex, method: members::Method<'a>) -> MethodIndex {
        let methods = &mut self[event].other;
        methods.push(method);
        MethodIndex {
            parent_type: event.parent_type,
            member: MethodMemberIndex::EventOther {
                event: event.event,
                other: methods.len() - 1,
            },
        }
    }
    pub fn event_other_index(&self, event: EventIndex, index: usize) -> Option<MethodIndex> {
        if index < self[event].other.len() {
            Some(MethodIndex {
                parent_type: event.parent_type,
                member: MethodMemberIndex::EventOther {
                    event: event.event,
                    other: index,
                },
            })
        } else {
            None
        }
    }
}
