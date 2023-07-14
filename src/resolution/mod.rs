pub mod read;
pub mod utils;
pub mod write;

use crate::prelude::*;
use dotnetdll_macros::From;
use paste::paste;
use std::ops::{Index, IndexMut};

/// A structured representation of a .NET DLL file's metadata, according to the ECMA-335 standard.
///
/// `Resolution` is the top-level data structure of dotnetdll.
/// By working with a `Resolution` instance, you can access all the details of the assembly, modules, types, and other members defined or referenced in a DLL.
#[derive(Debug, Clone)]
pub struct Resolution<'a> {
    /// Assembly metadata, if the DLL defines an assembly.
    pub assembly: Option<Assembly<'a>>,
    /// All external assemblies referenced by the DLL.
    pub assembly_references: Vec<ExternalAssemblyReference<'a>>,
    /// Entry point for the DLL, if one is defined.
    pub entry_point: Option<EntryPoint>,
    /// Types that the DLL exports. Note that this is a separate notion to type accessibility modifiers.
    pub exported_types: Vec<ExportedType<'a>>,
    /// References to fields defined in external assemblies.
    pub field_references: Vec<ExternalFieldReference<'a>>,
    /// File resources that the DLL references or contains.
    pub files: Vec<File<'a>>,
    /// Resources embedded within the DLL.
    pub manifest_resources: Vec<resource::ManifestResource<'a>>,
    /// References to methods defined in external assemblies.
    pub method_references: Vec<ExternalMethodReference<'a>>,
    /// The module defined by the DLL. Note that this is a distinct object from an assembly.
    pub module: Module<'a>,
    /// References to modules defined in external assemblies.
    pub module_references: Vec<ExternalModuleReference<'a>>,
    /// Types defined within the DLL.
    pub type_definitions: Vec<TypeDefinition<'a>>,
    /// References to types defined in external assemblies.
    pub type_references: Vec<ExternalTypeReference<'a>>,
}

impl<'a> Resolution<'a> {
    pub fn new(module: Module<'a>) -> Self {
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
            type_definitions: vec![TypeDefinition::new(None, "<Module>")],
            type_references: vec![],
        }
    }

    pub fn parse(bytes: &'a [u8], opts: ReadOptions) -> crate::dll::Result<Self> {
        let dll = DLL::parse(bytes)?;
        dll.resolve(opts)
    }

    pub fn write(&self, opts: WriteOptions) -> crate::dll::Result<Vec<u8>> {
        write::write_impl(self, opts)
    }

    pub fn set_entry_point(&mut self, entry_point: impl Into<EntryPoint>) {
        self.entry_point = Some(entry_point.into());
    }
}

#[derive(Debug, Copy, Clone, From)]
pub enum EntryPoint {
    Method(MethodIndex),
    File(FileIndex),
}

macro_rules! basic_index {
    ($name:ident indexes $field:ident as $t:ty) => {
        paste! {
            #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
            pub struct $name(pub(crate) usize);

            impl<'a> Index<$name> for Resolution<'a> {
                type Output = $t;

                fn index(&self, index: $name) -> &Self::Output {
                    &self.[<$field s>][index.0]
                }
            }
            impl<'a> IndexMut<$name> for Resolution<'a> {
                fn index_mut(&mut self, index: $name) -> &mut Self::Output {
                    &mut self.[<$field s>][index.0]
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

basic_index!(AssemblyRefIndex indexes assembly_reference as ExternalAssemblyReference<'a>);
basic_index!(ExportedTypeIndex indexes exported_type as ExportedType<'a>);
basic_index!(FieldRefIndex indexes field_reference as ExternalFieldReference<'a>);
basic_index!(FileIndex indexes file as File<'a>);
basic_index!(MethodRefIndex indexes method_reference as ExternalMethodReference<'a>);
basic_index!(ModuleRefIndex indexes module_reference as ExternalModuleReference<'a>);
basic_index!(TypeIndex indexes type_definition as TypeDefinition<'a>);
basic_index!(TypeRefIndex indexes type_reference as ExternalTypeReference<'a>);

macro_rules! internal_index {
    ($name:ident indexes $sing:ident / $plural:ident as $t:ty) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name {
            pub(crate) parent_type: TypeIndex,
            pub(crate) $sing: usize,
        }
        impl $name {
            pub fn parent_type(self) -> TypeIndex {
                self.parent_type
            }
        }

        impl<'a> Index<$name> for Resolution<'a> {
            type Output = $t;

            fn index(&self, index: $name) -> &Self::Output {
                &self[index.parent_type].$plural[index.$sing]
            }
        }

        impl<'a> IndexMut<$name> for Resolution<'a> {
            fn index_mut(&mut self, index: $name) -> &mut Self::Output {
                &mut self[index.parent_type].$plural[index.$sing]
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

internal_index!(FieldIndex indexes field / fields as Field<'a>);
internal_index!(PropertyIndex indexes property / properties as Property<'a>);
internal_index!(EventIndex indexes event / events as Event<'a>);

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
impl MethodIndex {
    pub fn parent_type(self) -> TypeIndex {
        self.parent_type
    }
}

impl<'a> Index<MethodIndex> for Resolution<'a> {
    type Output = Method<'a>;

    fn index(&self, index: MethodIndex) -> &Self::Output {
        let parent = &self[index.parent_type];

        use MethodMemberIndex::*;
        match index.member {
            Method(i) => &parent.methods[i],
            PropertyGetter(i) => {
                let o = parent.properties[i].getter.as_ref();
                o.unwrap()
            }
            PropertySetter(i) => {
                let o = parent.properties[i].setter.as_ref();
                o.unwrap()
            }
            PropertyOther { property, other } => &parent.properties[property].other[other],
            EventAdd(i) => &parent.events[i].add_listener,
            EventRemove(i) => &parent.events[i].remove_listener,
            EventRaise(i) => {
                let o = parent.events[i].raise_event.as_ref();
                o.unwrap()
            }
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
            PropertyGetter(i) => {
                let o = parent.properties[i].getter.as_mut();
                o.unwrap()
            }
            PropertySetter(i) => {
                let o = parent.properties[i].setter.as_mut();
                o.unwrap()
            }
            PropertyOther { property, other } => &mut parent.properties[property].other[other],
            EventAdd(i) => &mut parent.events[i].add_listener,
            EventRemove(i) => &mut parent.events[i].remove_listener,
            EventRaise(i) => {
                let o = parent.events[i].raise_event.as_mut();
                o.unwrap()
            }
            EventOther { event, other } => &mut parent.events[event].other[other],
        }
    }
}
impl<'a> Resolution<'a> {
    pub fn push_method(&mut self, parent: TypeIndex, method: Method<'a>) -> MethodIndex {
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
    pub fn enumerate_methods(&self, parent: TypeIndex) -> impl Iterator<Item = (MethodIndex, &Method<'a>)> {
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

    pub fn set_property_getter(&mut self, property: PropertyIndex, method: Method<'a>) -> MethodIndex {
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

    pub fn set_property_setter(&mut self, property: PropertyIndex, method: Method<'a>) -> MethodIndex {
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

    pub fn push_property_other(&mut self, property: PropertyIndex, method: Method<'a>) -> MethodIndex {
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

    // technically since this can be derived all from `event`, self is unnecessary
    // however, it should match the rest of the indexing functions, especially if internal
    // representations change and self is later needed
    #[allow(clippy::unused_self)]
    pub fn event_add_index(&self, event: EventIndex) -> MethodIndex {
        MethodIndex {
            parent_type: event.parent_type,
            member: MethodMemberIndex::EventAdd(event.event),
        }
    }

    // ditto
    #[allow(clippy::unused_self)]
    pub fn event_remove_index(&self, event: EventIndex) -> MethodIndex {
        MethodIndex {
            parent_type: event.parent_type,
            member: MethodMemberIndex::EventRemove(event.event),
        }
    }

    pub fn set_event_raise(&mut self, event: EventIndex, method: Method<'a>) -> MethodIndex {
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

    pub fn push_event_other(&mut self, event: EventIndex, method: Method<'a>) -> MethodIndex {
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
