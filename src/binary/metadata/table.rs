use super::index;
use bitvec::{order::Lsb0, view::BitView};
use num_derive::{FromPrimitive, ToPrimitive};
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};

// paste!
use paste::paste;

macro_rules! tables {
    ($($name:ident = $val:literal $([sorted by $($sort_field:ident),+])? { $($fname:ident: $ty:ty,)+ }),+) => {
        #[derive(Clone, Copy, Debug, Eq, FromPrimitive, Hash, PartialEq, ToPrimitive)]
        pub enum Kind {
            $(
                $name = $val,
            )*
        }

        $(
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            pub struct $name {
                $(pub $fname: $ty,)*
            }

            impl HasKind for $name {
                fn kind() -> Kind {
                    Kind::$name
                }
            }

            impl<'a> TryFromCtx<'a, index::Sizes<'a>> for $name {
                type Error = scroll::Error;

                fn try_from_ctx(from: &[u8], ctx: index::Sizes<'a>) -> Result<(Self, usize), Self::Error> {
                    let offset = &mut 0;

                    Ok(($name {
                        $($fname: from.gread_with(offset, ctx)?,)*
                    }, *offset))
                }
            }

            impl<'a> TryIntoCtx<index::Sizes<'a>> for $name {
                type Error = scroll::Error;

                fn try_into_ctx(self, into: &mut [u8], ctx: index::Sizes<'a>) -> Result<usize, Self::Error> {
                    let offset = &mut 0;

                    $(
                        into.gwrite_with(self.$fname, offset, ctx)?;
                    )*

                    Ok(*offset)
                }
            }
        )*

        paste! {
            #[derive(Debug, Clone, Eq, PartialEq)]
            pub struct Tables {
                $(
                    pub [<$name:snake>]: Vec<$name>,
                )*
            }

            impl Tables {
                pub fn new() -> Tables {
                    Tables {
                        $(
                            [<$name:snake>]: vec![],
                        )*
                    }
                }

                pub fn valid_mask(&self) -> u64 {
                    let mut mask = 0;

                    let slice = mask.view_bits_mut::<Lsb0>();

                    $(
                        if !self.[<$name:snake>].is_empty() {
                            slice.set($val, true);
                        }
                    )*

                    mask
                }

                pub fn sort(&mut self) {
                    $(
                        $(
                            self.[<$name:snake>].sort_by_key(|r| ($(r.$sort_field),+));
                        )?
                    )+
                }

                pub fn sorted_mask() -> u64 {
                    let mut mask = 0;

                    let slice = mask.view_bits_mut::<Lsb0>();

                    $(
                        $(
                            // need to expand the $sort_field to only match on sorted tables
                            _ = stringify!($($sort_field),+);
                            slice.set($val, true);
                        )?
                    )*

                    mask
                }
            }

            impl Default for Tables {
                fn default() -> Self {
                    Self::new()
                }
            }

            macro_rules! tables_kind_push {
                ($tables:ident, $kind:ident, $add:expr) => {
                    match $kind {
                        $(
                            Kind::$name => $tables.[<$name:snake>].push($add),
                        )*
                    }
                }
            }

            macro_rules! for_each_row {
                ($tables:expr, |$capt:ident, $kind:ident| $do:expr) => {
                    $(
                        for $capt in $tables.[<$name:snake>] {
                            let $kind = Kind::$name;
                            $do;
                        }
                    )*
                }
            }

            macro_rules! for_each_table {
                ($tables:expr, |$capt:ident, $kind:ident| $do:expr) => {
                    $({
                        let $capt = &$tables.[<$name:snake>];
                        let $kind = Kind::$name;
                        $do;
                    })*
                }
            }
        }
    };
}

pub trait HasKind {
    fn kind() -> Kind;
}

tables! {
    Assembly = 0x20 {
        hash_alg_id: u32,
        major_version: u16,
        minor_version: u16,
        build_number: u16,
        revision_number: u16,
        flags: u32,
        public_key: index::Blob,
        name: index::String,
        culture: index::String,
    },
    AssemblyOs = 0x22 {
        os_platform_id: u32,
        os_major_version: u32,
        os_minor_version: u32,
    },
    AssemblyProcessor = 0x21 {
        processor: u32,
    },
    AssemblyRef = 0x23 {
        major_version: u16,
        minor_version: u16,
        build_number: u16,
        revision_number: u16,
        flags: u32,
        public_key_or_token: index::Blob,
        name: index::String,
        culture: index::String,
        hash_value: index::Blob,
    },
    AssemblyRefOs = 0x25 {
        os_platform_id: u32,
        os_major_version: u32,
        os_minor_version: u32,
        assembly_ref: index::Simple<AssemblyRef>,
    },
    AssemblyRefProcessor = 0x24 {
        processor: u32,
        assembly_ref: index::Simple<AssemblyRef>,
    },
    ClassLayout = 0x0F [sorted by parent] {
        packing_size: u16,
        class_size: u32,
        parent: index::Simple<TypeDef>,
    },
    Constant = 0x0B [sorted by parent] {
        constant_type: u8,
        padding: u8,
        parent: index::HasConstant,
        value: index::Blob,
    },
    CustomAttribute = 0x0C [sorted by parent] {
        parent: index::HasCustomAttribute,
        attr_type: index::CustomAttributeType,
        value: index::Blob,
    },
    DeclSecurity = 0x0E [sorted by parent] {
        action: u16,
        parent: index::HasDeclSecurity,
        permission_set: index::Blob,
    },
    EventMap = 0x12 {
        parent: index::Simple<TypeDef>,
        event_list: index::Simple<Event>,
    },
    Event = 0x14 {
        event_flags: u16,
        name: index::String,
        event_type: index::TypeDefOrRef,
    },
    ExportedType = 0x27 {
        flags: u32,
        type_def_id: u32, // actually an index::Simple<TypeDef>, but needs to be forced to 4 bytes
        type_name: index::String,
        type_namespace: index::String,
        implementation: index::Implementation,
    },
    Field = 0x04 {
        flags: u16,
        name: index::String,
        signature: index::Blob,
    },
    FieldLayout = 0x10 [sorted by field] {
        offset: u32,
        field: index::Simple<Field>,
    },
    FieldMarshal = 0x0D [sorted by parent] {
        parent: index::HasFieldMarshal,
        native_type: index::Blob,
    },
    FieldRva = 0x1D [sorted by field] {
        rva: u32,
        field: index::Simple<Field>,
    },
    File = 0x26 {
        flags: u32,
        name: index::String,
        hash_value: index::Blob,
    },
    GenericParam = 0x2A [sorted by owner, number] {
        number: u16,
        flags: u16,
        owner: index::TypeOrMethodDef,
        name: index::String,
    },
    GenericParamConstraint = 0x2C [sorted by owner] {
        owner: index::Simple<GenericParam>,
        constraint: index::TypeDefOrRef,
    },
    ImplMap = 0x1C [sorted by member_forwarded] {
        mapping_flags: u16,
        member_forwarded: index::MemberForwarded,
        import_name: index::String,
        import_scope: index::Simple<ModuleRef>,
    },
    InterfaceImpl = 0x09 [sorted by class, interface] {
        class: index::Simple<TypeDef>,
        interface: index::TypeDefOrRef,
    },
    ManifestResource = 0x28 {
        offset: u32,
        flags: u32,
        name: index::String,
        implementation: index::Implementation,
    },
    MemberRef = 0x0A {
        class: index::MemberRefParent,
        name: index::String,
        signature: index::Blob,
    },
    MethodDef = 0x06 {
        rva: u32,
        impl_flags: u16,
        flags: u16,
        name: index::String,
        signature: index::Blob,
        param_list: index::Simple<Param>,
    },
    MethodImpl = 0x19 [sorted by class] {
        class: index::Simple<TypeDef>,
        method_body: index::MethodDefOrRef,
        method_declaration: index::MethodDefOrRef,
    },
    MethodSemantics = 0x18 [sorted by association] {
        semantics: u16,
        method: index::Simple<MethodDef>,
        association: index::HasSemantics,
    },
    MethodSpec = 0x2B {
        method: index::MethodDefOrRef,
        instantiation: index::Blob,
    },
    Module = 0x00 {
        generation: u16,
        name: index::String,
        mvid: index::GUID,
        enc_id: index::GUID,
        enc_base_id: index::GUID,
    },
    ModuleRef = 0x1A {
        name: index::String,
    },
    NestedClass = 0x29 [sorted by nested_class] {
        nested_class: index::Simple<TypeDef>,
        enclosing_class: index::Simple<TypeDef>,
    },
    Param = 0x08 {
        flags: u16,
        sequence: u16,
        name: index::String,
    },
    Property = 0x17 {
        flags: u16,
        name: index::String,
        property_type: index::Blob,
    },
    PropertyMap = 0x15 {
        parent: index::Simple<TypeDef>,
        property_list: index::Simple<Property>,
    },
    StandAloneSig = 0x11 {
        signature: index::Blob,
    },
    TypeDef = 0x02 {
        flags: u32,
        type_name: index::String,
        type_namespace: index::String,
        extends: index::TypeDefOrRef,
        field_list: index::Simple<Field>,
        method_list: index::Simple<MethodDef>,
    },
    TypeRef = 0x01 {
        resolution_scope: index::ResolutionScope,
        type_name: index::String,
        type_namespace: index::String,
    },
    TypeSpec = 0x1B {
        signature: index::Blob,
    }
}
