use super::index;
use num_derive::FromPrimitive;
use scroll::{ctx::TryFromCtx, Pread};

macro_rules! tables {
    ($($name:ident = $val:literal { $($fname:ident: $ty:ty,)+ },)+) => {
        #[derive(Clone, Copy, Debug, Eq, FromPrimitive, Hash, PartialEq)]
        pub enum Kind {
            $(
                $name = $val,
            )*
            Unused = 0xFF
        }

        $(
            #[derive(Clone, Copy, Debug)]
            pub struct $name {
                $(pub $fname: $ty,)*
            }

            impl HasKind for $name {
                fn get_kind() -> Kind {
                    Kind::$name
                }
            }

            impl<'a> TryFromCtx<'a, index::Context<'a>> for $name {
                type Error = scroll::Error;

                fn try_from_ctx(from: &[u8], ctx: index::Context<'a>) -> Result<(Self, usize), Self::Error> {
                    let offset = &mut 0;

                    Ok(($name {
                        $($fname: from.gread_with(offset, ctx)?,)*
                    }, *offset))
                }
            }
        )*

        #[derive(Debug)]
        pub enum Table {
            $($name($name),)*
        }

        macro_rules! build_match {
            ($kind:ident, $from:ident, $offset:ident, $ctx:ident) => {
                match $kind {
                    $(
                        Kind::$name => Table::$name($from.gread_with::<$name>($offset, $ctx)?),
                    )*
                    Kind::Unused => unreachable!()
                }
            };
        }
    };
}

pub trait HasKind {
    fn get_kind() -> Kind;
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
    AssemblyOS = 0x22 {
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
    AssemblyRefOS = 0x25 {
        os_platform_id: u32,
        os_major_version: u32,
        os_minor_version: u32,
        assembly_ref: index::Simple<AssemblyRef>,
    },
    AssemblyRefProcessor = 0x24 {
        processor: u32,
        assembly_ref: index::Simple<AssemblyRef>,
    },
    ClassLayout = 0x0F {
        packing_size: u16,
        class_size: u16,
        parent: index::Simple<TypeDef>,
    },
    Constant = 0x0B {
        r#type: u8,
        padding: u8,
        parent: index::HasConstant,
        value: index::Blob,
    },
    CustomAttribute = 0x0C {
        parent: index::HasCustomAttribute,
        r#type: index::CustomAttributeType,
        value: index::Blob,
    },
    DeclSecurity = 0x0E {
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
    FieldLayout = 0x10 {
        offset: u32,
        field: index::Simple<Field>,
    },
    FieldMarshal = 0x0D {
        parent: index::HasFieldMarshal,
        native_type: index::Blob,
    },
    FieldRVA = 0x1D {
        rva: u32,
        field: index::Simple<Field>,
    },
    File = 0x26 {
        flags: u32,
        name: index::String,
        hash_value: index::Blob,
    },
    GenericParam = 0x2A {
        number: u16,
        flags: u16,
        owner: index::TypeOrMethodDef,
        name: index::String,
    },
    GenericParamConstraint = 0x2C {
        owner: index::Simple<GenericParam>,
        constraint: index::TypeDefOrRef,
    },
    ImplMap = 0x1C {
        mapping_flags: u16,
        member_forwarded: index::MemberForwarded,
        import_name: index::String,
        import_scope: index::Simple<ModuleRef>,
    },
    InterfaceImpl = 0x09 {
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
    MethodImpl = 0x19 {
        class: index::Simple<TypeDef>,
        method_body: index::MethodDefOrRef,
        method_declaration: index::MethodDefOrRef,
    },
    MethodSemantics = 0x18 {
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
    NestedClass = 0x29 {
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
        r#type: index::Blob,
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
    },
}
