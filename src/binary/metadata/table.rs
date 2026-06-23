//! Metadata table row definitions for the `#~` stream.
//!
//! This module models the logical metadata tables described in `ECMA-335, II.22`.
//! Each table appears as:
//! - a [`Kind`] discriminant whose numeric value is the table id (for example `0x02`
//!   for `TypeDef`), and
//! - a row struct with the same name (for example [`TypeDef`] and [`MethodDef`])
//!   containing one decoded row from that table.
//!
//! Row fields are constants (`u16`, `u32`, etc.) or typed table/heap indices from
//! [`super::index`]. Index widths and coded-index decoding follow the physical
//! metadata layout rules in `ECMA-335, II.24.2.6`.

use super::index;
use bitvec::{order::Lsb0, view::BitView};
use num_derive::{FromPrimitive, ToPrimitive};
use scroll::{
    Pread, Pwrite,
    ctx::{TryFromCtx, TryIntoCtx},
};

// paste!
use paste::paste;

macro_rules! tables {
    ($($(#[$table_meta:meta])* $name:ident = $val:literal $([sorted by $($sort_field:ident),+])? { $($fname:ident: $ty:ty,)+ }),+ $(,)?) => {
        /// Metadata table kind discriminator.
        ///
        /// Each discriminant is the table identifier used in metadata tokens and
        /// table-valid/sorted bitmasks (`ECMA-335, II.22` and `ECMA-335, II.24.2.6`).
        #[derive(Clone, Copy, Debug, Eq, FromPrimitive, Hash, PartialEq, ToPrimitive)]
        pub enum Kind {
            $(
                $(#[$table_meta])*
                $name = $val,
            )*
        }

        $(
            $(#[$table_meta])*
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

            macro_rules! tables_kind_reserve {
                ($tables:ident, $kind:ident, $n:expr) => {
                    match $kind {
                        $(
                            Kind::$name => $tables.[<$name:snake>].reserve($n),
                        )*
                    }
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

/// Associates a metadata row type with its table [`Kind`].
///
/// Implemented by every table row struct in this module.
pub trait HasKind {
    /// Returns the metadata table kind for `Self`.
    fn kind() -> Kind;
}

tables! {
    /// `Assembly` metadata table (`0x20`; `ECMA-335, II.22.2`).
    /// Rows store assembly identity, version, flags, and public key information.
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
    /// `AssemblyOS` metadata table (`0x22`; `ECMA-335, II.22.3`).
    /// Rows store operating-system compatibility triples for an assembly.
    AssemblyOs = 0x22 {
        os_platform_id: u32,
        os_major_version: u32,
        os_minor_version: u32,
    },
    /// `AssemblyProcessor` metadata table (`0x21`; `ECMA-335, II.22.4`).
    /// Rows store processor identifiers associated with an assembly.
    AssemblyProcessor = 0x21 {
        processor: u32,
    },
    /// `AssemblyRef` metadata table (`0x23`; `ECMA-335, II.22.5`).
    /// Rows store versioned references to external assemblies.
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
    /// `AssemblyRefOS` metadata table (`0x25`; `ECMA-335, II.22.6`).
    /// Rows store operating-system constraints for an `AssemblyRef`.
    AssemblyRefOs = 0x25 {
        os_platform_id: u32,
        os_major_version: u32,
        os_minor_version: u32,
        assembly_ref: index::Simple<AssemblyRef>,
    },
    /// `AssemblyRefProcessor` metadata table (`0x24`; `ECMA-335, II.22.7`).
    /// Rows store processor constraints for an `AssemblyRef`.
    AssemblyRefProcessor = 0x24 {
        processor: u32,
        assembly_ref: index::Simple<AssemblyRef>,
    },
    /// `ClassLayout` metadata table (`0x0F`; `ECMA-335, II.22.8`).
    /// Rows store explicit packing and class size for a `TypeDef`.
    ClassLayout = 0x0F [sorted by parent] {
        packing_size: u16,
        class_size: u32,
        parent: index::Simple<TypeDef>,
    },
    /// `Constant` metadata table (`0x0B`; `ECMA-335, II.22.9`).
    /// Rows store compile-time constant values for fields, parameters, or properties.
    Constant = 0x0B [sorted by parent] {
        constant_type: u8,
        padding: u8,
        parent: index::HasConstant,
        value: index::Blob,
    },
    /// `CustomAttribute` metadata table (`0x0C`; `ECMA-335, II.22.10`).
    /// Rows store a custom-attribute constructor reference and serialized value blob.
    CustomAttribute = 0x0C [sorted by parent] {
        parent: index::HasCustomAttribute,
        attr_type: index::CustomAttributeType,
        value: index::Blob,
    },
    /// `DeclSecurity` metadata table (`0x0E`; `ECMA-335, II.22.11`).
    /// Rows store declarative security actions and permission-set blobs.
    DeclSecurity = 0x0E [sorted by parent] {
        action: u16,
        parent: index::HasDeclSecurity,
        permission_set: index::Blob,
    },
    /// `EventMap` metadata table (`0x12`; `ECMA-335, II.22.12`).
    /// Rows map a `TypeDef` to the first row in its contiguous `Event` run.
    EventMap = 0x12 {
        parent: index::Simple<TypeDef>,
        event_list: index::Simple<Event>,
    },
    /// `Event` metadata table (`0x14`; `ECMA-335, II.22.13`).
    /// Rows store event flags, name, and delegate/interface type.
    Event = 0x14 {
        event_flags: u16,
        name: index::String,
        event_type: index::TypeDefOrRef,
    },
    /// `ExportedType` metadata table (`0x27`; `ECMA-335, II.22.14`).
    /// Rows describe public types exported from other files or forwarded to other assemblies.
    ExportedType = 0x27 {
        flags: u32,
        type_def_id: u32, // actually an index::Simple<TypeDef>, but needs to be forced to 4 bytes
        type_name: index::String,
        type_namespace: index::String,
        implementation: index::Implementation,
    },
    /// `Field` metadata table (`0x04`; `ECMA-335, II.22.15`).
    /// Rows define fields with flags, name, and field signature blob.
    Field = 0x04 {
        flags: u16,
        name: index::String,
        signature: index::Blob,
    },
    /// `FieldLayout` metadata table (`0x10`; `ECMA-335, II.22.16`).
    /// Rows give explicit offsets for fields in explicit-layout types.
    FieldLayout = 0x10 [sorted by field] {
        offset: u32,
        field: index::Simple<Field>,
    },
    /// `FieldMarshal` metadata table (`0x0D`; `ECMA-335, II.22.17`).
    /// Rows attach unmanaged marshaling descriptors to fields or parameters.
    FieldMarshal = 0x0D [sorted by parent] {
        parent: index::HasFieldMarshal,
        native_type: index::Blob,
    },
    /// `FieldRVA` metadata table (`0x1D`; `ECMA-335, II.22.18`).
    /// Rows map static fields to initial data at a PE relative virtual address.
    FieldRva = 0x1D [sorted by field] {
        rva: u32,
        field: index::Simple<Field>,
    },
    /// `File` metadata table (`0x26`; `ECMA-335, II.22.19`).
    /// Rows describe files in a multi-file assembly manifest and their hashes.
    File = 0x26 {
        flags: u32,
        name: index::String,
        hash_value: index::Blob,
    },
    /// `GenericParam` metadata table (`0x2A`; `ECMA-335, II.22.20`).
    /// Rows define generic parameter number, attributes, owner, and name.
    GenericParam = 0x2A [sorted by owner, number] {
        number: u16,
        flags: u16,
        owner: index::TypeOrMethodDef,
        name: index::String,
    },
    /// `GenericParamConstraint` metadata table (`0x2C`; `ECMA-335, II.22.21`).
    /// Rows declare one type constraint for a generic parameter.
    GenericParamConstraint = 0x2C [sorted by owner] {
        owner: index::Simple<GenericParam>,
        constraint: index::TypeDefOrRef,
    },
    /// `ImplMap` metadata table (`0x1C`; `ECMA-335, II.22.22`).
    /// Rows map managed methods/fields to imported unmanaged entry points.
    ImplMap = 0x1C [sorted by member_forwarded] {
        mapping_flags: u16,
        member_forwarded: index::MemberForwarded,
        import_name: index::String,
        import_scope: index::Simple<ModuleRef>,
    },
    /// `InterfaceImpl` metadata table (`0x09`; `ECMA-335, II.22.23`).
    /// Rows record interface implementations for each class or interface type.
    InterfaceImpl = 0x09 [sorted by class, interface] {
        class: index::Simple<TypeDef>,
        interface: index::TypeDefOrRef,
    },
    /// `ManifestResource` metadata table (`0x28`; `ECMA-335, II.22.24`).
    /// Rows describe manifest resources, visibility flags, and storage location.
    ManifestResource = 0x28 {
        offset: u32,
        flags: u32,
        name: index::String,
        implementation: index::Implementation,
    },
    /// `MemberRef` metadata table (`0x0A`; `ECMA-335, II.22.25`).
    /// Rows reference fields or methods declared by another parent scope.
    MemberRef = 0x0A {
        class: index::MemberRefParent,
        name: index::String,
        signature: index::Blob,
    },
    /// `MethodDef` metadata table (`0x06`; `ECMA-335, II.22.26`).
    /// Rows define methods with RVA, flags, name, signature, and parameter range.
    MethodDef = 0x06 {
        rva: u32,
        impl_flags: u16,
        flags: u16,
        name: index::String,
        signature: index::Blob,
        param_list: index::Simple<Param>,
    },
    /// `MethodImpl` metadata table (`0x19`; `ECMA-335, II.22.27`).
    /// Rows pair a type with method body/declaration entries used for overrides.
    MethodImpl = 0x19 [sorted by class] {
        class: index::Simple<TypeDef>,
        method_body: index::MethodDefOrRef,
        method_declaration: index::MethodDefOrRef,
    },
    /// `MethodSemantics` metadata table (`0x18`; `ECMA-335, II.22.28`).
    /// Rows associate methods with property/event semantics such as getter or adder.
    MethodSemantics = 0x18 [sorted by association] {
        semantics: u16,
        method: index::Simple<MethodDef>,
        association: index::HasSemantics,
    },
    /// `MethodSpec` metadata table (`0x2B`; `ECMA-335, II.22.29`).
    /// Rows store a generic method plus its instantiation signature blob.
    MethodSpec = 0x2B {
        method: index::MethodDefOrRef,
        instantiation: index::Blob,
    },
    /// `Module` metadata table (`0x00`; `ECMA-335, II.22.30`).
    /// The single row stores module identity fields such as name and MVID.
    Module = 0x00 {
        generation: u16,
        name: index::String,
        mvid: index::GUID,
        enc_id: index::GUID,
        enc_base_id: index::GUID,
    },
    /// `ModuleRef` metadata table (`0x1A`; `ECMA-335, II.22.31`).
    /// Rows name external modules referenced by this module.
    ModuleRef = 0x1A {
        name: index::String,
    },
    /// `NestedClass` metadata table (`0x29`; `ECMA-335, II.22.32`).
    /// Rows link each nested type definition to its enclosing type definition.
    NestedClass = 0x29 [sorted by nested_class] {
        nested_class: index::Simple<TypeDef>,
        enclosing_class: index::Simple<TypeDef>,
    },
    /// `Param` metadata table (`0x08`; `ECMA-335, II.22.33`).
    /// Rows store per-parameter flags, sequence number, and optional name.
    Param = 0x08 {
        flags: u16,
        sequence: u16,
        name: index::String,
    },
    /// `Property` metadata table (`0x17`; `ECMA-335, II.22.34`).
    /// Rows define property flags, name, and property signature blob.
    Property = 0x17 {
        flags: u16,
        name: index::String,
        property_type: index::Blob,
    },
    /// `PropertyMap` metadata table (`0x15`; `ECMA-335, II.22.35`).
    /// Rows map a `TypeDef` to the first row in its contiguous `Property` run.
    PropertyMap = 0x15 {
        parent: index::Simple<TypeDef>,
        property_list: index::Simple<Property>,
    },
    /// `StandAloneSig` metadata table (`0x11`; `ECMA-335, II.22.36`).
    /// Rows store standalone signatures used by locals or call-site specs.
    StandAloneSig = 0x11 {
        signature: index::Blob,
    },
    /// `TypeDef` metadata table (`0x02`; `ECMA-335, II.22.37`).
    /// Rows define types, their base type, and contiguous field/method ranges.
    TypeDef = 0x02 {
        flags: u32,
        type_name: index::String,
        type_namespace: index::String,
        extends: index::TypeDefOrRef,
        field_list: index::Simple<Field>,
        method_list: index::Simple<MethodDef>,
    },
    /// `TypeRef` metadata table (`0x01`; `ECMA-335, II.22.38`).
    /// Rows reference external type names with a resolution scope.
    TypeRef = 0x01 {
        resolution_scope: index::ResolutionScope,
        type_name: index::String,
        type_namespace: index::String,
    },
    /// `TypeSpec` metadata table (`0x1B`; `ECMA-335, II.22.39`).
    /// Rows provide tokens for complex or instantiated type signatures.
    TypeSpec = 0x1B {
        signature: index::Blob,
    },
}
