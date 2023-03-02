use super::{EntryPoint, FieldIndex, MethodIndex, MethodMemberIndex, Resolution, TypeIndex};
use crate::binary::{
    cli::{Header, Metadata, RVASize},
    heap::*,
    metadata::{header, index, table::*},
    method, stream,
};
use crate::convert;
use crate::dll::Result;
use crate::resolved::{
    assembly::HashAlgorithm,
    attribute::Attribute,
    body,
    generic::Variance,
    members::{
        BodyFormat, BodyManagement, CharacterSet, Constant as ConstantValue, FieldReferenceParent, FieldSource,
        MethodReferenceParent, UnmanagedCallingConvention, UserMethod, VtableLayout,
    },
    resource::{Implementation, Visibility},
    signature::CallingConvention,
    types::{Layout, ResolutionScope, TypeImplementation},
};
use object::{
    endian::{LittleEndian, U32Bytes},
    pe,
    write::pe::{Writer as PEWriter, *},
};
use scroll::Pwrite;
use scroll_buffer::DynamicBuffer;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct WriteOptions {
    pub is_32_bit: bool,
    pub is_executable: bool,
}

pub(crate) fn write_impl(res: &Resolution, opts: WriteOptions) -> Result<Vec<u8>> {
    // writer setup
    let mut buffer = vec![];
    let mut writer = PEWriter::new(!opts.is_32_bit, 0x200, 0x200, &mut buffer);

    let mut num_sections = 1; // .text
    if opts.is_executable {
        // add .idata and .reloc
        num_sections += 2;
    }

    // begin reservations

    writer.reserve_dos_header_and_stub();
    writer.reserve_nt_headers(pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    writer.reserve_section_headers(num_sections);

    let mut text = vec![];

    let imports = if opts.is_executable {
        let import_rva = writer.virtual_len();

        let mut idata = Vec::with_capacity(0x100);
        idata.extend(b"mscoree.dll\0");

        macro_rules! current_rva {
            () => {
                import_rva + idata.len() as u32
            };
        }

        let hint_name_rva = current_rva!();
        idata.extend(b"\0\0_CorExeMain\0");

        let import_lookup_rva = current_rva!();
        let mut lookup_table: Vec<u8> = vec![];
        if opts.is_32_bit {
            lookup_table.extend(hint_name_rva.to_le_bytes());
            lookup_table.extend([0; 4]);
        } else {
            lookup_table.extend((hint_name_rva as u64).to_le_bytes());
            lookup_table.extend([0; 8]);
        }
        // write lookup table
        idata.extend_from_slice(&lookup_table);

        // write IAT
        let iat_rva = current_rva!();
        idata.extend(lookup_table);
        writer.set_data_directory(pe::IMAGE_DIRECTORY_ENTRY_IAT, iat_rva, 8);

        macro_rules! u32 {
            ($v:expr) => {
                U32Bytes::new(LittleEndian, $v)
            };
        }

        // write import directory entries
        let directory_rva = current_rva!();
        idata.extend_from_slice(object::pod::bytes_of(&pe::ImageImportDescriptor {
            original_first_thunk: u32!(import_lookup_rva),
            time_date_stamp: u32!(0),
            forwarder_chain: u32!(0),
            name: u32!(import_rva),
            first_thunk: u32!(iat_rva),
        }));
        idata.extend([0; 20]);
        let size = idata.len() as u32;

        // by default, writer.reserve_idata_section() enables IMAGE_SCN_MEM_WRITE, which is forbidden by coreclr
        let section = writer.reserve_section(
            *b".idata\0\0",
            pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ,
            size,
            size,
        );
        writer.set_data_directory(pe::IMAGE_DIRECTORY_ENTRY_IMPORT, directory_rva, 40);

        // write entry point to beginning of text section
        text.extend([0xff, 0x25]);
        text.extend(iat_rva.to_le_bytes());

        Some((idata, section))
    } else {
        None
    };

    let text_rva = writer.virtual_len();
    macro_rules! current_rva {
        () => {
            text_rva + text.len() as u32
        };
    }

    macro_rules! heap_idx {
        ($heap:ident, $val:expr) => {
            $heap.write(&$val)?
        };
    }

    macro_rules! opt_heap {
        ($heap:ident, $val:expr) => {
            match &$val {
                Some(v) => heap_idx!($heap, v),
                None => 0.into(),
            }
        };
    }

    let mut strings = StringsWriter::new();
    let mut blobs = BlobWriter::new();
    let mut guids = GUIDWriter::new();
    let mut userstrings = UserStringWriter::new();

    let mut tables = Tables::new();

    let mut type_cache = HashMap::new();
    let mut blob_scratch = DynamicBuffer::with_increment(8);

    macro_rules! build_ctx {
        () => {
            &mut convert::write::Context {
                blobs: &mut blobs,
                specs: &mut tables.type_spec,
                type_cache: &mut type_cache,
                blob_scratch: &mut blob_scratch,
            }
        };
    }

    let mut attributes: Vec<(&Attribute, index::HasCustomAttribute)> = vec![];

    macro_rules! write_attrs {
        ($a:expr, $parent:ident($idx:expr)) => {
            attributes.extend($a.iter().map(|r| (r, index::HasCustomAttribute::$parent($idx))))
        };
    }

    macro_rules! write_security {
        ($s:expr, $parent:ident($idx:expr)) => {{
            if let Some(s) = $s {
                let idx = tables.decl_security.len() + 1;
                tables.decl_security.push(DeclSecurity {
                    action: s.action,
                    parent: index::HasDeclSecurity::$parent($idx),
                    permission_set: heap_idx!(blobs, &s.value),
                });

                write_attrs!(s.attributes, DeclSecurity(idx));
            }
        }};
    }

    if let Some(a) = &res.assembly {
        tables.assembly.push(Assembly {
            hash_alg_id: match a.hash_algorithm {
                HashAlgorithm::None => 0x0000,
                HashAlgorithm::ReservedMD5 => 0x8003,
                HashAlgorithm::SHA1 => 0x8004,
            },
            major_version: a.version.major,
            minor_version: a.version.minor,
            build_number: a.version.build,
            revision_number: a.version.revision,
            flags: a.flags.to_mask(),
            public_key: opt_heap!(blobs, a.public_key),
            name: heap_idx!(strings, a.name),
            culture: opt_heap!(strings, a.culture),
        });

        write_attrs!(a.attributes, Assembly(1));
        write_security!(&a.security, Assembly(1));
    }

    tables.assembly_ref.reserve(res.assembly_references.len());
    for (idx, a) in res.assembly_references.iter().enumerate() {
        tables.assembly_ref.push(AssemblyRef {
            major_version: a.version.major,
            minor_version: a.version.minor,
            build_number: a.version.build,
            revision_number: a.version.revision,
            flags: a.has_full_public_key as u32,
            public_key_or_token: opt_heap!(blobs, a.public_key_or_token),
            name: heap_idx!(strings, a.name),
            culture: opt_heap!(strings, a.culture),
            hash_value: opt_heap!(blobs, a.hash_value),
        });

        write_attrs!(a.attributes, AssemblyRef(idx + 1));
    }

    tables.exported_type.reserve(res.exported_types.len());
    for (idx, e) in res.exported_types.iter().enumerate() {
        let mut export = ExportedType {
            flags: e.flags.to_mask(),
            type_def_id: 0,
            type_name: heap_idx!(strings, e.name),
            type_namespace: opt_heap!(strings, e.namespace),
            implementation: index::Implementation::Null,
        };

        export.implementation = match e.implementation {
            TypeImplementation::Nested(t) => index::Implementation::ExportedType(t.0 + 1),
            TypeImplementation::ModuleFile { type_def, file } => {
                export.type_def_id = type_def.0 as u32;
                index::Implementation::File(file.0 + 1)
            }
            TypeImplementation::TypeForwarder(a) => {
                export.flags |= 0x0020_0000;
                index::Implementation::AssemblyRef(a.0 + 1)
            }
        };

        write_attrs!(e.attributes, ExportedType(idx + 1));

        tables.exported_type.push(export);
    }

    tables.file.reserve(res.files.len());
    for (idx, f) in res.files.iter().enumerate() {
        tables.file.push(File {
            flags: build_bitmask!(f, has_metadata => 0x0001),
            name: heap_idx!(strings, f.name),
            hash_value: heap_idx!(blobs, f.hash_value),
        });

        write_attrs!(f.attributes, File(idx + 1));
    }

    let mut resources = vec![];

    tables.manifest_resource.reserve(res.manifest_resources.len());
    for (idx, r) in res.manifest_resources.iter().enumerate() {
        let (offset, implementation) = match &r.implementation {
            Implementation::File { location, offset } => (*offset, index::Implementation::File(location.0 + 1)),
            Implementation::Assembly { location, offset } => {
                (*offset, index::Implementation::AssemblyRef(location.0 + 1))
            }
            Implementation::CurrentFile(res) => {
                let offset = resources.len();
                resources.extend((res.len() as u32).to_le_bytes());
                resources.extend_from_slice(res);
                (offset, index::Implementation::Null)
            }
        };

        tables.manifest_resource.push(ManifestResource {
            offset: offset as u32,
            flags: match r.visibility {
                Visibility::Public => 0x0001,
                Visibility::Private => 0x0002,
            },
            name: heap_idx!(strings, r.name),
            implementation,
        });

        write_attrs!(r.attributes, ManifestResource(idx + 1));
    }

    tables.module.push(Module {
        generation: 0,
        name: heap_idx!(strings, res.module.name),
        mvid: heap_idx!(guids, &res.module.mvid),
        enc_id: 0.into(),
        enc_base_id: 0.into(),
    });
    write_attrs!(res.module.attributes, Module(1));

    tables.module_ref.reserve(res.module_references.len());
    for (idx, r) in res.module_references.iter().enumerate() {
        tables.module_ref.push(ModuleRef {
            name: heap_idx!(strings, r.name),
        });

        write_attrs!(r.attributes, ModuleRef(idx + 1));
    }

    let mut method_index_map = HashMap::new();
    let mut field_index_map = HashMap::new();

    macro_rules! build_generic {
            ($gs:expr, $parent:ident($idx:expr)) => {
                tables.generic_param.reserve($gs.len());
                for (idx, g) in $gs.iter().enumerate() {
                    let table_idx = tables.generic_param.len() + 1;
                    tables.generic_param.push(GenericParam {
                        number: idx as u16,
                        flags: match g.variance {
                            Variance::Invariant => 0x0,
                            Variance::Covariant => 0x1,
                            Variance::Contravariant => 0x2,
                        } | build_bitmask!(
                            g.special_constraint,
                            reference_type => 0x04,
                            value_type => 0x08,
                            has_default_constructor => 0x10
                        ),
                        owner: index::TypeOrMethodDef::$parent($idx),
                        name: heap_idx!(strings, g.name),
                    });
                    write_attrs!(g.attributes, GenericParam(table_idx));

                    tables
                        .generic_param_constraint
                        .reserve(g.type_constraints.len());
                    for c in &g.type_constraints {
                        let constraint_idx = tables.generic_param_constraint.len() + 1;
                        tables
                            .generic_param_constraint
                            .push(GenericParamConstraint {
                                owner: table_idx.into(),
                                constraint: convert::write::idx_with_modifiers(
                                    &c.constraint_type,
                                    &c.custom_modifiers,
                                    build_ctx!(),
                                )?,
                            });
                        write_attrs!(c.attributes, GenericParamConstraint(constraint_idx));
                    }
                }
            };
        }

    let mut overrides: Vec<(index::Simple<TypeDef>, _, _)> = Vec::new();
    let mut bodies = Vec::new();

    tables.type_def.reserve(res.type_definitions.len());
    for (idx, t) in res.type_definitions.iter().enumerate() {
        // I think we're supposed to ignore the <Module> type entry
        let simple_idx = (idx + 1).into();

        tables.type_def.push(TypeDef {
            flags: {
                let mut f = t.flags.to_mask();
                if t.security.is_some() {
                    f |= 0x0004_0000;
                }
                f
            },
            type_name: heap_idx!(strings, t.name),
            type_namespace: opt_heap!(strings, t.namespace),
            extends: match &t.extends {
                Some(t) => convert::write::source_index(None, t, build_ctx!())?,
                None => index::TypeDefOrRef::Null,
            },
            // for some reason, things break if I use 0 for null index instead of 1
            // doesn't make any sense, but ildasm fully crashes otherwise
            field_list: (tables.field.len() + 1).into(),
            method_list: if t.methods.is_empty() {
                1
            } else {
                tables.method_def.len() + 1
            }
            .into(),
        });

        build_generic!(t.generic_parameters, TypeDef(idx));

        tables.interface_impl.reserve(t.implements.len());
        for (attrs, i) in &t.implements {
            let impl_idx = tables.interface_impl.len() + 1;
            tables.interface_impl.push(InterfaceImpl {
                class: simple_idx,
                interface: convert::write::source_index(None, i, build_ctx!())?,
            });
            write_attrs!(attrs, InterfaceImpl(impl_idx));
        }

        // ignore <Module> here
        write_attrs!(t.attributes, TypeDef(idx + 1));

        write_security!(&t.security, TypeDef(idx));

        overrides.extend(
            t.overrides
                .iter()
                .map(|o| (simple_idx, o.implementation, o.declaration)),
        );

        match t.flags.layout {
            Layout::Sequential(Some(s)) => {
                tables.class_layout.push(ClassLayout {
                    packing_size: s.packing_size as u16,
                    class_size: s.class_size as u32,
                    parent: simple_idx,
                });
            }
            Layout::Explicit(Some(e)) => {
                tables.class_layout.push(ClassLayout {
                    packing_size: 0,
                    class_size: e.class_size as u32,
                    parent: simple_idx,
                });
            }
            _ => {}
        }

        if let Some(enc) = t.encloser {
            tables.nested_class.push(NestedClass {
                nested_class: simple_idx,
                enclosing_class: enc.0.into(),
            });
        }

        macro_rules! write_pinvoke {
                ($p:expr, $parent:ident($idx:expr)) => {{
                    if let Some(p) = $p {
                        tables.impl_map.push(ImplMap {
                            mapping_flags: build_bitmask!(p,
                                no_mangle => 0x1, supports_last_error => 0x40
                            ) | match p.character_set {
                                CharacterSet::NotSpecified => 0x0,
                                CharacterSet::Ansi => 0x2,
                                CharacterSet::Unicode => 0x4,
                                CharacterSet::Auto => 0x6,
                            } | match p.calling_convention {
                                UnmanagedCallingConvention::Platformapi => 0x100,
                                UnmanagedCallingConvention::Cdecl => 0x200,
                                UnmanagedCallingConvention::Stdcall => 0x300,
                                UnmanagedCallingConvention::Thiscall => 0x400,
                                UnmanagedCallingConvention::Fastcall => 0x500,
                            },
                            member_forwarded: index::MemberForwarded::$parent($idx),
                            import_name: heap_idx!(strings, p.import_name),
                            import_scope: (p.import_scope.0 + 1).into(),
                        });
                    }
                }}
            }

        macro_rules! write_marshal {
            ($spec:expr, $parent:ident($idx:expr)) => {{
                if let Some(s) = $spec {
                    tables.field_marshal.push(FieldMarshal {
                        parent: index::HasFieldMarshal::$parent($idx),
                        native_type: convert::write::into_blob(s, build_ctx!())?,
                    });
                }
            }};
        }

        macro_rules! write_default {
            ($d:expr, $parent:ident($idx:expr)) => {{
                if let Some(c) = $d {
                    use crate::binary::signature::encoded::*;
                    use ConstantValue::*;

                    macro_rules! blob {
                        ($v:expr) => {
                            heap_idx!(blobs, $v.to_le_bytes())
                        };
                    }
                    let (constant_type, value) = match c {
                        Boolean(b) => (ELEMENT_TYPE_BOOLEAN, blob!(*b as u8)),
                        Char(u) => (ELEMENT_TYPE_CHAR, blob!(u)),
                        Int8(i) => (ELEMENT_TYPE_I1, blob!(i)),
                        UInt8(u) => (ELEMENT_TYPE_U1, blob!(u)),
                        Int16(i) => (ELEMENT_TYPE_I2, blob!(i)),
                        UInt16(u) => (ELEMENT_TYPE_U2, blob!(u)),
                        Int32(i) => (ELEMENT_TYPE_I4, blob!(i)),
                        UInt32(u) => (ELEMENT_TYPE_U4, blob!(u)),
                        Int64(i) => (ELEMENT_TYPE_I8, blob!(i)),
                        UInt64(u) => (ELEMENT_TYPE_U8, blob!(u)),
                        Float32(f) => (ELEMENT_TYPE_R4, blob!(f)),
                        Float64(f) => (ELEMENT_TYPE_R8, blob!(f)),
                        String(cs) => (
                            ELEMENT_TYPE_STRING,
                            heap_idx!(
                                blobs,
                                &cs.iter().map(|c| c.to_le_bytes()).flatten().collect::<Vec<_>>()
                            ),
                        ),
                        Null => (ELEMENT_TYPE_CLASS, blob!(0_u32)),
                    };

                    tables.constant.push(Constant {
                        constant_type,
                        padding: 0,
                        parent: index::HasConstant::$parent($idx),
                        value,
                    });
                }
            }};
        }

        field_index_map.reserve(t.fields.len());
        tables.field.reserve(t.fields.len());
        for (internal_idx, f) in t.fields.iter().enumerate() {
            let table_idx = tables.field.len() + 1;
            field_index_map.insert(
                FieldIndex {
                    parent_type: TypeIndex(idx),
                    field: internal_idx,
                },
                table_idx,
            );

            tables.field.push(Field {
                flags: {
                    let mut mask = build_bitmask!(f,
                            static_member => 0x0010,
                            init_only => 0x0020,
                            literal => 0x0040,
                            not_serialized => 0x0080,
                            special_name => 0x0200,
                            runtime_special_name => 0x0400);
                    mask |= f.accessibility.to_mask();
                    if f.pinvoke.is_some() {
                        mask |= 0x2000;
                    }
                    if f.marshal.is_some() {
                        mask |= 0x1000;
                    }
                    if f.default.is_some() {
                        mask |= 0x8000;
                    }
                    if f.initial_value.is_some() {
                        mask |= 0x0100;
                    }
                    mask
                },
                name: heap_idx!(strings, f.name),
                signature: convert::write::field_def(f, build_ctx!())?,
            });

            write_attrs!(f.attributes, Field(table_idx));
            write_pinvoke!(&f.pinvoke, Field(table_idx));
            write_marshal!(f.marshal, Field(table_idx));
            write_default!(&f.default, Field(table_idx));

            if let Some(v) = &f.initial_value {
                tables.field_rva.push(FieldRva {
                    rva: current_rva!(),
                    field: table_idx.into(),
                });
                text.extend_from_slice(v);
            }

            if let Some(o) = f.offset {
                tables.field_layout.push(FieldLayout {
                    offset: o as u32,
                    field: table_idx.into(),
                });
            }
        }

        let mut all_methods: Vec<_> = t
            .methods
            .iter()
            .enumerate()
            .map(|(i, m)| (MethodMemberIndex::Method(i), None, m))
            .collect();

        tables.property.reserve(t.properties.len());
        if !t.properties.is_empty() {
            tables.property_map.push(PropertyMap {
                parent: simple_idx,
                property_list: (tables.property.len() + 1).into(),
            });
        }
        for (prop_idx, p) in t.properties.iter().enumerate() {
            let table_idx = tables.property.len() + 1;
            let association = Some(index::HasSemantics::Property(table_idx));

            tables.property.push(Property {
                flags: {
                    let mut mask = build_bitmask!(p,
                            special_name => 0x0200,
                            runtime_special_name => 0x0400);
                    if p.default.is_some() {
                        mask |= 0x1000;
                    }
                    mask
                },
                name: heap_idx!(strings, p.name),
                property_type: convert::write::property(p, build_ctx!())?,
            });

            write_attrs!(p.attributes, Property(table_idx));
            write_default!(&p.default, Property(table_idx));

            all_methods.extend(
                p.other
                    .iter()
                    .enumerate()
                    .map(|(i, o)| {
                        (
                            MethodMemberIndex::PropertyOther {
                                property: prop_idx,
                                other: i,
                            },
                            o,
                        )
                    })
                    .chain(
                        p.getter
                            .as_ref()
                            .map(|g| (MethodMemberIndex::PropertyGetter(prop_idx), g)),
                    )
                    .chain(
                        p.setter
                            .as_ref()
                            .map(|g| (MethodMemberIndex::PropertySetter(prop_idx), g)),
                    )
                    .map(|(i, m)| (i, association, m)),
            );
        }

        tables.event.reserve(t.events.len());
        if !t.events.is_empty() {
            tables.event_map.push(EventMap {
                parent: simple_idx,
                event_list: (tables.event.len() + 1).into(),
            });
        }
        for (event_idx, e) in t.events.iter().enumerate() {
            let table_idx = tables.event.len() + 1;
            let association = Some(index::HasSemantics::Event(table_idx));

            tables.event.push(Event {
                event_flags: build_bitmask!(e,
                        special_name => 0x0200,
                        runtime_special_name => 0x0400),
                name: heap_idx!(strings, e.name),
                event_type: convert::write::index(&e.delegate_type, build_ctx!())?,
            });

            write_attrs!(e.attributes, Event(table_idx));

            all_methods.extend(
                [
                    (MethodMemberIndex::EventAdd(event_idx), &e.add_listener),
                    (MethodMemberIndex::EventRemove(event_idx), &e.remove_listener),
                ]
                .into_iter()
                .chain(
                    e.raise_event
                        .as_ref()
                        .map(|r| (MethodMemberIndex::EventRaise(event_idx), r)),
                )
                .chain(e.other.iter().enumerate().map(|(i, o)| {
                    (
                        MethodMemberIndex::EventOther {
                            event: event_idx,
                            other: i,
                        },
                        o,
                    )
                }))
                .map(|(i, m)| (i, association, m)),
            );
        }

        method_index_map.reserve(all_methods.len());
        tables.method_def.reserve(all_methods.len());
        for (member_idx, assoc, m) in all_methods {
            let def_index = tables.method_def.len() + 1;
            method_index_map.insert(
                MethodIndex {
                    parent_type: TypeIndex(idx),
                    member: member_idx,
                },
                def_index,
            );

            if let Some(association) = assoc {
                tables.method_semantics.push(MethodSemantics {
                    semantics: match member_idx {
                        MethodMemberIndex::PropertyGetter(_) => 0x0002,
                        MethodMemberIndex::PropertySetter(_) => 0x0001,
                        MethodMemberIndex::PropertyOther { .. } | MethodMemberIndex::EventOther { .. } => 0x0004,
                        MethodMemberIndex::EventAdd(_) => 0x0008,
                        MethodMemberIndex::EventRemove(_) => 0x0010,
                        MethodMemberIndex::EventRaise(_) => 0x0020,
                        _ => unreachable!(),
                    },
                    method: def_index.into(),
                    association,
                });
            }

            // all methods must be entered in the index_map before we start writing bodies
            // so just set all RVAs to 0 right now and we'll go back and get them later
            if let Some(b) = &m.body {
                bodies.push((tables.method_def.len(), b));
            }
            tables.method_def.push(MethodDef {
                rva: 0,
                impl_flags: {
                    let mut mask = build_bitmask!(m,
                            forward_ref => 0x0010,
                            preserve_sig => 0x0080,
                            synchronized => 0x0020,
                            no_inlining => 0x0008,
                            no_optimization => 0x0040);
                    mask |= match m.body_format {
                        BodyFormat::IL => 0x0,
                        BodyFormat::Native => 0x1,
                        BodyFormat::Runtime => 0x3,
                    };
                    mask |= match m.body_management {
                        BodyManagement::Unmanaged => 0x4,
                        BodyManagement::Managed => 0x0,
                    };
                    mask
                },
                flags: {
                    let mut mask = build_bitmask!(m,
                            sealed => 0x0020,
                            virtual_member => 0x0040,
                            hide_by_sig => 0x0080,
                            strict => 0x0200,
                            abstract_member => 0x0400,
                            special_name => 0x0800,
                            runtime_special_name => 0x1000,
                            require_sec_object => 0x8000);
                    if m.is_static() {
                        mask |= 0x0010;
                    }
                    mask |= m.accessibility.to_mask();
                    mask |= match m.vtable_layout {
                        VtableLayout::ReuseSlot => 0x0000,
                        VtableLayout::NewSlot => 0x0100,
                    };
                    if m.pinvoke.is_some() {
                        mask |= 0x2000;
                    }
                    if m.security.is_some() {
                        mask |= 0x4000;
                    }
                    mask
                },
                name: heap_idx!(strings, &m.name),
                signature: {
                    let ctx = build_ctx!();
                    if m.generic_parameters.is_empty() {
                        convert::write::method_def(&m.signature, ctx)?
                    } else {
                        let mut sig = m.signature.clone();
                        sig.calling_convention = CallingConvention::Generic(m.generic_parameters.len());
                        convert::write::method_def(&sig, ctx)?
                    }
                },
                param_list: (tables.param.len() + 1).into(),
            });

            build_generic!(m.generic_parameters, MethodDef(def_index));

            write_attrs!(m.attributes, MethodDef(def_index));
            write_pinvoke!(&m.pinvoke, MethodDef(def_index));
            write_security!(&m.security, MethodDef(def_index));

            tables.param.reserve(m.parameter_metadata.len());
            for (idx, p) in std::iter::once(&m.return_type_metadata)
                .chain(m.parameter_metadata.iter())
                .enumerate()
            {
                if let Some(p) = p {
                    let param_idx = tables.param.len() + 1;

                    tables.param.push(Param {
                        flags: {
                            let mut mask = build_bitmask!(p,
                                    is_in => 0x0001,
                                    is_out => 0x0002,
                                    optional => 0x0010);
                            if p.default.is_some() {
                                mask |= 0x1000;
                            }
                            if p.marshal.is_some() {
                                mask |= 0x2000;
                            }
                            mask
                        },
                        sequence: idx as u16,
                        name: opt_heap!(strings, p.name),
                    });

                    write_attrs!(p.attributes, Param(param_idx));
                    write_marshal!(p.marshal, Param(param_idx));
                    write_default!(&p.default, Param(param_idx));
                }
            }
        }
    }

    // NOTE: method ref indexes are the same as member ref indexes
    // field refs come after method refs in the member ref table, so their indexes are offset by method_ref.len()

    let user_method = |u: UserMethod| match u {
        UserMethod::Definition(m) => index::MethodDefOrRef::MethodDef(method_index_map[&m]),
        UserMethod::Reference(r) => index::MethodDefOrRef::MemberRef(r.0 + 1),
    };

    let field_offset = res.method_references.len();
    let field_source = |f: FieldSource| match f {
        FieldSource::Definition(d) => index::Token {
            target: index::TokenTarget::Table(Kind::Field),
            index: field_index_map[&d],
        },
        FieldSource::Reference(r) => index::Token {
            target: index::TokenTarget::Table(Kind::MemberRef),
            index: r.0 + 1 + field_offset,
        },
    };

    for (def_idx, body) in bodies {
        let ctx = build_ctx!();
        let m_ctx = &mut convert::write::MethodContext {
            stand_alone_sigs: &mut tables.stand_alone_sig,
            method_specs: &mut tables.method_spec,
            userstrings: &mut userstrings,
            user_method: &user_method,
            field_source: &field_source,
        };

        let mut instructions: Vec<_> = body
            .instructions
            .iter()
            .map(|i| convert::write::instruction(i, ctx, m_ctx))
            .collect::<Result<_>>()?;
        let mut offsets: Vec<_> = instructions
            .iter()
            .scan(0, |state, i| {
                let my_offset = *state;
                *state += i.bytesize();
                Some(my_offset)
            })
            .collect();

        use crate::binary::il::Instruction;

        let mut n_short = 0;
        let mut deltas = vec![];
        for i in &instructions {
            use Instruction::*;

            deltas.push(3 * n_short);
            if matches!(i, Beq(o) | Bge(o) | BgeUn(o) | Bgt(o) | BgtUn(o) | Ble(o) | BleUn(o) | Blt(o) | BltUn(o)
                    | BneUn(o) | Br(o) | Brfalse(o) | Brtrue(o) | Leave(o) if i8::try_from(*o).is_ok())
            {
                n_short += 1;
            }
        }
        for (offset, delta) in offsets.iter_mut().zip(deltas.into_iter()) {
            *offset -= delta;
        }

        for (idx, i) in instructions.iter_mut().enumerate() {
            let bytesize = i.bytesize();
            let convert_offset = |o: &mut i32, can_shorten: bool| {
                let base = offsets[idx] + bytesize;
                let target = offsets[*o as usize];
                *o = (target as i32) - (base as i32);
                if can_shorten && i8::try_from(*o).is_ok() {
                    // this instruction will become 3 bytes shorter, need to adjust offset for change in bytesize
                    *o += 3;
                }
            };

            use paste::paste;
            macro_rules! build_match {
                    ($($ins:ident),+) => {
                        match i {
                            $(
                                Instruction::$ins(o) => {
                                    convert_offset(o, true);
                                    if let Ok(int) = i8::try_from(*o) {
                                        *i = paste! { Instruction::[<$ins S>](int) };
                                    }
                                }
                            )+
                            Instruction::Switch(os) => os.iter_mut().for_each(|o| convert_offset(o, false)),
                            _ => {}
                        }
                    }
                }

            build_match!(Beq, Bge, BgeUn, Bgt, BgtUn, Ble, BleUn, Blt, BltUn, BneUn, Br, Brfalse, Brtrue, Leave);
        }

        let body_size = instructions.iter().map(Instruction::bytesize).sum();

        let mut data_sections: Vec<_> = body
            .data_sections
            .iter()
            .map(|d| {
                let section = match d {
                    body::DataSection::Unrecognized { fat, size } => method::SectionKind::Unrecognized {
                        is_fat: *fat,
                        length: *size,
                    },
                    body::DataSection::ExceptionHandlers(es) => {
                        let exs = es
                            .iter()
                            .map(|e| {
                                use body::ExceptionKind::*;

                                let class_token_or_filter = match &e.kind {
                                    TypedException(t) => {
                                        let mut buf = [0; 4];
                                        buf.pwrite(index::Token::from(convert::write::index(t, build_ctx!())?), 0)?;
                                        u32::from_le_bytes(buf)
                                    }
                                    Filter { offset } => offsets[*offset] as u32,
                                    _ => 0,
                                };

                                let convert_pair = |off: usize, len: usize| {
                                    (
                                        offsets[off] as u32,
                                        instructions[off..off + len].iter().map(|i| i.bytesize() as u32).sum(),
                                    )
                                };

                                let (try_offset, try_length) = convert_pair(e.try_offset, e.try_length);
                                let (handler_offset, handler_length) = convert_pair(e.handler_offset, e.handler_length);

                                Ok(method::Exception {
                                    flags: match &e.kind {
                                        TypedException(_) => 0x0,
                                        Filter { .. } => 0x1,
                                        Finally => 0x2,
                                        Fault => 0x4,
                                    },
                                    try_offset,
                                    try_length,
                                    handler_offset,
                                    handler_length,
                                    class_token_or_filter,
                                })
                            })
                            .collect::<Result<_>>()?;
                        method::SectionKind::Exceptions(exs)
                    }
                };
                Ok(method::DataSection {
                    section,
                    more_sections: true,
                })
            })
            .collect::<Result<_>>()?;
        if let Some(last) = data_sections.last_mut() {
            last.more_sections = false;
        }

        let m = method::Method {
            header: if body_size < 64
                && body.header.maximum_stack_size <= 8
                && body.header.local_variables.is_empty()
                && !body.header.initialize_locals
                && body.data_sections.is_empty()
            {
                method::Header::Tiny { size: body_size }
            } else {
                let local_var_sig_tok = if body.header.local_variables.is_empty() {
                    0
                } else {
                    tables.stand_alone_sig.push(StandAloneSig {
                        signature: convert::write::local_vars(&body.header.local_variables, build_ctx!())?,
                    });

                    let mut buf = [0_u8; 4];
                    buf.pwrite(
                        index::Token {
                            target: index::TokenTarget::Table(Kind::StandAloneSig),
                            index: tables.stand_alone_sig.len(),
                        },
                        0,
                    )?;
                    u32::from_le_bytes(buf)
                };

                method::Header::Fat {
                    more_sects: !body.data_sections.is_empty(),
                    init_locals: body.header.initialize_locals,
                    max_stack: body.header.maximum_stack_size as u16,
                    size: body_size,
                    local_var_sig_tok,
                }
            },
            body: instructions,
            data_sections,
        };

        // fat method headers must be aligned
        if matches!(m.header, method::Header::Fat { .. }) {
            let to_align = text.len() % 4;
            if to_align != 0 {
                text.extend(vec![0; 4 - to_align]);
            }
        }

        tables.method_def[def_idx].rva = current_rva!();

        let mut buf = DynamicBuffer::with_increment(16);
        buf.pwrite(m, 0)?;

        text.extend_from_slice(buf.get());
    }

    tables
        .method_impl
        .extend(overrides.into_iter().map(|(parent, body, decl)| MethodImpl {
            class: parent,
            method_body: user_method(body),
            method_declaration: user_method(decl),
        }));

    macro_rules! type_to_parent {
        ($t:expr) => {
            match convert::write::index($t, build_ctx!())? {
                index::TypeDefOrRef::TypeDef(d) => index::MemberRefParent::TypeDef(d),
                index::TypeDefOrRef::TypeRef(r) => index::MemberRefParent::TypeRef(r),
                index::TypeDefOrRef::TypeSpec(s) => index::MemberRefParent::TypeSpec(s),
                _ => unreachable!(),
            }
        };
    }

    tables
        .member_ref
        .reserve(res.method_references.len() + res.field_references.len());
    for (idx, m) in res.method_references.iter().enumerate() {
        tables.member_ref.push(MemberRef {
            class: match &m.parent {
                MethodReferenceParent::Type(t) => type_to_parent!(t),
                MethodReferenceParent::Module(m) => index::MemberRefParent::ModuleRef(m.0 + 1),
                MethodReferenceParent::VarargMethod(m) => index::MemberRefParent::MethodDef(method_index_map[m]),
            },
            name: heap_idx!(strings, m.name),
            signature: convert::write::method_ref(&m.signature, build_ctx!())?,
        });

        write_attrs!(m.attributes, MemberRef(idx + 1));
    }
    for (idx, f) in res.field_references.iter().enumerate() {
        tables.member_ref.push(MemberRef {
            class: match &f.parent {
                FieldReferenceParent::Type(t) => type_to_parent!(t),
                FieldReferenceParent::Module(m) => index::MemberRefParent::ModuleRef(m.0 + 1),
            },
            name: heap_idx!(strings, f.name),
            signature: convert::write::field_ref(f, build_ctx!())?,
        });

        write_attrs!(f.attributes, MemberRef(field_offset + idx + 1));
    }

    tables.type_ref.reserve(res.type_references.len());
    for (idx, r) in res.type_references.iter().enumerate() {
        tables.type_ref.push(TypeRef {
            resolution_scope: match r.scope {
                ResolutionScope::Nested(t) => index::ResolutionScope::TypeRef(t.0 + 1),
                ResolutionScope::ExternalModule(m) => index::ResolutionScope::ModuleRef(m.0 + 1),
                ResolutionScope::CurrentModule => index::ResolutionScope::Module(1),
                ResolutionScope::Assembly(a) => index::ResolutionScope::AssemblyRef(a.0 + 1),
                ResolutionScope::Exported => index::ResolutionScope::Null,
            },
            type_name: heap_idx!(strings, r.name),
            type_namespace: opt_heap!(strings, r.namespace),
        });

        write_attrs!(r.attributes, TypeRef(idx + 1));
    }

    tables.custom_attribute.reserve(attributes.len());
    for (a, parent) in attributes {
        tables.custom_attribute.push(CustomAttribute {
            parent,
            attr_type: match a.constructor {
                UserMethod::Definition(m) => index::CustomAttributeType::MethodDef(method_index_map[&m]),
                UserMethod::Reference(r) => index::CustomAttributeType::MemberRef(r.0 + 1),
            },
            value: opt_heap!(blobs, a.value.as_ref()),
        });
    }

    let entry_point_token = match res.entry_point {
        Some(e) => {
            let tok = match e {
                EntryPoint::Method(m) => index::Token {
                    target: index::TokenTarget::Table(Kind::MethodDef),
                    index: method_index_map[&m],
                },
                EntryPoint::File(f) => index::Token {
                    target: index::TokenTarget::Table(Kind::File),
                    index: f.0 + 1,
                },
            };

            let mut buf = [0_u8; 4];
            buf.pwrite(tok, 0)?;
            u32::from_le_bytes(buf)
        }
        None => 0,
    };

    // begin writing

    let strings_vec = strings.into_vec();
    let guids_vec = guids.into_vec();
    let blobs_vec = blobs.into_vec();
    let userstrings_vec = userstrings.into_vec();

    let header = header::Header {
        reserved0: 0,
        major_version: 2,
        minor_version: 0,
        heap_sizes: {
            let mut mask = 0;

            if strings_vec.len() >= (1_usize << 16) {
                mask |= 0x01;
            }
            if guids_vec.len() >= (1_usize << 16) {
                mask |= 0x02;
            }
            if blobs_vec.len() >= (1_usize << 16) {
                mask |= 0x04;
            }

            mask
        },
        reserved1: 1,
        valid: tables.valid_mask(),
        sorted: Tables::sorted_mask(),
        tables,
    };

    let mut header_buf = DynamicBuffer::with_increment(32);
    header_buf.pwrite(header, 0)?;
    let header_stream = header_buf.get();

    const VERSION_STRING: &str = "Standard CLI 2005";

    let streams: Vec<_> = [
        (header_stream, "#~"),
        (&strings_vec, StringsReader::NAME),
        (&guids_vec, GUIDReader::NAME),
        (&blobs_vec, BlobReader::NAME),
        (&userstrings_vec, UserStringReader::NAME),
    ]
    .into_iter()
    .filter(|(s, _)| !s.is_empty())
    .collect();

    // ECMA-335, II.24.2.1 (page 271)
    let root_and_header_size: usize = 20_usize
        + crate::utils::round_up_to_4(VERSION_STRING.len() + 1_usize).0
        + streams
            .iter()
            .map(|(_, n)| {
                // add offset and size fields
                8 + crate::utils::round_up_to_4(n.len() + 1).0
            })
            .sum::<usize>();

    let metadata_rva = current_rva!();

    let mut metadata_buf = vec![0_u8; root_and_header_size];
    metadata_buf.pwrite(
        Metadata {
            signature: 0x424A_5342, // magic value, same page of ECMA as above
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            version: VERSION_STRING,
            flags: 0,
            stream_headers: streams
                .iter()
                .scan(root_and_header_size, |offset, (s, name)| {
                    let prev = *offset;
                    let size = s.len();
                    *offset += size;

                    Some(stream::Header {
                        offset: prev as u32,
                        size: size as u32,
                        name,
                    })
                })
                .collect(),
        },
        0,
    )?;
    for (s, _) in streams {
        metadata_buf.extend(s);
    }

    let metadata_len = metadata_buf.len();
    text.extend(metadata_buf);

    let resources_rva = RVASize {
        rva: current_rva!(),
        size: resources.len() as u32,
    };
    text.extend(resources);

    let cli_rva = current_rva!();
    let cli_header = Header {
        cb: 72,
        major_runtime_version: 0,
        minor_runtime_version: 0,
        metadata: RVASize {
            rva: metadata_rva,
            size: metadata_len as u32,
        },
        flags: pe::COMIMAGE_FLAGS_ILONLY,
        entry_point_token,
        resources: resources_rva,
        strong_name_signature: RVASize::default(),
        code_manager_table: RVASize::default(),
        vtable_fixups: RVASize::default(),
        export_address_table_jumps: RVASize::default(),
        managed_native_header: RVASize::default(),
    };
    let mut header_buf = [0_u8; 72];
    header_buf.pwrite_with(cli_header, 0, scroll::LE)?;
    text.extend(header_buf);

    writer.set_data_directory(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, cli_rva, 72);

    let text_range = writer.reserve_text_section(text.len() as u32);

    if opts.is_executable {
        writer.add_reloc(
            text_range.virtual_address,
            if opts.is_32_bit {
                pe::IMAGE_REL_BASED_HIGHLOW
            } else {
                pe::IMAGE_REL_BASED_DIR64
            },
        );
        writer.reserve_reloc_section();
    }

    // begin writing

    // because this is just writing to a Vec, the buffer always succeeds to allocate and there's no need to handle the error
    writer.write_dos_header_and_stub().unwrap();
    writer.write_nt_headers(NtHeaders {
        machine: if opts.is_32_bit {
            pe::IMAGE_FILE_MACHINE_I386
        } else {
            pe::IMAGE_FILE_MACHINE_AMD64
        },
        time_date_stamp: match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as u32,
            _ => 0,
        },
        characteristics: {
            let mut flags = pe::IMAGE_FILE_EXECUTABLE_IMAGE;
            if !opts.is_executable {
                flags |= pe::IMAGE_FILE_DLL;
            }
            flags
        },
        major_linker_version: 6,
        minor_linker_version: 0,
        address_of_entry_point: if opts.is_executable {
            text_range.virtual_address
        } else {
            0
        },
        image_base: 0x0040_0000,
        major_operating_system_version: 5,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 5,
        minor_subsystem_version: 0,
        subsystem: pe::IMAGE_SUBSYSTEM_WINDOWS_CUI,
        dll_characteristics: 0,
        size_of_stack_reserve: 0x0010_0000,
        size_of_stack_commit: 0x1000,
        size_of_heap_reserve: 0x0010_0000,
        size_of_heap_commit: 0x1000,
    });
    writer.write_section_headers();
    if let Some((idata, section)) = imports {
        writer.write_section(section.file_offset, &idata);
    }
    writer.write_section(text_range.file_offset, &text);
    // ignored if no relocs have been set
    writer.write_reloc_section();

    Ok(buffer)
}
