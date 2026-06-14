use super::{
    AssemblyRefIndex, EntryPoint, ExportedTypeIndex, FieldIndex, FileIndex, MethodIndex, MethodMemberIndex,
    MethodRefIndex, ModuleRefIndex, Resolution, TypeIndex, TypeRefIndex, lazy,
};
use crate::binary::{heap::*, metadata};
use crate::convert::{self, TypeKind};
use crate::dll::{DLL, DLLError::*, Result};
use crate::prelude::generic::{Constraint, Generic, SpecialConstraint, Variance};
use crate::resolved::{types::MemberType, *};
use rustc_hash::FxHashMap as HashMap;
use scroll::Pread;
use std::{borrow::Cow, sync::Arc};
use tracing::{debug, warn};

/// A dictionary of options for [`Resolution::parse`] and [`DLL::resolve`].
#[derive(Debug, Default, Copy, Clone)]
pub struct Options {
    /// If this flag is set, [`Resolution::parse`] and [`DLL::resolve`] will not resolve the bodies of class methods,
    /// meaning [`Method::body`](members::Method::body) will always be `None`.
    ///
    /// [`Default`] value of `false`.
    pub skip_method_bodies: bool,

    /// If this flag is set, method bodies are decoded on first access via
    /// [`Resolution::method_body`] rather than eagerly during parsing.
    ///
    /// In lazy mode [`Method::body`](members::Method::body) is always `None` regardless of
    /// whether the method is abstract. Use [`Resolution::method_body`] to retrieve a body;
    /// check [`Method::abstract_member`](members::Method::abstract_member) to determine whether
    /// a body exists at all.
    ///
    /// Decoding errors (malformed IL) are deferred to the first call of
    /// [`Resolution::method_body`] rather than failing the initial parse.
    ///
    /// [`Default`] value of `false`.
    pub lazy_method_bodies: bool,

    /// If this flag is set, method signatures are decoded on first access via
    /// [`Resolution::method_signature`] / [`Resolution::method_ref_signature`] rather than
    /// eagerly during parsing.
    ///
    /// In lazy mode [`Method::signature`](members::Method::signature) and
    /// [`ExternalMethodReference::signature`](members::ExternalMethodReference::signature) hold a
    /// placeholder value (`ManagedMethod::default()`). Use [`Resolution::method_signature`] and
    /// [`Resolution::method_ref_signature`] to retrieve the real decoded signature.
    ///
    /// Decoding errors are deferred to the first accessor call for that method and are not cached
    /// — retried on the next call.
    ///
    /// This option is independent of `lazy_method_bodies` and can be combined with it.
    ///
    /// [`Default`] value of `false`.
    pub lazy_method_signatures: bool,

    /// If this flag is set, custom attributes are not distributed to their parent elements during
    /// parsing. Instead, they are resolved on demand via the accessor methods
    /// [`Resolution::type_attributes`], [`Resolution::method_attributes`],
    /// [`Resolution::field_attributes`], and [`Resolution::assembly_attributes`].
    ///
    /// **What changes in lazy mode:**
    /// - `TypeDefinition::attributes`, `Method::attributes`, `Field::attributes`, and
    ///   `Assembly::attributes` are always **empty** — reads will silently return no attributes.
    /// - Use the accessor methods above to retrieve attributes for any element.
    /// - Accessor methods always return `Vec<Attribute>` (owned). In eager mode they clone from the
    ///   already-populated field; in lazy mode they resolve and allocate on each call, but avoid the
    ///   upfront cost of distributing all attributes at parse time.
    ///
    /// **What does not change:**
    /// - Attribute *values* (the serialized blob) are already lazy-decoded in both modes — calling
    ///   [`Attribute::instantiation_data`](crate::resolved::attribute::Attribute::instantiation_data)
    ///   is always deferred until explicitly requested. This flag only defers the *distribution*
    ///   (iterating the table and routing each attribute to its parent element), not the value decode.
    /// - Elements not covered by the four accessors (e.g. `TypeReference::attributes`,
    ///   `ExternalMethodReference::attributes`, parameter attributes, generic parameter attributes)
    ///   are still distributed eagerly — only the four high-traffic targets are lazy.
    ///
    /// **Performance note:** skipping distribution saves ~8–10 % of total parse time for large
    /// assemblies (e.g. `System.Private.CoreLib`) when only a small subset of elements are
    /// inspected. If a workload touches attributes on most elements the savings are minimal.
    ///
    /// This option is independent of all other lazy options and can be combined freely.
    ///
    /// [`Default`] value of `false`.
    pub lazy_attributes: bool,
}

macro_rules! throw {
    ($($arg:tt)*) => {
        return Err(CLI(scroll::Error::Custom(format!($($arg)*))))
    }
}

macro_rules! heap_idx {
    ($heap:ident, $idx:expr) => {
        Cow::Borrowed($heap.at_index($idx)?)
    };
}

macro_rules! optional_idx {
    ($heap:ident, $idx:expr) => {
        if $idx.is_null() {
            None
        } else {
            Some(heap_idx!($heap, $idx))
        }
    };
}

macro_rules! build_version {
    ($src:ident) => {
        Version {
            major: $src.major_version,
            minor: $src.minor_version,
            build: $src.build_number,
            revision: $src.revision_number,
        }
    };
}

// this allows us to initialize the Vec out of order
// we consider it safe because we assert that the body will fully initialize everything
// it's much simpler and more efficient than trying to use a HashMap or something
macro_rules! build_vec {
    ($name:ident = $t:ty[$len:expr], $body:expr) => {
        let mut $name = vec![std::mem::MaybeUninit::uninit(); $len];
        $body;
        // see transmute docs: this makes sure the original vector is not dropped
        let mut $name = std::mem::ManuallyDrop::new($name);
        // SAFETY: MaybeUninit<T> has the same layout as T, so the following pointer cast is legal
        // this is just to avoid copying the Vec<MaybeUninit<T>> version into a new Vec
        #[allow(unused_mut)]
        let mut $name = unsafe { Vec::from_raw_parts($name.as_mut_ptr().cast::<$t>(), $name.len(), $name.capacity()) };
    };
}

macro_rules! stage_start {
    ($start:ident) => {
        #[cfg(feature = "stage-timing")]
        let $start = std::time::Instant::now();
    };
}

macro_rules! stage_end {
    ($start:ident, $name:literal) => {
        #[cfg(feature = "stage-timing")]
        {
            let elapsed = $start.elapsed();
            debug!(
                stage = $name,
                elapsed_ns = elapsed.as_nanos() as u64,
                elapsed = ?elapsed,
                "read_impl stage timing"
            );
        }
    };
}

// since we're dealing with raw indices and not references, we have to think about what the other indices are pointing to
// if we remove an element, all the indices above it need to be adjusted accordingly for future iterations
fn extract_method<'a>(
    parent: &mut types::TypeDefinition<'a>,
    idx: MethodIndex,
    methods: &mut [MethodIndex],
    tables: &metadata::table::Tables,
) -> members::Method<'a> {
    let MethodMemberIndex::Method(internal_idx) = idx.member else {
        unreachable!()
    };

    if let Ok(start_idx) = methods.binary_search_by_key(&idx.parent_type, |m| m.parent_type) {
        // first element is the index into methods, second element is the internal index
        let mut max_internal: Option<(usize, usize)> = None;

        // look for the maximum internal index for all methods in the same type
        let mut find_max = |start: usize, inc: isize, stop: usize| {
            let mut current_index = start;
            while methods[current_index].parent_type == idx.parent_type {
                if let MethodMemberIndex::Method(i) = methods[current_index].member {
                    match &max_internal {
                        Some((_, max_i)) if i <= *max_i => {}
                        _ => {
                            max_internal = Some((current_index, i));
                        }
                    }
                }
                if current_index == stop {
                    break;
                }
                current_index = current_index.checked_add_signed(inc).unwrap();
            }
        };

        // since we only sorted on parent_type, we could land anywhere in the group with the same parent
        // so we need to iterate in both directions to make sure we don't miss anything
        find_max(start_idx, 1, tables.method_def.len() - 1);
        if start_idx != 0 {
            find_max(start_idx - 1, -1, 0);
        }

        // once we have the maximum internal index, this corresponds to the last method in the type
        // since we're about to swap_remove, change this method's internal index to where it's going to be put
        if let Some((max_index, _)) = max_internal {
            methods[max_index].member = MethodMemberIndex::Method(internal_idx);
        }
    }

    parent.methods.swap_remove(internal_idx)
}

fn make_generic<'a, T: TypeKind>(
    name: Cow<'a, str>,
    p: &metadata::table::GenericParam,
    param_idx: usize,
    constraint_map: &mut HashMap<usize, (usize, usize)>,
    tables: &metadata::table::Tables,
    ctx: &convert::read::Context<'_, 'a>,
) -> Result<Generic<'a, T>> {
    Ok(Generic {
        attributes: vec![],
        variance: match p.flags & 0x3 {
            0x0 => Variance::Invariant,
            0x1 => Variance::Covariant,
            0x2 => Variance::Contravariant,
            _ => {
                throw!("invalid variance value 0x3 for generic parameter {}", name)
            }
        },
        name,
        special_constraint: SpecialConstraint {
            reference_type: check_bitmask!(p.flags, 0x04),
            value_type: check_bitmask!(p.flags, 0x08),
            has_default_constructor: check_bitmask!(p.flags, 0x10),
        },
        type_constraints: {
            let constraints = &tables.generic_param_constraint;
            let owner = param_idx + 1;
            let start = constraints.partition_point(|c| c.owner.0 < owner);

            let mut type_constraints = Vec::new();
            let mut c_idx = start;

            while let Some(c) = constraints.get(c_idx) {
                if c.owner.0 != owner {
                    break;
                }

                let (cmod, ty) = convert::read::idx_with_mod(c.constraint, ctx)?;
                let internal = type_constraints.len();
                constraint_map.insert(c_idx, (param_idx, internal));
                type_constraints.push(Constraint {
                    attributes: vec![],
                    custom_modifiers: cmod,
                    constraint_type: ty,
                });

                c_idx += 1;
            }

            type_constraints
        },
    })
}

fn member_accessibility(flags: u16) -> Result<members::Accessibility> {
    use Accessibility::*;
    use members::Accessibility::*;

    Ok(match flags & 0x7 {
        0x0 => CompilerControlled,
        0x1 => Access(Private),
        0x2 => Access(FamilyANDAssembly),
        0x3 => Access(Assembly),
        0x4 => Access(Family),
        0x5 => Access(FamilyORAssembly),
        0x6 => Access(Public),
        _ => throw!("flags value 0x7 has no meaning for member accessibility"),
    })
}

fn decode_assembly<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    blobs: &BlobReader<'a>,
) -> Result<Option<assembly::Assembly<'a>>> {
    let mut assembly = None;
    if let Some(a) = tables.assembly.first() {
        use assembly::*;

        assembly = Some(Assembly {
            attributes: vec![],
            hash_algorithm: match a.hash_alg_id {
                0x0000 => HashAlgorithm::None,
                0x8003 => HashAlgorithm::ReservedMD5,
                0x8004 => HashAlgorithm::SHA1,
                other => throw!("unrecognized assembly hash algorithm {:#06x}", other),
            },
            version: build_version!(a),
            flags: Flags::new(a.flags),
            public_key: optional_idx!(blobs, a.public_key),
            name: heap_idx!(strings, a.name),
            culture: optional_idx!(strings, a.culture),
            security: None,
        });
    }

    Ok(assembly)
}

fn decode_assembly_refs<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    blobs: &BlobReader<'a>,
) -> Result<Vec<assembly::ExternalAssemblyReference<'a>>> {
    use rayon::prelude::*;

    tables
        .assembly_ref
        .par_iter()
        .map(|a| {
            use assembly::*;
            Ok(ExternalAssemblyReference {
                attributes: vec![],
                version: build_version!(a),
                has_full_public_key: check_bitmask!(a.flags, 0x0001),
                public_key_or_token: optional_idx!(blobs, a.public_key_or_token),
                name: heap_idx!(strings, a.name),
                culture: optional_idx!(strings, a.culture),
                hash_value: optional_idx!(blobs, a.hash_value),
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn decode_type_definitions<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    ctx: &convert::read::Context<'_, 'a>,
) -> Result<Vec<types::TypeDefinition<'a>>> {
    let mut types = Vec::with_capacity(tables.type_def.len());
    for (idx, t) in tables.type_def.iter().enumerate() {
        use types::*;

        let layout_flags = t.flags & 0x18;
        let name = heap_idx!(strings, t.type_name);

        types.push(TypeDefinition {
            attributes: vec![],
            flags: TypeFlags::from_mask(
                t.flags,
                if layout_flags == 0x00 {
                    Layout::Automatic
                } else {
                    let layout = {
                        let pos = tables.class_layout.partition_point(|c| c.parent.0 - 1 < idx);
                        tables.class_layout.get(pos).filter(|c| c.parent.0 - 1 == idx)
                    };

                    match layout_flags {
                        0x08 => Layout::Sequential(layout.map(|l| SequentialLayout {
                            packing_size: l.packing_size as usize,
                            class_size: l.class_size as usize,
                        })),
                        0x10 => Layout::Explicit(layout.map(|l| ExplicitLayout {
                            class_size: l.class_size as usize,
                        })),
                        _ => unreachable!(),
                    }
                },
            ),
            name,
            namespace: optional_idx!(strings, t.type_namespace),
            fields: vec![],
            properties: vec![],
            methods: vec![],
            events: vec![],
            encloser: None,
            overrides: vec![],
            extends: if t.extends.is_null() {
                None
            } else {
                Some(convert::read::type_source(t.extends, ctx)?)
            },
            implements: vec![],
            generic_parameters: vec![],
            security: None,
        });
    }

    Ok(types)
}

fn decode_files<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    blobs: &BlobReader<'a>,
) -> Result<Vec<module::File<'a>>> {
    use rayon::prelude::*;

    tables
        .file
        .par_iter()
        .map(|f| {
            Ok(module::File {
                attributes: vec![],
                has_metadata: !check_bitmask!(f.flags, 0x0001),
                name: heap_idx!(strings, f.name),
                hash_value: heap_idx!(blobs, f.hash_value),
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn decode_resources<'a>(
    dll: &DLL<'a>,
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    files: &[module::File<'a>],
    assembly_refs: &[assembly::ExternalAssemblyReference<'a>],
) -> Result<Vec<resource::ManifestResource<'a>>> {
    use rayon::prelude::*;

    tables
        .manifest_resource
        .par_iter()
        .map(|r| {
            use metadata::index::Implementation as BinImpl;
            use resource::*;

            let name = heap_idx!(strings, r.name);
            let mut offset = r.offset as usize;

            Ok(ManifestResource {
                attributes: vec![],
                visibility: match r.flags & 0x7 {
                    0x1 => Visibility::Public,
                    0x2 => Visibility::Private,
                    bad => throw!("invalid visibility {:#03x} for manifest resource {}", bad, name),
                },
                implementation: match r.implementation {
                    BinImpl::File(f) => {
                        let idx = f - 1;
                        if idx < files.len() {
                            Implementation::File {
                                location: FileIndex(idx),
                                offset,
                            }
                        } else {
                            throw!("invalid file index {} for manifest resource {}", idx, name)
                        }
                    }
                    BinImpl::AssemblyRef(a) => {
                        let idx = a - 1;

                        if idx < assembly_refs.len() {
                            Implementation::Assembly {
                                location: AssemblyRefIndex(idx),
                                offset,
                            }
                        } else {
                            throw!(
                                "invalid assembly reference index {} for manifest resource {}",
                                idx,
                                name
                            )
                        }
                    }
                    BinImpl::ExportedType(_) => throw!(
                        "exported type indices are invalid in manifest resource implementations (found in resource {})",
                        name
                    ),
                    BinImpl::Null => {
                        let rva_data = dll.at_rva(&dll.cli.resources)?;
                        let len: u32 = rva_data.gread_with(&mut offset, scroll::LE)?;
                        Implementation::CurrentFile(rva_data[offset..offset + (len as usize)].into())
                    }
                },
                name,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn decode_exported_types<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    files: &[module::File<'a>],
    assembly_refs: &[assembly::ExternalAssemblyReference<'a>],
) -> Result<Vec<types::ExportedType<'a>>> {
    use rayon::prelude::*;

    tables
        .exported_type
        .par_iter()
        .map(|e| {
            use metadata::index::Implementation;
            use types::*;

            let name = heap_idx!(strings, e.type_name);
            Ok(ExportedType {
                attributes: vec![],
                flags: TypeFlags::from_mask(e.flags, Layout::Automatic),
                namespace: optional_idx!(strings, e.type_namespace),
                implementation: match e.implementation {
                    Implementation::File(f) => {
                        let idx = f - 1;
                        let t_idx = e.type_def_id as usize;

                        if idx < files.len() {
                            TypeImplementation::ModuleFile {
                                type_def: if t_idx < tables.type_def.len() {
                                    TypeIndex(t_idx)
                                } else {
                                    throw!("invalid type definition index {} in exported type {}", t_idx, name)
                                },
                                file: FileIndex(idx),
                            }
                        } else {
                            throw!("invalid file index {} in exported type {}", idx, name)
                        }
                    }
                    Implementation::AssemblyRef(a) => {
                        let idx = a - 1;

                        if idx < assembly_refs.len() {
                            TypeImplementation::TypeForwarder(AssemblyRefIndex(idx))
                        } else {
                            throw!("invalid assembly reference index {} in exported type {}", idx, name)
                        }
                    }
                    Implementation::ExportedType(t) => {
                        let idx = t - 1;
                        if idx < tables.exported_type.len() {
                            TypeImplementation::Nested(ExportedTypeIndex(idx))
                        } else {
                            throw!("invalid nested type index {} in exported type {}", idx, name);
                        }
                    }
                    Implementation::Null => throw!("invalid null implementation index for exported type {}", name),
                },
                name,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn decode_module<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    guids: &GUIDReader<'a>,
) -> Result<module::Module<'a>> {
    let module_row = tables
        .module
        .first()
        .ok_or_else(|| scroll::Error::Custom("missing required module metadata table".to_string()))?;
    Ok(module::Module {
        attributes: vec![],
        name: heap_idx!(strings, module_row.name),
        mvid: guids.at_index(module_row.mvid)?,
    })
}

fn decode_module_refs<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
) -> Result<Vec<module::ExternalModuleReference<'a>>> {
    use rayon::prelude::*;

    tables
        .module_ref
        .par_iter()
        .map(|r| {
            Ok(module::ExternalModuleReference {
                attributes: vec![],
                name: heap_idx!(strings, r.name),
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn decode_type_refs<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    module_refs: &[module::ExternalModuleReference<'a>],
    assembly_refs: &[assembly::ExternalAssemblyReference<'a>],
) -> Result<Vec<types::ExternalTypeReference<'a>>> {
    use rayon::prelude::*;

    tables
        .type_ref
        .par_iter()
        .map(|r| {
            use metadata::index::ResolutionScope as BinRS;
            use types::*;

            let name = heap_idx!(strings, r.type_name);
            let namespace = optional_idx!(strings, r.type_namespace);

            Ok(ExternalTypeReference {
                attributes: vec![],
                namespace,
                scope: match r.resolution_scope {
                    BinRS::Module(_) => ResolutionScope::CurrentModule,
                    BinRS::ModuleRef(m) => {
                        let idx = m - 1;
                        if idx < module_refs.len() {
                            ResolutionScope::ExternalModule(ModuleRefIndex(idx))
                        } else {
                            throw!("invalid module reference index {} for type reference {}", idx, name)
                        }
                    }
                    BinRS::AssemblyRef(a) => {
                        let idx = a - 1;

                        if idx < assembly_refs.len() {
                            ResolutionScope::Assembly(AssemblyRefIndex(idx))
                        } else {
                            throw!("invalid assembly reference index {} for type reference {}", idx, name)
                        }
                    }
                    BinRS::TypeRef(t) => {
                        let idx = t - 1;
                        if idx < tables.type_ref.len() {
                            ResolutionScope::Nested(TypeRefIndex(idx))
                        } else {
                            throw!("invalid nested type index {} for type reference {}", idx, name);
                        }
                    }
                    BinRS::Null => ResolutionScope::Exported,
                },
                name,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn decode_interfaces<'a>(
    tables: &metadata::table::Tables,
    types: &mut [types::TypeDefinition<'a>],
    ctx: &convert::read::Context<'_, 'a>,
) -> Result<Vec<(usize, usize)>> {
    let mut interface_idxs = Vec::with_capacity(tables.interface_impl.len());
    for i in &tables.interface_impl {
        let idx = i.class.0 - 1;
        match types.get_mut(idx) {
            Some(t) => {
                t.implements
                    .push((vec![], convert::read::type_source(i.interface, ctx)?));
                interface_idxs.push((idx, t.implements.len() - 1));
            }
            None => throw!("invalid type index {} for interface implementation", idx),
        }
    }
    Ok(interface_idxs)
}

fn decode_fields<'a>(
    types: &mut [types::TypeDefinition<'a>],
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    blobs: &BlobReader<'a>,
    ctx: &convert::read::Context<'_, 'a>,
) -> Result<Vec<FieldIndex>> {
    use rayon::prelude::*;

    let owned_fields = tables
        .type_def
        .iter()
        .enumerate()
        .map(|(type_idx, t)| {
            let start = t.field_list.0 - 1;
            let end = match tables.type_def.get(type_idx + 1) {
                Some(next) => next.field_list.0,
                None => tables.field.len() + 1,
            } - 1;

            (type_idx, start, end)
        })
        .collect::<Vec<_>>();

    let decoded_fields = owned_fields
        .par_iter()
        .map(|&(type_idx, start, end)| {
            use crate::binary::signature::kinds::FieldSig;
            use members::*;

            let Some(type_fields) = tables.field.get(start..end) else {
                throw!("invalid field range in type_def {}", type_idx)
            };

            let mut fields = Vec::with_capacity(type_fields.len());
            let mut field_idxs = Vec::with_capacity(type_fields.len());

            for (offset, f) in type_fields.iter().enumerate() {
                let f_idx = start + offset;

                let FieldSig {
                    custom_modifiers: cmod,
                    field_type: t,
                    by_ref,
                } = heap_idx!(blobs, f.signature).pread(0)?;

                fields.push(Field {
                    attributes: vec![],
                    name: heap_idx!(strings, f.name),
                    type_modifiers: cmod
                        .into_iter()
                        .map(|c| convert::read::custom_modifier(c, ctx))
                        .collect::<Result<_>>()?,
                    by_ref,
                    return_type: MemberType::from_sig(t, ctx)?,
                    accessibility: member_accessibility(f.flags)?,
                    static_member: check_bitmask!(f.flags, 0x10),
                    init_only: check_bitmask!(f.flags, 0x20),
                    literal: check_bitmask!(f.flags, 0x40),
                    default: None,
                    not_serialized: check_bitmask!(f.flags, 0x80),
                    special_name: check_bitmask!(f.flags, 0x200),
                    pinvoke: None,
                    runtime_special_name: check_bitmask!(f.flags, 0x400),
                    offset: None,
                    marshal: None,
                    initial_value: None,
                });

                field_idxs.push((
                    f_idx,
                    FieldIndex {
                        parent_type: TypeIndex(type_idx),
                        field: fields.len() - 1,
                    },
                ));
            }

            Ok((type_idx, fields, field_idxs))
        })
        .collect::<Result<Vec<_>>>()?;

    build_vec!(fields = FieldIndex[tables.field.len()], {
        for (type_idx, decoded_type_fields, decoded_type_field_idxs) in decoded_fields {
            let parent_fields = &mut types[type_idx].fields;
            let field_offset = parent_fields.len();
            parent_fields.reserve(decoded_type_fields.len());
            parent_fields.extend(decoded_type_fields);

            for (f_idx, mut field_idx) in decoded_type_field_idxs {
                field_idx.field += field_offset;
                fields[f_idx].write(field_idx);
            }
        }
    });

    Ok(fields)
}

struct DecodedMethods {
    methods: Vec<MethodIndex>,
    owned_params: Vec<(usize, usize, usize)>,
    sig_pending_def: Vec<(crate::binary::metadata::index::Blob, bool)>,
}

fn decode_methods<'a>(
    types: &mut [types::TypeDefinition<'a>],
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    blobs: &BlobReader<'a>,
    ctx: &convert::read::Context<'_, 'a>,
    opts: Options,
) -> Result<DecodedMethods> {
    use rayon::prelude::*;

    let owned_methods = tables
        .type_def
        .iter()
        .enumerate()
        .map(|(type_idx, t)| {
            let start = t.method_list.0 - 1;
            let end = match tables.type_def.get(type_idx + 1) {
                Some(next) => next.method_list.0,
                None => tables.method_def.len() + 1,
            } - 1;

            (type_idx, start, end)
        })
        .collect::<Vec<_>>();

    let decoded_methods = owned_methods
        .par_iter()
        .map(|&(type_idx, start, end)| {
            use members::*;

            let Some(type_methods) = tables.method_def.get(start..end) else {
                throw!("invalid method_def range in type_def {}", type_idx)
            };

            let mut methods = Vec::with_capacity(type_methods.len());
            let mut method_idxs = Vec::with_capacity(type_methods.len());
            let mut param_ranges = Vec::with_capacity(type_methods.len());

            for (offset, m) in type_methods.iter().enumerate() {
                let m_idx = start + offset;

                let name = heap_idx!(strings, m.name);

                let sig = if opts.lazy_method_signatures {
                    Default::default()
                } else {
                    let mut sig = convert::read::managed_method(heap_idx!(blobs, m.signature).pread(0)?, ctx)?;
                    if check_bitmask!(m.flags, 0x10) {
                        sig.instance = false;
                    }
                    sig
                };

                methods.push(Method {
                    attributes: vec![],
                    body: None,
                    signature: sig,
                    accessibility: member_accessibility(m.flags)?,
                    generic_parameters: vec![],
                    return_type_metadata: None,
                    parameter_metadata: vec![],
                    sealed: check_bitmask!(m.flags, 0x20),
                    virtual_member: check_bitmask!(m.flags, 0x40),
                    hide_by_sig: check_bitmask!(m.flags, 0x80),
                    vtable_layout: match m.flags & 0x100 {
                        0x000 => VtableLayout::ReuseSlot,
                        0x100 => VtableLayout::NewSlot,
                        _ => unreachable!(),
                    },
                    strict: check_bitmask!(m.flags, 0x200),
                    abstract_member: check_bitmask!(m.flags, 0x400),
                    special_name: check_bitmask!(m.flags, 0x800),
                    pinvoke: None,
                    runtime_special_name: check_bitmask!(m.flags, 0x1000),
                    security: None,
                    require_sec_object: check_bitmask!(m.flags, 0x8000),
                    body_format: match m.impl_flags & 0x3 {
                        0x0 => BodyFormat::IL,
                        0x1 => BodyFormat::Native,
                        0x2 => throw!("invalid code type value OPTIL (0x2) for method {}", name),
                        0x3 => BodyFormat::Runtime,
                        _ => unreachable!(),
                    },
                    name,
                    body_management: match m.impl_flags & 0x4 {
                        0x0 => BodyManagement::Unmanaged,
                        0x4 => BodyManagement::Managed,
                        _ => unreachable!(),
                    },
                    forward_ref: check_bitmask!(m.impl_flags, 0x10),
                    preserve_sig: check_bitmask!(m.impl_flags, 0x80),
                    internal_call: check_bitmask!(m.impl_flags, 0x1000),
                    synchronized: check_bitmask!(m.impl_flags, 0x20),
                    no_inlining: check_bitmask!(m.impl_flags, 0x8),
                    no_optimization: check_bitmask!(m.impl_flags, 0x40),
                });

                method_idxs.push((
                    m_idx,
                    MethodIndex {
                        parent_type: TypeIndex(type_idx),
                        member: MethodMemberIndex::Method(methods.len() - 1),
                    },
                ));

                let param_start = m.param_list.0 - 1;
                let param_end = match tables.method_def.get(m_idx + 1) {
                    Some(next) => next.param_list.0,
                    None => tables.param.len() + 1,
                } - 1;

                if tables.param.get(param_start..param_end).is_none() {
                    throw!("invalid param range in method_def {}", m_idx)
                }

                if param_start != param_end {
                    param_ranges.push((m_idx, param_start, param_end));
                }
            }

            Ok((type_idx, methods, method_idxs, param_ranges))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut owned_params = Vec::with_capacity(tables.param.len());
    let sig_pending_def: Vec<(crate::binary::metadata::index::Blob, bool)> = if opts.lazy_method_signatures {
        tables
            .method_def
            .iter()
            .map(|m| (m.signature, check_bitmask!(m.flags, 0x10)))
            .collect()
    } else {
        vec![]
    };

    build_vec!(methods = MethodIndex[tables.method_def.len()], {
        for (type_idx, decoded_type_methods, decoded_type_method_idxs, decoded_type_param_ranges) in decoded_methods {
            let parent_methods = &mut types[type_idx].methods;
            let method_offset = parent_methods.len();
            parent_methods.reserve(decoded_type_methods.len());
            parent_methods.extend(decoded_type_methods);

            for (m_idx, mut method_idx) in decoded_type_method_idxs {
                let MethodMemberIndex::Method(member_idx) = &mut method_idx.member else {
                    unreachable!()
                };
                *member_idx += method_offset;
                methods[m_idx].write(method_idx);
            }

            owned_params.extend(decoded_type_param_ranges);
        }
    });

    Ok(DecodedMethods {
        methods,
        owned_params,
        sig_pending_def,
    })
}

fn get_field_mut<'a, 'r>(types: &'r mut [types::TypeDefinition<'a>], idx: FieldIndex) -> &'r mut members::Field<'a> {
    &mut types[idx.parent_type.0].fields[idx.field]
}

fn get_method_mut<'a, 'r>(types: &'r mut [types::TypeDefinition<'a>], idx: MethodIndex) -> &'r mut members::Method<'a> {
    let MethodMemberIndex::Method(member_idx) = idx.member else {
        unreachable!()
    };
    &mut types[idx.parent_type.0].methods[member_idx]
}

fn decode_params<'a>(
    types: &mut [types::TypeDefinition<'a>],
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    methods: &[MethodIndex],
    owned_params: Vec<(usize, usize, usize)>,
) -> Result<Vec<(usize, usize)>> {
    use rayon::prelude::*;

    struct DecodedParam<'a> {
        p_idx: usize,
        sequence: usize,
        metadata: Option<members::ParameterMetadata<'a>>,
    }

    let decoded_params = owned_params
        .par_iter()
        .map(|&(m_idx, start, end)| {
            use members::*;

            let mut decoded = Vec::with_capacity(end - start);

            for p_idx in start..end {
                let param = &tables.param[p_idx];
                let sequence = param.sequence as usize;

                decoded.push(DecodedParam {
                    p_idx,
                    sequence,
                    metadata: Some(ParameterMetadata {
                        attributes: vec![],
                        name: optional_idx!(strings, param.name),
                        is_in: check_bitmask!(param.flags, 0x1),
                        is_out: check_bitmask!(param.flags, 0x2),
                        optional: check_bitmask!(param.flags, 0x10),
                        default: None,
                        marshal: None,
                    }),
                });
            }

            Ok((m_idx, decoded))
        })
        .collect::<Result<Vec<_>>>()?;

    build_vec!(params = (usize, usize)[tables.param.len()], {
        for (m_idx, decoded_method_params) in decoded_params {
            let method = get_method_mut(types, methods[m_idx]);

            let max_sequence = decoded_method_params
                .iter()
                .map(|param| param.sequence)
                .max()
                .unwrap_or(0);
            if max_sequence > 0 && method.parameter_metadata.len() < max_sequence {
                method.parameter_metadata.resize(max_sequence, None);
            }

            for param in decoded_method_params {
                if param.sequence == 0 {
                    method.return_type_metadata = param.metadata;
                } else {
                    method.parameter_metadata[param.sequence - 1] = param.metadata;
                }

                params[param.p_idx].write((m_idx, param.sequence));
            }
        }
    });

    Ok(params)
}

fn decode_properties<'a>(
    types: &mut [types::TypeDefinition<'a>],
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    blobs: &BlobReader<'a>,
    ctx: &convert::read::Context<'_, 'a>,
) -> Result<Vec<(usize, usize)>> {
    use rayon::prelude::*;

    let owned_properties = tables
        .property_map
        .iter()
        .enumerate()
        .map(|(map_idx, map)| {
            let type_idx = map.parent.0 - 1;
            if type_idx >= types.len() {
                throw!("invalid parent type index {} for property map {}", type_idx, map_idx)
            }

            let start = map.property_list.0 - 1;
            let end = match tables.property_map.get(map_idx + 1) {
                Some(next) => next.property_list.0,
                None => tables.property.len() + 1,
            } - 1;

            Ok((type_idx, start, end, map_idx))
        })
        .collect::<Result<Vec<_>>>()?;

    let decoded_properties = owned_properties
        .par_iter()
        .map(|&(type_idx, start, end, map_idx)| {
            use crate::binary::signature::kinds::PropertySig;
            use members::*;

            let Some(props) = tables.property.get(start..end) else {
                throw!("invalid property range in property_map {}", map_idx)
            };

            let mut properties = Vec::with_capacity(props.len());
            let mut property_idxs = Vec::with_capacity(props.len());

            for (offset, prop) in props.iter().enumerate() {
                let p_idx = start + offset;
                let sig = heap_idx!(blobs, prop.property_type).pread::<PropertySig>(0)?;

                properties.push(Property {
                    attributes: vec![],
                    name: heap_idx!(strings, prop.name),
                    getter: None,
                    setter: None,
                    other: vec![],
                    static_member: !sig.has_this,
                    property_type: convert::read::parameter(sig.property_type, ctx)?,
                    parameters: {
                        let mut ps = Vec::with_capacity(sig.params.len());
                        for p in sig.params {
                            ps.push(convert::read::parameter(p, ctx)?);
                        }
                        ps
                    },
                    special_name: check_bitmask!(prop.flags, 0x200),
                    runtime_special_name: check_bitmask!(prop.flags, 0x1000),
                    default: None,
                });

                property_idxs.push((p_idx, (type_idx, properties.len() - 1)));
            }

            Ok((type_idx, properties, property_idxs))
        })
        .collect::<Result<Vec<_>>>()?;

    build_vec!(properties = (usize, usize)[tables.property.len()], {
        for (type_idx, decoded_type_properties, decoded_type_property_idxs) in decoded_properties {
            let parent_properties = &mut types[type_idx].properties;
            let property_offset = parent_properties.len();
            parent_properties.reserve(decoded_type_properties.len());
            parent_properties.extend(decoded_type_properties);

            for (p_idx, (prop_type_idx, mut prop_idx)) in decoded_type_property_idxs {
                debug_assert_eq!(type_idx, prop_type_idx);
                prop_idx += property_offset;
                properties[p_idx].write((prop_type_idx, prop_idx));
            }
        }
    });

    Ok(properties)
}

fn decode_events<'a>(
    types: &mut [types::TypeDefinition<'a>],
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    ctx: &convert::read::Context<'_, 'a>,
    sem_by_event: &mut HashMap<usize, Vec<(u16, usize)>>,
    methods: &mut [MethodIndex],
) -> Result<Vec<(usize, usize)>> {
    build_vec!(events = (usize, usize)[tables.event.len()], {
        for (map_idx, map) in tables.event_map.iter().enumerate() {
            let type_idx = map.parent.0 - 1;

            let parent = types.get_mut(type_idx).ok_or_else(|| {
                scroll::Error::Custom(format!(
                    "invalid parent type index {} for event map {}",
                    type_idx, map_idx
                ))
            })?;

            let start = map.event_list.0 - 1;
            let end = match tables.event_map.get(map_idx + 1) {
                Some(next) => next.event_list.0,
                None => tables.event.len() + 1,
            } - 1;

            let Some(type_events) = tables.event.get(start..end) else {
                throw!("invalid event range in event_map {}", map_idx)
            };

            for (offset, event) in type_events.iter().enumerate() {
                use members::*;

                let e_idx = start + offset;
                let name = heap_idx!(strings, event.name);

                let internal_idx = parent.events.len();

                macro_rules! get_listener {
                    ($l_name:literal, $flag:literal, $variant:ident) => {{
                        let Some(entries) = sem_by_event.get_mut(&e_idx) else {
                            throw!("could not find {} listener for event {}", $l_name, name)
                        };
                        let Some(position) = entries
                            .iter()
                            .position(|(semantics, _)| check_bitmask!(*semantics, $flag))
                        else {
                            throw!("could not find {} listener for event {}", $l_name, name)
                        };
                        let (_, m_idx) = entries.swap_remove(position);
                        if m_idx < tables.method_def.len() {
                            let method = extract_method(parent, methods[m_idx], methods, tables);
                            methods[m_idx].member = MethodMemberIndex::$variant(internal_idx);
                            method
                        } else {
                            throw!(
                                "invalid method index {} in {} index for event {}",
                                m_idx,
                                $l_name,
                                name
                            );
                        }
                    }};
                }

                let add_listener = get_listener!("add", 0x8, EventAdd);
                let remove_listener = get_listener!("remove", 0x10, EventRemove);

                parent.events.push(Event {
                    attributes: vec![],
                    delegate_type: convert::read::type_idx(event.event_type, ctx)?,
                    add_listener,
                    remove_listener,
                    name,
                    raise_event: None,
                    other: vec![],
                    special_name: check_bitmask!(event.event_flags, 0x200),
                    runtime_special_name: check_bitmask!(event.event_flags, 0x400),
                });
                events[e_idx].write((type_idx, internal_idx));
            }
        }
    });

    Ok(events)
}

#[derive(Copy, Clone)]
enum SemanticsAssociation {
    Event(usize),
    Property(usize),
}

#[derive(Copy, Clone)]
struct SemanticsAction {
    raw_method_idx: usize,
    semantics: u16,
    association: SemanticsAssociation,
}

struct TypeSemanticsWork {
    parent_type: usize,
    method_start: usize,
    method_end: usize,
    actions: Vec<SemanticsAction>,
}

fn apply_method_semantics_for_type<'a>(
    parent_type: usize,
    parent: &mut types::TypeDefinition<'a>,
    methods_for_type: &mut [MethodIndex],
    method_start: usize,
    actions: &[SemanticsAction],
    properties: &[(usize, usize)],
    events: &[(usize, usize)],
) -> Result<()> {
    let mut raw_by_internal = vec![usize::MAX; parent.methods.len()];
    for (local_raw_idx, method_idx) in methods_for_type.iter().enumerate() {
        if let MethodMemberIndex::Method(internal_idx) = method_idx.member {
            let Some(slot) = raw_by_internal.get_mut(internal_idx) else {
                throw!(
                    "invalid method internal index {} for type {} in method semantics",
                    internal_idx,
                    parent_type
                )
            };
            *slot = local_raw_idx;
        }
    }

    if raw_by_internal.contains(&usize::MAX) {
        throw!(
            "incomplete method index map for type {} in method semantics",
            parent_type
        )
    }

    let mut extraction_order = Vec::with_capacity(actions.len());
    for (action_idx, action) in actions.iter().enumerate() {
        let Some(local_raw_idx) = action
            .raw_method_idx
            .checked_sub(method_start)
            .filter(|idx| *idx < methods_for_type.len())
        else {
            throw!("invalid method index {} for method semantics", action.raw_method_idx)
        };

        let MethodMemberIndex::Method(internal_idx) = methods_for_type[local_raw_idx].member else {
            throw!("invalid method index {} for method semantics", action.raw_method_idx)
        };

        extraction_order.push((internal_idx, action_idx, local_raw_idx));
    }
    extraction_order.sort_unstable_by_key(|(internal_idx, _, _)| std::cmp::Reverse(*internal_idx));

    let mut extracted = Vec::with_capacity(actions.len());

    for (internal_idx, action_idx, expected_local_raw_idx) in extraction_order {
        let Some(&removed_local_raw_idx) = raw_by_internal.get(internal_idx) else {
            throw!(
                "invalid method internal index {} for type {} in method semantics",
                internal_idx,
                parent_type
            )
        };

        if removed_local_raw_idx != expected_local_raw_idx {
            throw!(
                "method semantics extraction mismatch for method {}",
                actions[action_idx].raw_method_idx
            )
        }

        let moved_local_raw_idx = raw_by_internal[raw_by_internal.len() - 1];

        raw_by_internal.swap_remove(internal_idx);
        let method = parent.methods.swap_remove(internal_idx);

        if internal_idx < raw_by_internal.len() {
            methods_for_type[moved_local_raw_idx].member = MethodMemberIndex::Method(internal_idx);
        }

        extracted.push((action_idx, method));
    }

    extracted.sort_unstable_by_key(|(action_idx, _)| *action_idx);

    for ((expected_action_idx, action), (action_idx, new_meth)) in actions.iter().enumerate().zip(extracted) {
        debug_assert_eq!(expected_action_idx, action_idx);

        let Some(local_raw_idx) = action
            .raw_method_idx
            .checked_sub(method_start)
            .filter(|idx| *idx < methods_for_type.len())
        else {
            throw!("invalid method index {} for method semantics", action.raw_method_idx)
        };

        let member_idx = &mut methods_for_type[local_raw_idx].member;

        match action.association {
            SemanticsAssociation::Event(idx) => {
                let &(_, internal_idx) = events.get(idx).ok_or_else(|| {
                    scroll::Error::Custom(format!("invalid event index {} for method semantics", idx))
                })?;
                let event = &mut parent.events[internal_idx];

                if check_bitmask!(action.semantics, 0x20) {
                    event.raise_event = Some(new_meth);
                    *member_idx = MethodMemberIndex::EventRaise(internal_idx);
                } else if check_bitmask!(action.semantics, 0x4) {
                    event.other.push(new_meth);
                    *member_idx = MethodMemberIndex::EventOther {
                        event: internal_idx,
                        other: event.other.len() - 1,
                    };
                }
            }
            SemanticsAssociation::Property(idx) => {
                let &(_, internal_idx) = properties.get(idx).ok_or_else(|| {
                    scroll::Error::Custom(format!("invalid property index {} for method semantics", idx))
                })?;
                let property = &mut parent.properties[internal_idx];

                if check_bitmask!(action.semantics, 0x1) {
                    property.setter = Some(new_meth);
                    *member_idx = MethodMemberIndex::PropertySetter(internal_idx);
                } else if check_bitmask!(action.semantics, 0x2) {
                    property.getter = Some(new_meth);
                    *member_idx = MethodMemberIndex::PropertyGetter(internal_idx);
                } else if check_bitmask!(action.semantics, 0x4) {
                    property.other.push(new_meth);
                    *member_idx = MethodMemberIndex::PropertyOther {
                        property: internal_idx,
                        other: property.other.len() - 1,
                    };
                }
            }
        }
    }

    Ok(())
}

fn apply_method_semantics_work<'a>(
    types: &mut [types::TypeDefinition<'a>],
    methods: &mut [MethodIndex],
    works: &[TypeSemanticsWork],
    type_base: usize,
    method_base: usize,
    properties: &[(usize, usize)],
    events: &[(usize, usize)],
) -> Result<()> {
    if works.is_empty() {
        return Ok(());
    }

    const SEQUENTIAL_WORK_THRESHOLD: usize = 8;

    if works.len() <= SEQUENTIAL_WORK_THRESHOLD {
        for work in works {
            let Some(type_local_idx) = work.parent_type.checked_sub(type_base).filter(|idx| *idx < types.len()) else {
                throw!("invalid parent type index {} for method semantics", work.parent_type)
            };

            let Some(method_start) = work
                .method_start
                .checked_sub(method_base)
                .filter(|idx| *idx <= methods.len())
            else {
                throw!("invalid method start index {} for method semantics", work.method_start)
            };

            let Some(method_end) = work
                .method_end
                .checked_sub(method_base)
                .filter(|idx| *idx <= methods.len())
            else {
                throw!("invalid method end index {} for method semantics", work.method_end)
            };

            let parent = &mut types[type_local_idx];
            let methods_for_type = methods.get_mut(method_start..method_end).ok_or_else(|| {
                scroll::Error::Custom(format!(
                    "invalid method range {}..{} for method semantics",
                    work.method_start, work.method_end
                ))
            })?;

            apply_method_semantics_for_type(
                work.parent_type,
                parent,
                methods_for_type,
                work.method_start,
                &work.actions,
                properties,
                events,
            )?;
        }

        return Ok(());
    }

    let mid = works.len() / 2;
    let split_type = works[mid].parent_type.checked_sub(type_base).ok_or_else(|| {
        scroll::Error::Custom(format!(
            "invalid type split for method semantics at {}",
            works[mid].parent_type
        ))
    })?;
    let split_method = works[mid].method_start.checked_sub(method_base).ok_or_else(|| {
        scroll::Error::Custom(format!(
            "invalid method split for method semantics at {}",
            works[mid].method_start
        ))
    })?;

    let (left_types, right_types) = types.split_at_mut(split_type);
    let (left_methods, right_methods) = methods.split_at_mut(split_method);
    let (left_works, right_works) = works.split_at(mid);

    let (left_result, right_result) = rayon::join(
        || {
            apply_method_semantics_work(
                left_types,
                left_methods,
                left_works,
                type_base,
                method_base,
                properties,
                events,
            )
        },
        || {
            apply_method_semantics_work(
                right_types,
                right_methods,
                right_works,
                type_base + split_type,
                method_base + split_method,
                properties,
                events,
            )
        },
    );

    left_result?;
    right_result
}

fn apply_method_semantics<'a>(
    types: &mut [types::TypeDefinition<'a>],
    tables: &metadata::table::Tables,
    methods: &mut [MethodIndex],
    properties: &[(usize, usize)],
    events: &[(usize, usize)],
    sem_by_event: &HashMap<usize, Vec<(u16, usize)>>,
    sem_by_property: &HashMap<usize, Vec<(u16, usize)>>,
) -> Result<()> {
    // Batch semantics extraction by parent type so each type's method-index map is built once.
    // Within a type, extract in descending internal-index order so swap_remove does not
    // invalidate any method positions that are still waiting to be removed.
    let mut remaining_event_counts: HashMap<(usize, u16, usize), usize> =
        HashMap::with_capacity_and_hasher(tables.method_semantics.len(), Default::default());
    let mut remaining_property_counts: HashMap<(usize, u16, usize), usize> =
        HashMap::with_capacity_and_hasher(tables.method_semantics.len(), Default::default());

    for (&event_idx, entries) in sem_by_event {
        for &(semantics, raw_method_idx) in entries {
            *remaining_event_counts
                .entry((event_idx, semantics, raw_method_idx))
                .or_insert(0) += 1;
        }
    }

    for (&property_idx, entries) in sem_by_property {
        for &(semantics, raw_method_idx) in entries {
            *remaining_property_counts
                .entry((property_idx, semantics, raw_method_idx))
                .or_insert(0) += 1;
        }
    }

    let mut semantics_by_type: HashMap<usize, Vec<SemanticsAction>> =
        HashMap::with_capacity_and_hasher(types.len(), Default::default());

    for s in &tables.method_semantics {
        use metadata::index::HasSemantics;

        let raw_method_idx = s.method.0 - 1;

        let (association, include) = match s.association {
            HasSemantics::Event(i) => {
                let idx = i - 1;
                let key = (idx, s.semantics, raw_method_idx);
                let include = match remaining_event_counts.get_mut(&key) {
                    Some(count) if *count > 0 => {
                        *count -= 1;
                        true
                    }
                    _ => false,
                };
                (SemanticsAssociation::Event(idx), include)
            }
            HasSemantics::Property(i) => {
                let idx = i - 1;
                let key = (idx, s.semantics, raw_method_idx);
                let include = match remaining_property_counts.get_mut(&key) {
                    Some(count) if *count > 0 => {
                        *count -= 1;
                        true
                    }
                    _ => false,
                };
                (SemanticsAssociation::Property(idx), include)
            }
            HasSemantics::Null => throw!("invalid null index for method semantics",),
        };

        if !include {
            continue;
        }

        let Some(&method_idx) = methods.get(raw_method_idx) else {
            throw!("invalid method index {} for method semantics", raw_method_idx)
        };

        semantics_by_type
            .entry(method_idx.parent_type.0)
            .or_default()
            .push(SemanticsAction {
                raw_method_idx,
                semantics: s.semantics,
                association,
            });
    }

    let mut work_by_type = semantics_by_type
        .into_iter()
        .map(|(parent_type, actions)| {
            let type_idx = TypeIndex(parent_type);
            let method_start = methods.partition_point(|m| m.parent_type < type_idx);
            let method_end = methods.partition_point(|m| m.parent_type <= type_idx);

            TypeSemanticsWork {
                parent_type,
                method_start,
                method_end,
                actions,
            }
        })
        .collect::<Vec<_>>();
    work_by_type.sort_unstable_by_key(|work| work.parent_type);

    apply_method_semantics_work(types, methods, &work_by_type, 0, 0, properties, events)
}

struct DecodedMemberRefs<'a> {
    field_refs: Vec<members::ExternalFieldReference<'a>>,
    field_map: HashMap<usize, usize>,
    method_refs: Vec<members::ExternalMethodReference<'a>>,
    method_map: HashMap<usize, usize>,
    sig_pending_ref: Vec<crate::binary::metadata::index::Blob>,
}

fn decode_member_refs<'a>(
    tables: &metadata::table::Tables,
    strings: &StringsReader<'a>,
    blobs: &BlobReader<'a>,
    module_refs: &[module::ExternalModuleReference<'a>],
    methods: &[MethodIndex],
    ctx: &convert::read::Context<'_, 'a>,
    opts: Options,
) -> Result<DecodedMemberRefs<'a>> {
    let member_ref_len = tables.member_ref.len();
    let mut field_refs = Vec::with_capacity(member_ref_len);
    let mut field_map = HashMap::with_capacity_and_hasher(member_ref_len, Default::default());
    let mut method_refs = Vec::with_capacity(member_ref_len);
    let mut method_map = HashMap::with_capacity_and_hasher(member_ref_len, Default::default());
    let mut sig_pending_ref: Vec<crate::binary::metadata::index::Blob> = if opts.lazy_method_signatures {
        Vec::with_capacity(member_ref_len)
    } else {
        vec![]
    };

    for (orig_idx, r) in tables.member_ref.iter().enumerate() {
        use members::*;
        use metadata::index::{MemberRefParent, TypeDefOrRef};

        let name = strings.at_index(r.name).map_err(CLI)?.into();
        let sig_blob = blobs.at_index(r.signature).map_err(CLI)?;

        let Some(&sig_kind) = sig_blob.first() else {
            continue;
        };

        if sig_kind == 0x06 {
            use crate::binary::signature::kinds::FieldSig;

            // NOTE: discarding errors means wasted allocation of formatted messages
            let field_sig: FieldSig = match sig_blob.pread(0) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let parent = match r.class {
                MemberRefParent::TypeDef(i) => {
                    FieldReferenceParent::Type(convert::read::type_idx(TypeDefOrRef::TypeDef(i), ctx)?)
                }
                MemberRefParent::TypeRef(i) => {
                    FieldReferenceParent::Type(convert::read::type_idx(TypeDefOrRef::TypeRef(i), ctx)?)
                }
                MemberRefParent::TypeSpec(i) => {
                    FieldReferenceParent::Type(convert::read::type_idx(TypeDefOrRef::TypeSpec(i), ctx)?)
                }
                MemberRefParent::ModuleRef(i) => {
                    let idx = i - 1;
                    if idx < module_refs.len() {
                        FieldReferenceParent::Module(ModuleRefIndex(idx))
                    } else {
                        throw!("invalid module reference index {} for field reference {}", idx, name);
                    }
                }
                _ => continue,
            };

            let field_type = MemberType::from_sig(field_sig.field_type, ctx)?;
            let mut custom_modifiers = Vec::with_capacity(field_sig.custom_modifiers.len());
            for c in field_sig.custom_modifiers {
                custom_modifiers.push(convert::read::custom_modifier(c, ctx)?);
            }

            let current_idx = field_refs.len();
            field_map.insert(orig_idx, current_idx);
            field_refs.push(ExternalFieldReference {
                attributes: vec![],
                parent,
                name,
                custom_modifiers,
                field_type,
            });
        } else {
            use crate::binary::signature::kinds::{CallingConvention, MethodRefSig};

            // NOTE: discarding errors means wasted allocation of formatted messages
            let ref_sig: MethodRefSig = match sig_blob.pread(0) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let signature = if opts.lazy_method_signatures {
                sig_pending_ref.push(r.signature);
                Default::default()
            } else {
                let mut sig = convert::read::managed_method(ref_sig.method_def, ctx)?;
                if sig.calling_convention == CallingConvention::Vararg {
                    let mut varargs = Vec::with_capacity(ref_sig.varargs.len());
                    for p in ref_sig.varargs {
                        varargs.push(convert::read::parameter(p, ctx)?);
                    }
                    sig.varargs = Some(varargs);
                }
                sig
            };

            let parent = match r.class {
                MemberRefParent::TypeDef(i) => {
                    MethodReferenceParent::Type(convert::read::type_idx(TypeDefOrRef::TypeDef(i), ctx)?)
                }
                MemberRefParent::TypeRef(i) => {
                    MethodReferenceParent::Type(convert::read::type_idx(TypeDefOrRef::TypeRef(i), ctx)?)
                }
                MemberRefParent::TypeSpec(i) => {
                    MethodReferenceParent::Type(convert::read::type_idx(TypeDefOrRef::TypeSpec(i), ctx)?)
                }
                MemberRefParent::ModuleRef(i) => {
                    let idx = i - 1;
                    if idx < module_refs.len() {
                        MethodReferenceParent::Module(ModuleRefIndex(idx))
                    } else {
                        throw!("invalid module reference index {} for method reference {}", idx, name);
                    }
                }
                MemberRefParent::MethodDef(i) => {
                    let idx = i - 1;
                    match methods.get(idx) {
                        Some(&m) => MethodReferenceParent::VarargMethod(m),
                        None => throw!("bad method def index {} for method reference {}", idx, name),
                    }
                }
                MemberRefParent::Null => throw!("invalid null parent index for method reference {}", name),
            };

            let current_idx = method_refs.len();
            method_map.insert(orig_idx, current_idx);
            method_refs.push(ExternalMethodReference {
                attributes: vec![],
                parent,
                name,
                signature,
            });
        }
    }

    Ok(DecodedMemberRefs {
        field_refs,
        field_map,
        method_refs,
        method_map,
        sig_pending_ref,
    })
}

#[allow(clippy::too_many_lines, clippy::nonminimal_bool)]
pub(crate) fn read_impl<'a>(dll: &DLL<'a>, opts: Options) -> Result<Resolution<'a>> {
    let (strings, blobs, guids, userstrings, logical) = dll.get_all_streams()?;
    let tables = logical.tables;

    let def_len = tables.type_def.len();
    let ref_len = tables.type_ref.len();
    let ctx = convert::read::Context {
        def_len,
        ref_len,
        specs: &tables.type_spec,
        sigs: &tables.stand_alone_sig,
        blobs: &blobs,
        userstrings: &userstrings,
    };

    stage_start!(stage_timer);
    debug!("assembly");
    let mut assembly = decode_assembly(&tables, &strings, &blobs)?;
    stage_end!(stage_timer, "assembly");

    stage_start!(stage_timer);
    debug!("assembly refs");
    let assembly_refs = decode_assembly_refs(&tables, &strings, &blobs)?;
    stage_end!(stage_timer, "assembly refs");

    stage_start!(stage_timer);
    debug!("type definitions");
    let mut types = decode_type_definitions(&tables, &strings, &ctx)?;
    stage_end!(stage_timer, "type definitions");

    debug!("nested types");

    for n in &tables.nested_class {
        let nest_idx = n.nested_class.0 - 1;
        match types.get_mut(nest_idx) {
            Some(t) => {
                let enclose_idx = n.enclosing_class.0 - 1;
                if enclose_idx < tables.type_def.len() {
                    t.encloser = Some(TypeIndex(enclose_idx));
                } else {
                    throw!(
                        "invalid enclosing type index {} for nested class declaration of type {}",
                        nest_idx,
                        t.name
                    );
                }
            }
            None => throw!("invalid type index {} for nested class declaration", nest_idx),
        }
    }

    debug!("files");
    let files = decode_files(&tables, &strings, &blobs)?;

    debug!("resources");
    let resources = decode_resources(dll, &tables, &strings, &files, &assembly_refs)?;

    debug!("exported types");
    let exports = decode_exported_types(&tables, &strings, &files, &assembly_refs)?;

    let module = decode_module(&tables, &strings, &guids)?;

    debug!("resolving module {}", module.name);

    let module_refs = decode_module_refs(&tables, &strings)?;

    debug!("type refs");
    let type_refs = decode_type_refs(&tables, &strings, &module_refs, &assembly_refs)?;

    debug!("interfaces");
    let interface_idxs = decode_interfaces(&tables, &mut types, &ctx)?;

    stage_start!(stage_timer);
    debug!("fields");
    let fields = decode_fields(&mut types, &tables, &strings, &blobs, &ctx)?;
    stage_end!(stage_timer, "fields");

    debug!("field layout");

    {
        use rayon::prelude::*;

        let field_layout_updates = tables
            .field_layout
            .par_iter()
            .map(|layout| {
                let idx = layout.field.0 - 1;
                match fields.get(idx) {
                    Some(&field) => Ok((field, layout.offset as usize)),
                    None => throw!("bad parent field index {} for field layout specification", idx),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        for (field, offset) in field_layout_updates {
            get_field_mut(&mut types, field).offset = Some(offset);
        }
    }

    debug!("field rva");

    {
        use rayon::prelude::*;

        let field_rva_updates = tables
            .field_rva
            .par_iter()
            .map(|rva| {
                let idx = rva.field.0 - 1;
                match fields.get(idx) {
                    Some(&field) => Ok((field, dll.raw_rva(rva.rva)?.into())),
                    None => throw!("bad parent field index {} for field RVA specification", idx),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        for (field, initial_value) in field_rva_updates {
            get_field_mut(&mut types, field).initial_value = Some(initial_value);
        }
    }

    stage_start!(stage_timer);
    debug!("methods");
    let DecodedMethods {
        mut methods,
        owned_params,
        sig_pending_def,
    } = decode_methods(&mut types, &tables, &strings, &blobs, &ctx, opts)?;
    stage_end!(stage_timer, "methods");

    // only should be used before the event/method semantics phase
    // since before then we know member index is a Method(usize)
    macro_rules! get_method {
        ($unwrap:expr) => {{
            let MethodIndex { parent_type, member } = $unwrap;
            &mut types[parent_type.0].methods[match member {
                MethodMemberIndex::Method(i) => i,
                _ => unreachable!(),
            }]
        }};
    }

    debug!("pinvoke");

    {
        use members::*;
        use metadata::index::MemberForwarded;
        use rayon::prelude::*;

        enum PInvokeTarget {
            Field(FieldIndex),
            Method(MethodIndex),
        }

        let pinvoke_updates = tables
            .impl_map
            .par_iter()
            .map(|i| {
                let name = heap_idx!(strings, i.import_name);

                let value = PInvoke {
                    no_mangle: check_bitmask!(i.mapping_flags, 0x1),
                    character_set: match i.mapping_flags & 0x6 {
                        0x0 => CharacterSet::NotSpecified,
                        0x2 => CharacterSet::Ansi,
                        0x4 => CharacterSet::Unicode,
                        0x6 => CharacterSet::Auto,
                        bad => throw!(
                            "invalid character set specifier {:#03x} for PInvoke import {}",
                            bad,
                            name
                        ),
                    },
                    supports_last_error: check_bitmask!(i.mapping_flags, 0x40),
                    calling_convention: match i.mapping_flags & 0x700 {
                        0x100 => UnmanagedCallingConvention::Platformapi,
                        0x200 => UnmanagedCallingConvention::Cdecl,
                        0x300 => UnmanagedCallingConvention::Stdcall,
                        0x400 => UnmanagedCallingConvention::Thiscall,
                        0x500 => UnmanagedCallingConvention::Fastcall,
                        bad => throw!(
                            "invalid calling convention specifier {:#05x} for PInvoke import {}",
                            bad,
                            name
                        ),
                    },
                    import_name: name.clone(),
                    import_scope: {
                        let idx = i.import_scope.0 - 1;

                        if idx < module_refs.len() {
                            ModuleRefIndex(idx)
                        } else {
                            throw!("invalid module reference index {} for PInvoke import {}", idx, name)
                        }
                    },
                };

                let target = match i.member_forwarded {
                    MemberForwarded::Field(i) => {
                        let idx = i - 1;

                        match fields.get(idx) {
                            Some(&i) => PInvokeTarget::Field(i),
                            None => throw!("invalid field index {} for PInvoke import {}", idx, name),
                        }
                    }
                    MemberForwarded::MethodDef(i) => {
                        let idx = i - 1;

                        match methods.get(idx) {
                            Some(&m) => PInvokeTarget::Method(m),
                            None => throw!("invalid method index {} for PInvoke import {}", idx, name),
                        }
                    }
                    MemberForwarded::Null => {
                        throw!("invalid null member index for PInvoke import {}", name)
                    }
                };

                Ok((target, value))
            })
            .collect::<Result<Vec<_>>>()?;

        for (target, value) in pinvoke_updates {
            match target {
                PInvokeTarget::Field(field) => get_field_mut(&mut types, field).pinvoke = Some(value),
                PInvokeTarget::Method(method) => get_method!(method).pinvoke = Some(value),
            }
        }
    }

    debug!("security");

    for (idx, s) in tables.decl_security.iter().enumerate() {
        use attribute::*;
        use metadata::index::HasDeclSecurity;

        let parent = match s.parent {
            HasDeclSecurity::TypeDef(t) => {
                let t_idx = t - 1;
                match types.get_mut(t_idx) {
                    Some(t) => &mut t.security,
                    None => throw!("invalid type parent index {} for security declaration {}", t_idx, idx),
                }
            }
            HasDeclSecurity::MethodDef(m) => {
                let m_idx = m - 1;
                match methods.get(m_idx) {
                    Some(&m) => &mut get_method!(m).security,
                    None => throw!("invalid method parent index {} for security declaration {}", m_idx, idx),
                }
            }
            HasDeclSecurity::Assembly(_) => match &mut assembly {
                Some(a) => &mut a.security,
                None => throw!(
                    "invalid assembly parent index for security declaration {} when no assembly exists in the current module",
                    idx
                ),
            },
            HasDeclSecurity::Null => throw!("invalid null parent index for security declaration {}", idx),
        };

        *parent = Some(SecurityDeclaration {
            attributes: vec![],
            action: s.action,
            value: heap_idx!(blobs, s.permission_set),
        });
    }

    debug!("generic parameters");

    let mut constraint_map =
        HashMap::with_capacity_and_hasher(tables.generic_param_constraint.len(), Default::default());

    // this table is supposed to be sorted by owner and number (ECMA-335, II.22, page 210)
    // thus no need to sort the generics by sequence after the fact
    for (param_idx, p) in tables.generic_param.iter().enumerate() {
        use metadata::index::TypeOrMethodDef;

        let name = heap_idx!(strings, p.name);

        match p.owner {
            TypeOrMethodDef::TypeDef(i) => {
                let idx = i - 1;
                match types.get_mut(idx) {
                    Some(t) => {
                        t.generic_parameters.push(make_generic(
                            name,
                            p,
                            param_idx,
                            &mut constraint_map,
                            &tables,
                            &ctx,
                        )?);
                    }
                    None => throw!("invalid type index {} for generic parameter {}", idx, name),
                }
            }
            TypeOrMethodDef::MethodDef(i) => {
                let idx = i - 1;
                let method = match methods.get(idx) {
                    Some(&m) => get_method!(m),
                    None => throw!("invalid method index {} for generic parameter {}", idx, name),
                };

                method
                    .generic_parameters
                    .push(make_generic(name, p, param_idx, &mut constraint_map, &tables, &ctx)?);
            }
            TypeOrMethodDef::Null => {
                throw!("invalid null owner index for generic parameter {}", name)
            }
        }
    }

    stage_start!(stage_timer);
    debug!("params");
    let params = decode_params(&mut types, &tables, &strings, &methods, owned_params)?;
    stage_end!(stage_timer, "params");

    debug!("field marshal");

    {
        use crate::binary::{metadata::index::HasFieldMarshal, signature::kinds::MarshalSpec};
        use rayon::prelude::*;

        let field_marshal_updates = tables
            .field_marshal
            .par_iter()
            .filter_map(|marshal| match marshal.parent {
                HasFieldMarshal::Field(_) => Some(marshal),
                _ => None,
            })
            .map(|marshal| {
                let idx = match marshal.parent {
                    HasFieldMarshal::Field(i) => i - 1,
                    _ => unreachable!(),
                };
                match fields.get(idx) {
                    Some(&field) => Ok((field, heap_idx!(blobs, marshal.native_type).pread::<MarshalSpec>(0)?)),
                    None => throw!("bad field index {} for field marshal", idx),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        for (field, marshal) in field_marshal_updates {
            get_field_mut(&mut types, field).marshal = Some(marshal);
        }

        for marshal in &tables.field_marshal {
            match marshal.parent {
                HasFieldMarshal::Field(_) => {}
                HasFieldMarshal::Param(i) => {
                    let value = Some(heap_idx!(blobs, marshal.native_type).pread::<MarshalSpec>(0)?);
                    let idx = i - 1;
                    match params.get(idx) {
                        Some(&(m_idx, p_idx)) => {
                            let method = get_method!(methods[m_idx]);

                            let param_meta = if p_idx == 0 {
                                &mut method.return_type_metadata
                            } else {
                                &mut method.parameter_metadata[p_idx - 1]
                            };

                            param_meta.as_mut().unwrap().marshal = value;
                        }
                        None => throw!("bad parameter index {} for field marshal", idx),
                    }
                }
                HasFieldMarshal::Null => throw!("invalid null parent index for field marshal"),
            }
        }
    }

    stage_start!(stage_timer);
    debug!("properties");
    let properties = decode_properties(&mut types, &tables, &strings, &blobs, &ctx)?;
    stage_end!(stage_timer, "properties");

    debug!("constants");

    for (idx, c) in tables.constant.iter().enumerate() {
        use crate::binary::signature::encoded::*;
        use members::Constant::*;
        use metadata::index::HasConstant;

        let blob = heap_idx!(blobs, c.value);

        let value = Some(match c.constant_type {
            ELEMENT_TYPE_BOOLEAN => Boolean(blob.pread_with::<u8>(0, scroll::LE)? == 1),
            ELEMENT_TYPE_CHAR => Char(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_I1 => Int8(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_U1 => UInt8(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_I2 => Int16(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_U2 => UInt16(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_I4 => Int32(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_U4 => UInt32(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_I8 => Int64(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_U8 => UInt64(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_R4 => Float32(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_R8 => Float64(blob.pread_with(0, scroll::LE)?),
            ELEMENT_TYPE_STRING => {
                let num_utf16 = blob.len() / 2;
                let mut offset = 0;
                let chars = (0..num_utf16)
                    .map(|_| blob.gread_with(&mut offset, scroll::LE))
                    .collect::<scroll::Result<Vec<_>>>()?;
                String(chars)
            }
            ELEMENT_TYPE_CLASS => {
                let t: u32 = blob.pread_with(0, scroll::LE)?;
                if t == 0 {
                    Null
                } else {
                    throw!(
                        "invalid class reference {:#010x} for constant {}, only null references allowed",
                        t,
                        idx
                    )
                }
            }
            bad => throw!("unrecognized element type {:#04x} for constant {}", bad, idx),
        });

        match c.parent {
            HasConstant::Field(i) => {
                let f_idx = i - 1;

                match fields.get(f_idx) {
                    Some(&i) => get_field_mut(&mut types, i).default = value,
                    None => throw!("invalid field parent index {} for constant {}", f_idx, idx),
                }
            }
            HasConstant::Param(i) => {
                let p_idx = i - 1;

                match params.get(p_idx) {
                    Some(&(parent, internal)) => {
                        let method = get_method!(methods[parent]);

                        let param_meta = if internal == 0 {
                            &mut method.return_type_metadata
                        } else {
                            &mut method.parameter_metadata[internal - 1]
                        };

                        param_meta.as_mut().unwrap().default = value;
                    }
                    None => throw!("invalid parameter parent index {} for constant {}", p_idx, idx),
                }
            }
            HasConstant::Property(i) => {
                let f_idx = i - 1;

                match properties.get(f_idx) {
                    Some(&(parent, internal)) => {
                        types[parent].properties[internal].default = value;
                    }
                    None => throw!("invalid property parent index {} for constant {}", f_idx, idx),
                }
            }
            HasConstant::Null => throw!("invalid null parent index for constant {}", idx),
        }
    }

    // sorts in preparation for the binary search in extract_method
    methods.sort_unstable_by_key(|m| m.parent_type);

    let mut sem_by_event: HashMap<usize, Vec<(u16, usize)>> =
        HashMap::with_capacity_and_hasher(tables.event.len(), Default::default());
    let mut sem_by_property: HashMap<usize, Vec<(u16, usize)>> =
        HashMap::with_capacity_and_hasher(tables.property.len(), Default::default());

    for s in &tables.method_semantics {
        use metadata::index::HasSemantics;

        let method_idx = s.method.0 - 1;
        match s.association {
            HasSemantics::Event(e) => sem_by_event.entry(e - 1).or_default().push((s.semantics, method_idx)),
            HasSemantics::Property(p) => sem_by_property
                .entry(p - 1)
                .or_default()
                .push((s.semantics, method_idx)),
            HasSemantics::Null => {}
        }
    }

    stage_start!(stage_timer);
    debug!("events");
    let events = decode_events(&mut types, &tables, &strings, &ctx, &mut sem_by_event, &mut methods)?;
    stage_end!(stage_timer, "events");

    stage_start!(stage_timer);
    debug!("method semantics");
    apply_method_semantics(
        &mut types,
        &tables,
        &mut methods,
        &properties,
        &events,
        &sem_by_event,
        &sem_by_property,
    )?;
    stage_end!(stage_timer, "method semantics");

    stage_start!(stage_timer);
    debug!("field refs / method refs");
    let DecodedMemberRefs {
        field_refs,
        field_map,
        method_refs,
        method_map,
        sig_pending_ref,
    } = decode_member_refs(&tables, &strings, &blobs, &module_refs, &methods, &ctx, opts)?;
    stage_end!(stage_timer, "field refs / method refs");

    let m_ctx = convert::read::MethodContext {
        field_map: &field_map,
        field_indices: &fields,
        method_specs: &tables.method_spec,
        method_indices: &methods,
        method_map: &method_map,
    };

    debug!("method impl");

    for i in &tables.method_impl {
        use types::*;

        let idx = i.class.0 - 1;
        match types.get_mut(idx) {
            Some(t) => t.overrides.push(MethodOverride {
                implementation: convert::read::user_method(i.method_body, &m_ctx)?,
                declaration: convert::read::user_method(i.method_declaration, &m_ctx)?,
            }),
            None => throw!("invalid parent type index {} for method override", idx),
        }
    }

    use metadata::{
        index::{Token, TokenTarget},
        table::Kind,
    };

    let entry_token = dll.cli.entry_point_token.to_le_bytes().pread::<Token>(0)?;

    let mut res = Resolution {
        assembly,
        assembly_references: assembly_refs,
        entry_point: if entry_token.index == 0 {
            None
        } else {
            let entry_idx = entry_token.index - 1;
            Some(match entry_token.target {
                TokenTarget::Table(Kind::MethodDef) => match methods.get(entry_idx) {
                    Some(&m) => EntryPoint::Method(m),
                    None => throw!("invalid method index {} for entry point", entry_idx),
                },
                TokenTarget::Table(Kind::File) => {
                    if entry_idx < files.len() {
                        EntryPoint::File(FileIndex(entry_idx))
                    } else {
                        throw!("invalid file index {} for entry point", entry_idx)
                    }
                }
                bad => throw!("invalid entry point metadata token {:?}", bad),
            })
        },
        exported_types: exports,
        field_references: field_refs,
        files,
        manifest_resources: resources,
        method_references: method_refs,
        module,
        module_references: module_refs,
        type_definitions: types,
        type_references: type_refs,
        lazy_state: None,
    };

    stage_start!(stage_timer);
    debug!("custom attributes");

    if !opts.lazy_attributes {
        for (idx, a) in tables.custom_attribute.iter().enumerate() {
            use attribute::*;
            use members::UserMethod;
            use metadata::index::{CustomAttributeType, HasCustomAttribute::*};

            let attr = Attribute {
                constructor: match a.attr_type {
                    CustomAttributeType::MethodDef(i) => {
                        let m_idx = i - 1;
                        match methods.get(m_idx) {
                            Some(&m) => UserMethod::Definition(m),
                            None => throw!(
                                "invalid method index {} for constructor of custom attribute {}",
                                m_idx,
                                idx
                            ),
                        }
                    }
                    CustomAttributeType::MemberRef(i) => {
                        let r_idx = i - 1;
                        match method_map.get(&r_idx) {
                            Some(&m_idx) => UserMethod::Reference(MethodRefIndex(m_idx)),
                            None => throw!(
                                "invalid member reference index {} for constructor of custom attribute {}",
                                r_idx,
                                idx
                            ),
                        }
                    }
                    CustomAttributeType::Null => {
                        throw!("invalid null index for constructor of custom attribute {}", idx)
                    }
                },
                value: optional_idx!(blobs, a.value),
            };

            // panicking indexers after the indexes from the attribute are okay here,
            // since they've already been checked during resolution

            macro_rules! do_at_generic {
                ($g:expr, |$capt:ident| $do:expr) => {{
                    use metadata::index::TypeOrMethodDef;
                    let g = $g;
                    match g.owner {
                        TypeOrMethodDef::TypeDef(t) => {
                            let $capt = &mut res.type_definitions[t - 1].generic_parameters[g.number as usize];
                            $do;
                        }
                        TypeOrMethodDef::MethodDef(m) => {
                            let $capt = &mut res[methods[m - 1]].generic_parameters[g.number as usize];
                            $do;
                        }
                        TypeOrMethodDef::Null => unreachable!(),
                    }
                }};
            }

            match a.parent {
                MethodDef(i) => {
                    let m_idx = i - 1;
                    match methods.get(m_idx) {
                        Some(&m) => res[m].attributes.push(attr),
                        None => throw!("invalid method index {} for parent of custom attribute {}", m_idx, idx),
                    }
                }
                Field(i) => {
                    let f_idx = i - 1;
                    match fields.get(f_idx) {
                        Some(&i) => res[i].attributes.push(attr),
                        None => throw!("invalid field index {} for parent of custom attribute {}", f_idx, idx),
                    }
                }
                TypeRef(i) => {
                    let r_idx = i - 1;
                    match res.type_references.get_mut(r_idx) {
                        Some(r) => r.attributes.push(attr),
                        None => throw!(
                            "invalid type reference index {} for parent of custom attribute {}",
                            r_idx,
                            idx
                        ),
                    }
                }
                TypeDef(i) => {
                    let t_idx = i - 1;
                    match res.type_definitions.get_mut(t_idx) {
                        Some(t) => t.attributes.push(attr),
                        None => throw!(
                            "invalid type definition index {} for parent of custom attribute {}",
                            t_idx,
                            idx
                        ),
                    }
                }
                Param(i) => {
                    let p_idx = i - 1;
                    match params.get(p_idx) {
                        Some(&(parent, internal)) => {
                            let method = &mut res[methods[parent]];

                            let param_meta = if internal == 0 {
                                &mut method.return_type_metadata
                            } else {
                                &mut method.parameter_metadata[internal - 1]
                            };

                            param_meta.as_mut().unwrap().attributes.push(attr);
                        }
                        None => throw!(
                            "invalid parameter index {} for parent of custom attribute {}",
                            p_idx,
                            idx
                        ),
                    }
                }
                InterfaceImpl(i) => {
                    let i_idx = i - 1;

                    match interface_idxs.get(i_idx) {
                        Some(&(parent, internal)) => res.type_definitions[parent].implements[internal].0.push(attr),
                        None => throw!(
                            "invalid interface implementation index {} for parent of custom attribute {}",
                            i_idx,
                            idx
                        ),
                    }
                }
                MemberRef(i) => {
                    let m_idx = i - 1;

                    match field_map.get(&m_idx) {
                        Some(&f) => res.field_references[f].attributes.push(attr),
                        None => match method_map.get(&m_idx) {
                            Some(&m) => res.method_references[m].attributes.push(attr),
                            None => throw!(
                                "invalid member reference index {} for parent of custom attribute {}",
                                m_idx,
                                idx
                            ),
                        },
                    }
                }
                Module(_) => res.module.attributes.push(attr),
                DeclSecurity(i) => {
                    use metadata::index::HasDeclSecurity;

                    let s_idx = i - 1;

                    match tables.decl_security.get(s_idx) {
                        Some(s) => match s.parent {
                            HasDeclSecurity::TypeDef(t) => res.type_definitions[t - 1]
                                .security
                                .as_mut()
                                .unwrap()
                                .attributes
                                .push(attr),
                            HasDeclSecurity::MethodDef(m) => {
                                res[methods[m - 1]].security.as_mut().unwrap().attributes.push(attr)
                            }
                            HasDeclSecurity::Assembly(_) => res
                                .assembly
                                .as_mut()
                                .and_then(|a| a.security.as_mut())
                                .unwrap()
                                .attributes
                                .push(attr),
                            HasDeclSecurity::Null => unreachable!(),
                        },
                        None => throw!(
                            "invalid security declaration index {} for parent of custom attribute {}",
                            s_idx,
                            idx
                        ),
                    }
                }
                Property(i) => {
                    let p_idx = i - 1;

                    match properties.get(p_idx) {
                        Some(&(parent, internal)) => {
                            res.type_definitions[parent].properties[internal].attributes.push(attr)
                        }
                        None => throw!(
                            "invalid property index {} for parent of custom attribute {}",
                            p_idx,
                            idx
                        ),
                    }
                }
                Event(i) => {
                    let e_idx = i - 1;

                    match events.get(e_idx) {
                        Some(&(parent, internal)) => {
                            res.type_definitions[parent].events[internal].attributes.push(attr)
                        }
                        None => throw!("invalid event index {} for parent of custom attribute {}", e_idx, idx),
                    }
                }
                ModuleRef(i) => {
                    let m_idx = i - 1;

                    match res.module_references.get_mut(m_idx) {
                        Some(m) => m.attributes.push(attr),
                        None => throw!(
                            "invalid module reference index {} for parent of custom attribute {}",
                            m_idx,
                            idx
                        ),
                    }
                }
                Assembly(_) => match res.assembly.as_mut() {
                    Some(a) => a.attributes.push(attr),
                    None => throw!(
                        "custom attribute {} has the module assembly as a parent, but this module does not have an assembly",
                        idx
                    ),
                },
                AssemblyRef(i) => {
                    let r_idx = i - 1;

                    match res.assembly_references.get_mut(r_idx) {
                        Some(a) => a.attributes.push(attr),
                        None => throw!(
                            "invalid assembly reference index {} for parent of custom attribute {}",
                            r_idx,
                            idx
                        ),
                    }
                }
                File(i) => {
                    let f_idx = i - 1;

                    match res.files.get_mut(f_idx) {
                        Some(f) => f.attributes.push(attr),
                        None => throw!("invalid file index {} for parent of custom attribute {}", f_idx, idx),
                    }
                }
                ExportedType(i) => {
                    let e_idx = i - 1;

                    match res.exported_types.get_mut(e_idx) {
                        Some(e) => e.attributes.push(attr),
                        None => throw!(
                            "invalid exported type index {} for parent of custom attribute {}",
                            e_idx,
                            idx
                        ),
                    }
                }
                ManifestResource(i) => {
                    let r_idx = i - 1;

                    match res.manifest_resources.get_mut(r_idx) {
                        Some(r) => r.attributes.push(attr),
                        None => throw!(
                            "invalid manifest resource index {} for parent of custom attribute {}",
                            r_idx,
                            idx
                        ),
                    }
                }
                GenericParam(i) => {
                    let g_idx = i - 1;

                    match tables.generic_param.get(g_idx) {
                        Some(g) => do_at_generic!(g, |rg| rg.attributes.push(attr)),
                        None => throw!(
                            "invalid generic parameter index {} for parent of custom attribute {}",
                            g_idx,
                            idx
                        ),
                    }
                }
                GenericParamConstraint(i) => {
                    let g_idx = i - 1;

                    match constraint_map.get(&g_idx) {
                        Some(&(generic, internal)) => do_at_generic!(tables.generic_param[generic], |g| g
                            .type_constraints[internal]
                            .attributes
                            .push(attr)),
                        None => throw!(
                            "invalid generic constraint index {} for parent of custom attribute {}",
                            g_idx,
                            idx
                        ),
                    }
                }
                MethodSpec(_) => {
                    warn!(
                        "custom attribute {} has a MethodSpec parent, this is not supported by dotnetdll",
                        idx
                    );
                }
                StandAloneSig(_) => {
                    warn!(
                        "custom attribute {} has a StandAloneSig parent, this is not supported by dotnetdll",
                        idx
                    );
                }
                TypeSpec(_) => {
                    warn!(
                        "custom attribute {} has a TypeSpec parent, this is not supported by dotnetdll",
                        idx
                    );
                }
                Null => throw!("invalid null index for parent of custom attribute {}", idx),
            }
        }
    } // end if !opts.lazy_attributes
    stage_end!(stage_timer, "custom attributes");

    if opts.lazy_method_bodies || opts.lazy_method_signatures || opts.lazy_attributes {
        debug!("building lazy parse state");

        // Build sparse attribute maps in one pass before the LazyParseState literal.
        let (attr_by_type, attr_by_method, attr_by_field, attr_by_assembly) = if opts.lazy_attributes {
            use crate::binary::metadata::index::{CustomAttributeType, HasCustomAttribute};
            use crate::resolved::members::UserMethod;

            let mut by_type: HashMap<usize, Vec<lazy::AttrRaw>> = HashMap::default();
            let mut by_method: HashMap<usize, Vec<lazy::AttrRaw>> = HashMap::default();
            let mut by_field: HashMap<usize, Vec<lazy::AttrRaw>> = HashMap::default();
            let mut by_asm: Vec<lazy::AttrRaw> = Vec::new();

            for a in &tables.custom_attribute {
                let constructor = match a.attr_type {
                    CustomAttributeType::MethodDef(i) => UserMethod::Definition(methods[i - 1]),
                    CustomAttributeType::MemberRef(i) => {
                        let m_idx = match method_map.get(&(i - 1)) {
                            Some(&m) => m,
                            None => continue,
                        };
                        UserMethod::Reference(MethodRefIndex(m_idx))
                    }
                    CustomAttributeType::Null => continue,
                };
                let blob_idx = if a.value.is_null() { None } else { Some(a.value) };
                let raw = (constructor, blob_idx);
                match a.parent {
                    HasCustomAttribute::TypeDef(i) => by_type.entry(i - 1).or_default().push(raw),
                    HasCustomAttribute::MethodDef(i) => by_method.entry(i - 1).or_default().push(raw),
                    HasCustomAttribute::Field(i) => by_field.entry(i - 1).or_default().push(raw),
                    HasCustomAttribute::Assembly(_) => by_asm.push(raw),
                    _ => {}
                }
            }
            (by_type, by_method, by_field, by_asm)
        } else {
            (HashMap::default(), HashMap::default(), HashMap::default(), Vec::new())
        };

        let n = tables.method_def.len();
        let (pending, method_idx_to_def, body_cache) = if opts.lazy_method_bodies {
            debug!("  lazy method bodies");
            let mut pending = Vec::with_capacity(n);
            let mut method_idx_to_def: HashMap<MethodIndex, usize> =
                HashMap::with_capacity_and_hasher(n, Default::default());
            let mut body_cache = Vec::with_capacity(n);

            for (def_idx, m) in tables.method_def.iter().enumerate() {
                if m.rva != 0 {
                    let (bytes, offset) = dll.method_bytes(m)?;
                    pending.push(Some(lazy::MethodPendingRaw { bytes, offset }));
                    method_idx_to_def.insert(methods[def_idx], def_idx);
                } else {
                    pending.push(None);
                }
                body_cache.push(std::sync::OnceLock::new());
            }
            (pending, method_idx_to_def, body_cache)
        } else {
            (vec![], HashMap::with_capacity_and_hasher(0, Default::default()), vec![])
        };

        let (
            method_spec_table,
            field_map_for_bodies,
            field_indices_for_bodies,
            method_indices_for_bodies,
            method_map_for_bodies,
        ) = if opts.lazy_method_bodies {
            (
                tables.method_spec.clone(),
                field_map.clone(),
                fields.clone(),
                methods.clone(),
                method_map.clone(),
            )
        } else {
            (
                vec![],
                HashMap::with_capacity_and_hasher(0, Default::default()),
                vec![],
                vec![],
                HashMap::with_capacity_and_hasher(0, Default::default()),
            )
        };

        // Signature MethodIndex -> method_def_idx map must be built AFTER method semantics,
        // because semantics may rewrite MethodIndex::member variants. Defer map construction
        // to first `method_signature` access; keep def-order MethodIndex rows as source data.
        let sig_method_indices = if opts.lazy_method_signatures && !opts.lazy_method_bodies {
            methods.clone()
        } else {
            vec![]
        };

        res.lazy_state = Some(Arc::new(lazy::LazyParseState {
            lazy_bodies: opts.lazy_method_bodies,
            lazy_signatures: opts.lazy_method_signatures,
            lazy_attributes: opts.lazy_attributes,
            def_len,
            ref_len,
            specs: tables.type_spec.clone(),
            sigs: tables.stand_alone_sig.clone(),
            method_spec_table,
            blobs,
            userstrings,
            field_map: field_map_for_bodies,
            field_indices: field_indices_for_bodies,
            method_indices: method_indices_for_bodies,
            method_map: method_map_for_bodies,
            pending,
            method_idx_to_def,
            body_cache,
            sig_method_indices,
            sig_method_idx_to_def: std::sync::OnceLock::new(),
            sig_pending_def,
            sig_cache_def: std::sync::OnceLock::new(),
            sig_pending_ref,
            sig_cache_ref: std::sync::OnceLock::new(),
            attr_by_type,
            attr_by_method,
            attr_by_field,
            attr_by_assembly,
            attr_method_idx_to_def: if opts.lazy_attributes {
                methods.iter().enumerate().map(|(i, &m)| (m, i)).collect()
            } else {
                rustc_hash::FxHashMap::default()
            },
            attr_field_idx_to_def: if opts.lazy_attributes {
                fields.iter().enumerate().map(|(i, &f)| (f, i)).collect()
            } else {
                rustc_hash::FxHashMap::default()
            },
        }));
    } else if !opts.skip_method_bodies {
        debug!("method bodies");

        use rayon::prelude::*;

        let bodies: Vec<(MethodIndex, body::Method)> = tables
            .method_def
            .par_iter()
            .enumerate()
            .filter(|(_, m)| m.rva != 0)
            .map(|(idx, m)| -> Result<(MethodIndex, body::Method)> {
                let raw_body = dll.get_method(m)?;
                let body = lazy::decode_body_with_ctx(raw_body, &ctx, &m_ctx)?;
                Ok((methods[idx], body))
            })
            .collect::<Result<Vec<_>>>()?;

        for (method_idx, body) in bodies {
            res[method_idx].body = Some(body);
        }
    } // end else if !opts.skip_method_bodies

    debug!("resolved module {}", res.module.name);

    Ok(res)
}
