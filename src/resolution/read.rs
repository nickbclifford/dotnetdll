use super::{
    AssemblyRefIndex, EntryPoint, ExportedTypeIndex, FieldIndex, FileIndex, MethodIndex, MethodMemberIndex,
    MethodRefIndex, ModuleRefIndex, Resolution, TypeIndex, TypeRefIndex,
};
use crate::binary::{heap::*, metadata, method};
use crate::convert::{self, TypeKind};
use crate::dll::{DLLError::*, Result, DLL};
use crate::prelude::generic::{Constraint, Generic, SpecialConstraint, Variance};
use crate::resolved::{
    types::{MemberType, MethodType},
    *,
};
use scroll::Pread;
use std::borrow::Cow;
use std::collections::HashMap;
use tracing::{debug, warn};

/// A dictionary of options for [`Resolution::parse`] and [`DLL::resolve`].
#[derive(Debug, Default, Copy, Clone)]
pub struct Options {
    /// If this flag is set, [`Resolution::parse`] and [`DLL::resolve`] will not resolve the bodies of class methods,
    /// meaning [`Method::body`](members::Method::body) will always be `None`.
    ///
    /// [`Default`] value of `false`.
    pub skip_method_bodies: bool,
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

// we use filter_maps for the member refs because we distinguish between the two
// kinds by testing if they parse successfully or not, and filter_map makes it really
// easy to implement that inside an iterator. however, we need to propagate the Results
// through the final iterator so that they don't get turned into None and swallowed on failure
macro_rules! filter_map_try {
    ($e:expr) => {
        match $e {
            Ok(n) => n,
            Err(e) => return Some(Err(e)),
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

// since we're dealing with raw indices and not references, we have to think about what the other indices are pointing to
// if we remove an element, all the indices above it need to be adjusted accordingly for future iterations
fn extract_method<'a>(
    parent: &mut types::TypeDefinition<'a>,
    idx: MethodIndex,
    methods: &mut [MethodIndex],
    tables: &metadata::table::Tables,
) -> members::Method<'a> {
    let MethodMemberIndex::Method(internal_idx) = idx.member else { unreachable!() };

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
        type_constraints: tables
            .generic_param_constraint
            .iter()
            .enumerate()
            .filter_map(|(c_idx, c)| {
                if c.owner.0 - 1 == param_idx {
                    let (cmod, ty) = filter_map_try!(convert::read::idx_with_mod(c.constraint, ctx));
                    Some(Ok((
                        c_idx,
                        Constraint {
                            attributes: vec![],
                            custom_modifiers: cmod,
                            constraint_type: ty,
                        },
                    )))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .enumerate()
            .map(|(internal, (original, c))| {
                constraint_map.insert(original, (param_idx, internal));
                c
            })
            .collect(),
    })
}

#[allow(clippy::too_many_lines, clippy::nonminimal_bool)]
pub(crate) fn read_impl<'a>(dll: &DLL<'a>, opts: Options) -> Result<Resolution<'a>> {
    let strings: StringsReader = dll.get_heap()?;
    let blobs: BlobReader = dll.get_heap()?;
    let guids: GUIDReader = dll.get_heap()?;
    let userstrings: UserStringReader = dll.get_heap()?;
    let mut tables = dll.get_logical_metadata()?.tables;

    let ctx = convert::read::Context {
        def_len: tables.type_def.len(),
        ref_len: tables.type_ref.len(),
        specs: &tables.type_spec,
        sigs: &tables.stand_alone_sig,
        blobs: &blobs,
        userstrings: &userstrings,
    };

    macro_rules! range_index {
        (enumerated $enum:expr => range $field:ident in $table:ident indexes $index_table:ident) => {{
            let (idx, var) = $enum;
            let range = (var.$field.0 - 1)..(match tables.$table.get(idx + 1) {
                Some(r) => r.$field.0,
                None => tables.$index_table.len() + 1,
            } - 1);
            match tables.$index_table.get(range.clone()) {
                Some(rows) => range.zip(rows),
                None => throw!(
                    "invalid {} range in {} {}",
                    stringify!($index_table),
                    stringify!($table),
                    idx
                ),
            }
        }};
    }

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

    let assembly_refs = tables
        .assembly_ref
        .iter()
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
        .collect::<Result<Vec<_>>>()?;

    let mut types = tables
        .type_def
        .iter()
        .enumerate()
        .map(|(idx, t)| {
            use types::*;

            let layout_flags = t.flags & 0x18;
            let name = heap_idx!(strings, t.type_name);

            Ok(TypeDefinition {
                attributes: vec![],
                flags: TypeFlags::from_mask(
                    t.flags,
                    if layout_flags == 0x00 {
                        Layout::Automatic
                    } else {
                        let layout = tables.class_layout.iter().find(|c| c.parent.0 - 1 == idx);

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
                    Some(convert::read::type_source(t.extends, &ctx)?)
                },
                implements: vec![],
                generic_parameters: vec![],
                security: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;

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

    let owned_fields = tables
        .type_def
        .iter()
        .enumerate()
        .map(|e| Ok(range_index!(enumerated e => range field_list in type_def indexes field)))
        .collect::<Result<Vec<_>>>()?;

    let owned_methods = tables
        .type_def
        .iter()
        .enumerate()
        .map(|e| Ok(range_index!(enumerated e => range method_list in type_def indexes method_def)))
        .collect::<Result<Vec<_>>>()?;

    let files: Vec<_> = tables
        .file
        .iter()
        .map(|f| {
            Ok(module::File {
                attributes: vec![],
                has_metadata: !check_bitmask!(f.flags, 0x0001),
                name: heap_idx!(strings, f.name),
                hash_value: heap_idx!(blobs, f.hash_value),
            })
        })
        .collect::<Result<_>>()?;

    let resources: Vec<_> = tables
        .manifest_resource
        .iter()
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
                        let resources = dll.at_rva(&dll.cli.resources)?;
                        let len: u32 = resources.gread_with(&mut offset, scroll::LE)?;
                        Implementation::CurrentFile(resources[offset..offset + (len as usize)].into())
                    }
                },
                name,
            })
        })
        .collect::<Result<_>>()?;

    let exports: Vec<_> = tables
        .exported_type
        .iter()
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
        .collect::<Result<_>>()?;

    let module_row = tables
        .module
        .first()
        .ok_or_else(|| scroll::Error::Custom("missing required module metadata table".to_string()))?;
    let module = module::Module {
        attributes: vec![],
        name: heap_idx!(strings, module_row.name),
        mvid: guids.at_index(module_row.mvid)?,
    };

    debug!("resolving module {}", module.name);

    let module_refs = tables
        .module_ref
        .iter()
        .map(|r| {
            Ok(module::ExternalModuleReference {
                attributes: vec![],
                name: heap_idx!(strings, r.name),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    debug!("type refs");

    let type_refs = tables
        .type_ref
        .iter()
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
        .collect::<Result<Vec<_>>>()?;

    debug!("interfaces");

    let interface_idxs = tables
        .interface_impl
        .iter()
        .map(|i| {
            let idx = i.class.0 - 1;
            match types.get_mut(idx) {
                Some(t) => {
                    t.implements
                        .push((vec![], convert::read::type_source(i.interface, &ctx)?));

                    Ok((idx, t.implements.len() - 1))
                }
                None => throw!("invalid type index {} for interface implementation", idx),
            }
        })
        .collect::<Result<Vec<_>>>()?;

    fn member_accessibility(flags: u16) -> Result<members::Accessibility> {
        use members::Accessibility::*;
        use Accessibility::*;

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

    build_vec!(fields = FieldIndex[tables.field.len()], {
        debug!("fields");

        for (type_idx, type_fields) in owned_fields.into_iter().enumerate() {
            use crate::binary::signature::kinds::FieldSig;
            use members::*;

            let parent_fields = &mut types[type_idx].fields;
            parent_fields.reserve(type_fields.len());

            for (f_idx, f) in type_fields {
                let FieldSig {
                    custom_modifiers: cmod,
                    field_type: t,
                    by_ref,
                } = heap_idx!(blobs, f.signature).pread(0)?;

                parent_fields.push(Field {
                    attributes: vec![],
                    name: heap_idx!(strings, f.name),
                    type_modifiers: cmod
                        .into_iter()
                        .map(|c| convert::read::custom_modifier(c, &ctx))
                        .collect::<Result<_>>()?,
                    by_ref,
                    return_type: MemberType::from_sig(t, &ctx)?,
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
                fields[f_idx].write(FieldIndex {
                    parent_type: TypeIndex(type_idx),
                    field: parent_fields.len() - 1,
                });
            }
        }
    });

    macro_rules! get_field {
        ($f_idx:ident) => {{
            &mut types[$f_idx.parent_type.0].fields[$f_idx.field]
        }};
    }

    debug!("field layout");

    for layout in &tables.field_layout {
        let idx = layout.field.0 - 1;
        match fields.get(idx) {
            Some(&field) => {
                get_field!(field).offset = Some(layout.offset as usize);
            }
            None => throw!("bad parent field index {} for field layout specification", idx),
        }
    }

    debug!("field rva");

    for rva in &tables.field_rva {
        let idx = rva.field.0 - 1;
        match fields.get(idx) {
            Some(&field) => {
                get_field!(field).initial_value = Some(dll.raw_rva(rva.rva)?.into());
            }
            None => throw!("bad parent field index {} for field RVA specification", idx),
        }
    }

    let mut owned_params = Vec::with_capacity(tables.param.len());

    build_vec!(methods = MethodIndex[tables.method_def.len()], {
        debug!("methods");

        for (type_idx, type_methods) in owned_methods.into_iter().enumerate() {
            let parent_methods = &mut types[type_idx].methods;
            parent_methods.reserve(type_methods.len());

            for (m_idx, m) in type_methods {
                use members::*;

                let name = heap_idx!(strings, m.name);

                let mut sig = convert::read::managed_method(heap_idx!(blobs, m.signature).pread(0)?, &ctx)?;

                if check_bitmask!(m.flags, 0x10) {
                    sig.instance = false;
                }

                parent_methods.push(Method {
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
                    synchronized: check_bitmask!(m.impl_flags, 0x20),
                    no_inlining: check_bitmask!(m.impl_flags, 0x8),
                    no_optimization: check_bitmask!(m.impl_flags, 0x40),
                });

                methods[m_idx].write(MethodIndex {
                    parent_type: TypeIndex(type_idx),
                    member: MethodMemberIndex::Method(parent_methods.len() - 1),
                });

                owned_params.push((
                    m_idx,
                    range_index!(
                        enumerated (m_idx, m) =>
                        range param_list in method_def indexes param
                    ),
                ));
            }
        }
    });

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

    for i in &tables.impl_map {
        use members::*;
        use metadata::index::MemberForwarded;

        let name = heap_idx!(strings, i.import_name);

        let value = Some(PInvoke {
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
        });

        match i.member_forwarded {
            MemberForwarded::Field(i) => {
                let idx = i - 1;

                match fields.get(idx) {
                    Some(&i) => get_field!(i).pinvoke = value,
                    None => throw!("invalid field index {} for PInvoke import {}", idx, name),
                }
            }
            MemberForwarded::MethodDef(i) => {
                let idx = i - 1;

                match methods.get(idx) {
                    Some(&m) => get_method!(m).pinvoke = value,
                    None => throw!("invalid method index {} for PInvoke import {}", idx, name),
                }
            }
            MemberForwarded::Null => {
                throw!("invalid null member index for PInvoke import {}", name)
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
                    None => throw!("invalid type parent index {} for security declaration {}", t_idx, idx)
                }
            }
            HasDeclSecurity::MethodDef(m) => {
                let m_idx = m - 1;
                match methods.get(m_idx) {
                    Some(&m) => &mut get_method!(m).security,
                    None => throw!("invalid method parent index {} for security declaration {}", m_idx, idx)
                }
            }
            HasDeclSecurity::Assembly(_) => match &mut assembly {
                Some(a) => &mut a.security,
                None => throw!("invalid assembly parent index for security declaration {} when no assembly exists in the current module", idx)
            }
            HasDeclSecurity::Null => throw!("invalid null parent index for security declaration {}", idx)
        };

        *parent = Some(SecurityDeclaration {
            attributes: vec![],
            action: s.action,
            value: heap_idx!(blobs, s.permission_set),
        });
    }

    debug!("generic parameters");

    let mut constraint_map = HashMap::new();

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

    build_vec!(params = (usize, usize)[tables.param.len()], {
        debug!("params");

        for (m_idx, iter) in owned_params {
            for (p_idx, param) in iter {
                use members::*;

                let sequence = param.sequence as usize;

                let param_val = Some(ParameterMetadata {
                    attributes: vec![],
                    name: optional_idx!(strings, param.name),
                    is_in: check_bitmask!(param.flags, 0x1),
                    is_out: check_bitmask!(param.flags, 0x2),
                    optional: check_bitmask!(param.flags, 0x10),
                    default: None,
                    marshal: None,
                });

                let method = get_method!(methods[m_idx]);

                if sequence == 0 {
                    method.return_type_metadata = param_val;
                } else {
                    let len = method.parameter_metadata.len();
                    if len < sequence {
                        method.parameter_metadata.extend(vec![None; sequence - len]);
                    }

                    method.parameter_metadata[sequence - 1] = param_val;
                }

                params[p_idx].write((m_idx, sequence));
            }
        }
    });

    debug!("field marshal");

    for marshal in &tables.field_marshal {
        use crate::binary::{metadata::index::HasFieldMarshal, signature::kinds::MarshalSpec};

        let value = Some(heap_idx!(blobs, marshal.native_type).pread::<MarshalSpec>(0)?);

        match marshal.parent {
            HasFieldMarshal::Field(i) => {
                let idx = i - 1;
                match fields.get(idx) {
                    Some(&field) => get_field!(field).marshal = value,
                    None => throw!("bad field index {} for field marshal", idx),
                }
            }
            HasFieldMarshal::Param(i) => {
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

    build_vec!(properties = (usize, usize)[tables.property.len()], {
        debug!("properties");

        for (map_idx, map) in tables.property_map.iter().enumerate() {
            let type_idx = map.parent.0 - 1;

            let parent_props = match types.get_mut(type_idx) {
                Some(t) => &mut t.properties,
                None => throw!("invalid parent type index {} for property map {}", type_idx, map_idx),
            };

            for (p_idx, prop) in range_index!(
                enumerated (map_idx, map) =>
                range property_list in property_map indexes property
            ) {
                use crate::binary::signature::kinds::PropertySig;
                use members::*;

                let sig = heap_idx!(blobs, prop.property_type).pread::<PropertySig>(0)?;

                parent_props.push(Property {
                    attributes: vec![],
                    name: heap_idx!(strings, prop.name),
                    getter: None,
                    setter: None,
                    other: vec![],
                    static_member: !sig.has_this,
                    property_type: convert::read::parameter(sig.property_type, &ctx)?,
                    parameters: sig
                        .params
                        .into_iter()
                        .map(|p| convert::read::parameter(p, &ctx))
                        .collect::<Result<_>>()?,
                    special_name: check_bitmask!(prop.flags, 0x200),
                    runtime_special_name: check_bitmask!(prop.flags, 0x1000),
                    default: None,
                });
                properties[p_idx].write((type_idx, parent_props.len() - 1));
            }
        }
    });

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
                    Some(&i) => get_field!(i).default = value,
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

    build_vec!(events = (usize, usize)[tables.event.len()], {
        debug!("events");

        for (map_idx, map) in tables.event_map.iter().enumerate() {
            let type_idx = map.parent.0 - 1;

            let parent = types.get_mut(type_idx).ok_or_else(|| {
                scroll::Error::Custom(format!(
                    "invalid parent type index {} for event map {}",
                    type_idx, map_idx
                ))
            })?;

            for (e_idx, event) in range_index!(
                enumerated (map_idx, map) =>
                range event_list in event_map indexes event
            ) {
                use members::*;

                let name = heap_idx!(strings, event.name);

                let internal_idx = parent.events.len();

                macro_rules! get_listener {
                    ($l_name:literal, $flag:literal, $variant:ident) => {{
                        let Some(position) = tables.method_semantics.iter().position(|s| {
                            use metadata::index::HasSemantics;
                            check_bitmask!(s.semantics, $flag)
                                && matches!(s.association, HasSemantics::Event(e) if e_idx == e - 1)
                        }) else { throw!("could not find {} listener for event {}", $l_name, name) };
                        let sem = tables.method_semantics.remove(position);
                        let m_idx = sem.method.0 - 1;
                        if m_idx < tables.method_def.len() {
                            let method = extract_method(parent, methods[m_idx], &mut methods, &tables);
                            methods[m_idx].member = MethodMemberIndex::$variant(internal_idx);
                            method
                        } else {
                            throw!("invalid method index {} in {} index for event {}", m_idx, $l_name, name);
                        }
                    }}
                }

                let add_listener = get_listener!("add", 0x8, EventAdd);
                let remove_listener = get_listener!("remove", 0x10, EventRemove);

                parent.events.push(Event {
                    attributes: vec![],
                    delegate_type: convert::read::type_idx(event.event_type, &ctx)?,
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

    debug!("method semantics");

    // NOTE: seems to be the longest resolution step for large assemblies (i.e. System.Private.CoreLib)
    // may be worth investigating possible speedups

    for s in &tables.method_semantics {
        use metadata::index::HasSemantics;

        let raw_idx = s.method.0 - 1;
        let Some(&method_idx) = methods.get(raw_idx) else { throw!("invalid method index {} for method semantics", raw_idx) };

        let parent = &mut types[method_idx.parent_type.0];

        let new_meth = extract_method(parent, method_idx, &mut methods, &tables);

        let member_idx = &mut methods[raw_idx].member;

        match s.association {
            HasSemantics::Event(i) => {
                let idx = i - 1;
                let &(_, internal_idx) = events.get(idx).ok_or_else(|| {
                    scroll::Error::Custom(format!("invalid event index {} for method semantics", idx))
                })?;
                let event = &mut parent.events[internal_idx];

                if check_bitmask!(s.semantics, 0x20) {
                    event.raise_event = Some(new_meth);
                    *member_idx = MethodMemberIndex::EventRaise(internal_idx);
                } else if check_bitmask!(s.semantics, 0x4) {
                    event.other.push(new_meth);
                    *member_idx = MethodMemberIndex::EventOther {
                        event: internal_idx,
                        other: event.other.len() - 1,
                    };
                }
            }
            HasSemantics::Property(i) => {
                let idx = i - 1;
                let &(_, internal_idx) = properties.get(idx).ok_or_else(|| {
                    scroll::Error::Custom(format!("invalid property index {} for method semantics", idx))
                })?;
                let property = &mut parent.properties[internal_idx];

                if check_bitmask!(s.semantics, 0x1) {
                    property.setter = Some(new_meth);
                    *member_idx = MethodMemberIndex::PropertySetter(internal_idx);
                } else if check_bitmask!(s.semantics, 0x2) {
                    property.getter = Some(new_meth);
                    *member_idx = MethodMemberIndex::PropertyGetter(internal_idx);
                } else if check_bitmask!(s.semantics, 0x4) {
                    property.other.push(new_meth);
                    *member_idx = MethodMemberIndex::PropertyOther {
                        property: internal_idx,
                        other: property.other.len() - 1,
                    };
                }
            }
            HasSemantics::Null => throw!("invalid null index for method semantics",),
        }
    }

    debug!("field refs");

    let (field_refs, field_map): (Vec<_>, HashMap<_, _>) = tables
        .member_ref
        .iter()
        .enumerate()
        .filter_map(|(idx, r)| {
            use crate::binary::signature::kinds::FieldSig;
            use members::*;
            use metadata::index::{MemberRefParent, TypeDefOrRef};

            let name = filter_map_try!(strings.at_index(r.name).map_err(CLI)).into();
            let sig_blob = filter_map_try!(blobs.at_index(r.signature).map_err(CLI));

            // NOTE: discarding errors means wasted allocation of formatted messages
            let field_sig: FieldSig = match sig_blob.pread(0) {
                Ok(s) => s,
                Err(_) => return None,
            };

            let parent = match r.class {
                MemberRefParent::TypeDef(i) => {
                    FieldReferenceParent::Type(filter_map_try!(convert::read::type_idx(TypeDefOrRef::TypeDef(i), &ctx)))
                }
                MemberRefParent::TypeRef(i) => {
                    FieldReferenceParent::Type(filter_map_try!(convert::read::type_idx(TypeDefOrRef::TypeRef(i), &ctx)))
                }
                MemberRefParent::TypeSpec(i) => FieldReferenceParent::Type(filter_map_try!(convert::read::type_idx(
                    TypeDefOrRef::TypeSpec(i),
                    &ctx
                ))),
                MemberRefParent::ModuleRef(i) => {
                    let idx = i - 1;
                    if idx < module_refs.len() {
                        FieldReferenceParent::Module(ModuleRefIndex(idx))
                    } else {
                        return Some(Err(CLI(scroll::Error::Custom(format!(
                            "invalid module reference index {} for field reference {}",
                            idx, name
                        )))));
                    }
                }
                _ => return None,
            };

            Some(Ok((
                idx,
                ExternalFieldReference {
                    attributes: vec![],
                    parent,
                    name,
                    custom_modifiers: filter_map_try!(field_sig
                        .custom_modifiers
                        .into_iter()
                        .map(|c| convert::read::custom_modifier(c, &ctx))
                        .collect::<Result<_>>()),
                    field_type: filter_map_try!(MemberType::from_sig(field_sig.field_type, &ctx)),
                },
            )))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .enumerate()
        .map(|(current_idx, (orig_idx, r))| (r, (orig_idx, current_idx)))
        .unzip();

    debug!("method refs");

    let (method_refs, method_map): (Vec<_>, HashMap<_, _>) = tables
        .member_ref
        .iter()
        .enumerate()
        .filter_map(|(idx, r)| {
            use crate::binary::signature::kinds::{CallingConvention, MethodRefSig};
            use members::*;
            use metadata::index::{MemberRefParent, TypeDefOrRef};

            let name = filter_map_try!(strings.at_index(r.name).map_err(CLI)).into();
            let sig_blob = filter_map_try!(blobs.at_index(r.signature).map_err(CLI));

            let ref_sig: MethodRefSig = match sig_blob.pread(0) {
                Ok(s) => s,
                Err(_) => return None,
            };

            let mut signature = filter_map_try!(convert::read::managed_method(ref_sig.method_def, &ctx));
            if signature.calling_convention == CallingConvention::Vararg {
                signature.varargs = Some(filter_map_try!(ref_sig
                    .varargs
                    .into_iter()
                    .map(|p| convert::read::parameter(p, &ctx))
                    .collect::<Result<_>>()));
            }

            let parent =
                match r.class {
                    MemberRefParent::TypeDef(i) => MethodReferenceParent::Type(filter_map_try!(
                        convert::read::type_idx(TypeDefOrRef::TypeDef(i), &ctx)
                    )),
                    MemberRefParent::TypeRef(i) => MethodReferenceParent::Type(filter_map_try!(
                        convert::read::type_idx(TypeDefOrRef::TypeRef(i), &ctx)
                    )),
                    MemberRefParent::TypeSpec(i) => MethodReferenceParent::Type(filter_map_try!(
                        convert::read::type_idx(TypeDefOrRef::TypeSpec(i), &ctx)
                    )),
                    MemberRefParent::ModuleRef(i) => {
                        let idx = i - 1;
                        if idx < module_refs.len() {
                            MethodReferenceParent::Module(ModuleRefIndex(idx))
                        } else {
                            return Some(Err(CLI(scroll::Error::Custom(format!(
                                "invalid module reference index {} for method reference {}",
                                idx, name
                            )))));
                        }
                    }
                    MemberRefParent::MethodDef(i) => {
                        let idx = i - 1;
                        match methods.get(idx) {
                            Some(&m) => MethodReferenceParent::VarargMethod(m),
                            None => {
                                return Some(Err(CLI(scroll::Error::Custom(format!(
                                    "bad method def index {} for method reference {}",
                                    idx, name
                                )))))
                            }
                        }
                    }
                    MemberRefParent::Null => {
                        return Some(Err(CLI(scroll::Error::Custom(format!(
                            "invalid null parent index for method reference {}",
                            name
                        )))))
                    }
                };

            Some(Ok((
                idx,
                ExternalMethodReference {
                    attributes: vec![],
                    parent,
                    name,
                    signature,
                },
            )))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .enumerate()
        .map(|(current_idx, (orig_idx, r))| (r, (orig_idx, current_idx)))
        .unzip();

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
    };

    debug!("custom attributes");

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
                    None => throw!(
                            "invalid method index {} for parent of custom attribute {}",
                            m_idx,
                            idx
                        ),
                }
            }
            Field(i) => {
                let f_idx = i - 1;
                match fields.get(f_idx) {
                    Some(&i) => res[i].attributes
                        .push(attr),
                    None => throw!(
                            "invalid field index {} for parent of custom attribute {}",
                            f_idx,
                            idx
                        ),
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

                        param_meta
                            .as_mut()
                            .unwrap()
                            .attributes
                            .push(attr);
                    },
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
                        )
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
                        HasDeclSecurity::TypeDef(t) => res.type_definitions[t - 1].security.as_mut().unwrap().attributes.push(attr),
                        HasDeclSecurity::MethodDef(m) => res[methods[m - 1]].security.as_mut().unwrap().attributes.push(attr),
                        HasDeclSecurity::Assembly(_) => res.assembly.as_mut().and_then(|a| a.security.as_mut()).unwrap().attributes.push(attr),
                        HasDeclSecurity::Null => unreachable!()
                    },
                    None => throw!(
                            "invalid security declaration index {} for parent of custom attribute {}",
                            s_idx,
                            idx
                        )
                }
            }
            Property(i) => {
                let p_idx = i - 1;

                match properties.get(p_idx) {
                    Some(&(parent, internal)) => res.type_definitions[parent].properties
                        [internal]
                        .attributes
                        .push(attr),
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
                    Some(&(parent, internal)) => res.type_definitions[parent].events[internal]
                        .attributes
                        .push(attr),
                    None => throw!(
                            "invalid event index {} for parent of custom attribute {}",
                            e_idx,
                            idx
                        ),
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
            Assembly(_) => {
                match res.assembly.as_mut() {
                    Some(a) => a.attributes.push(attr),
                    None => throw!(
                            "custom attribute {} has the module assembly as a parent, but this module does not have an assembly",
                            idx
                        )
                }
            }
            AssemblyRef(i) => {
                let r_idx = i - 1;

                match res.assembly_references.get_mut(r_idx) {
                    Some(a) => a.attributes.push(attr),
                    None => throw!(
                            "invalid assembly reference index {} for parent of custom attribute {}",
                            r_idx,
                            idx
                        )
                }
            }
            File(i) => {
                let f_idx = i - 1;

                match res.files.get_mut(f_idx) {
                    Some(f) => f.attributes.push(attr),
                    None => throw!(
                            "invalid file index {} for parent of custom attribute {}",
                            f_idx,
                            idx
                        )
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
                        )
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
                        )
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
                        )
                }
            }
            GenericParamConstraint(i) => {
                let g_idx = i - 1;

                match constraint_map.get(&g_idx) {
                    Some(&(generic, internal)) => do_at_generic!(
                            tables.generic_param[generic],
                            |g| g.type_constraints[internal].attributes.push(attr)
                        ),
                    None => throw!(
                            "invalid generic constraint index {} for parent of custom attribute {}",
                            g_idx,
                            idx
                        )
                }
            }
            MethodSpec(_) => {
                warn!("custom attribute {} has a MethodSpec parent, this is not supported by dotnetdll", idx);
            }
            StandAloneSig(_) => {
                warn!("custom attribute {} has a StandAloneSig parent, this is not supported by dotnetdll", idx);
            }
            TypeSpec(_) => {
                warn!("custom attribute {} has a TypeSpec parent, this is not supported by dotnetdll", idx);
            }
            Null => throw!("invalid null index for parent of custom attribute {}", idx)
        }
    }

    if !opts.skip_method_bodies {
        debug!("method bodies");

        for (idx, m) in tables.method_def.iter().enumerate() {
            use crate::binary::signature::kinds::{LocalVar, LocalVarSig};
            use body::*;
            use types::LocalVariable;

            if m.rva == 0 {
                continue;
            }

            let name = &res[methods[idx]].name;

            let raw_body = dll.get_method(m)?;

            let header = match raw_body.header {
                method::Header::Tiny { .. } => Header {
                    initialize_locals: false,
                    maximum_stack_size: 8, // ECMA-335, II.25.4.2 (page 285)
                    local_variables: vec![],
                },
                method::Header::Fat {
                    init_locals,
                    max_stack,
                    local_var_sig_tok,
                    ..
                } => {
                    let local_variables = if local_var_sig_tok == 0 {
                        vec![]
                    } else {
                        let tok: Token = local_var_sig_tok.to_le_bytes().pread(0)?;
                        if matches!(tok.target, TokenTarget::Table(Kind::StandAloneSig))
                            && tok.index <= tables.stand_alone_sig.len()
                        {
                            let vars: LocalVarSig =
                                heap_idx!(blobs, tables.stand_alone_sig[tok.index - 1].signature).pread(0)?;

                            vars.0
                                .into_iter()
                                .map(|v| {
                                    Ok(match v {
                                        LocalVar::TypedByRef => LocalVariable::TypedReference,
                                        LocalVar::Variable {
                                            custom_modifiers,
                                            pinned,
                                            by_ref,
                                            var_type,
                                        } => LocalVariable::Variable {
                                            custom_modifiers: custom_modifiers
                                                .into_iter()
                                                .map(|c| convert::read::custom_modifier(c, &ctx))
                                                .collect::<Result<_>>()?,
                                            pinned,
                                            by_ref,
                                            var_type: MethodType::from_sig(var_type, &ctx)?,
                                        },
                                    })
                                })
                                .collect::<Result<Vec<_>>>()?
                        } else {
                            throw!("invalid local variable signature token {:?} for method {}", tok, name);
                        }
                    };
                    Header {
                        initialize_locals: init_locals,
                        maximum_stack_size: max_stack as usize,
                        local_variables,
                    }
                }
            };

            let raw_instrs = raw_body.body;

            let mut init_offset = 0;
            let instr_offsets: Vec<_> = raw_instrs
                .iter()
                .map(|i| {
                    let offset = init_offset;
                    init_offset += i.bytesize();
                    offset
                })
                .collect();

            let data_sections = raw_body
                .data_sections
                .into_iter()
                .map(|d| {
                    use crate::binary::method::SectionKind;
                    Ok(match d.section {
                        SectionKind::Exceptions(e) => DataSection::ExceptionHandlers(
                            e.into_iter()
                                .map(|h| {
                                    macro_rules! get_offset {
                                        ($byte:expr, $name:literal) => {{
                                            let max = instr_offsets.iter().max().unwrap();

                                            if $byte as usize == max + 1 {
                                                instr_offsets.len()
                                            } else {
                                                instr_offsets
                                                    .iter()
                                                    .position(|&i| i == $byte as usize)
                                                    .ok_or_else(|| {
                                                        scroll::Error::Custom(format!(
                                                            "could not find corresponding instruction for {} offset {}",
                                                            $name, $byte
                                                        ))
                                                    })?
                                            }
                                        }};
                                    }

                                    let kind = match h.flags {
                                        0 => ExceptionKind::TypedException(convert::read::type_token(
                                            h.class_token_or_filter.to_le_bytes().pread::<Token>(0)?,
                                            &ctx,
                                        )?),
                                        1 => ExceptionKind::Filter {
                                            offset: get_offset!(h.class_token_or_filter, "filter"),
                                        },
                                        2 => ExceptionKind::Finally,
                                        4 => ExceptionKind::Fault,
                                        bad => throw!("invalid exception clause type {:#06x}", bad),
                                    };

                                    let try_offset = get_offset!(h.try_offset, "try");
                                    let handler_offset = get_offset!(h.handler_offset, "handler");

                                    Ok(Exception {
                                        kind,
                                        try_offset,
                                        try_length: get_offset!(h.try_offset + h.try_length, "try") - try_offset,
                                        handler_offset,
                                        handler_length: get_offset!(h.handler_offset + h.handler_length, "handler")
                                            - handler_offset,
                                    })
                                })
                                .collect::<Result<_>>()?,
                        ),
                        SectionKind::Unrecognized { is_fat, length } => DataSection::Unrecognized {
                            fat: is_fat,
                            size: length,
                        },
                    })
                })
                .collect::<Result<_>>()?;

            let instrs = raw_instrs
                .into_iter()
                .enumerate()
                .map(|(idx, i)| convert::read::instruction(i, idx, &instr_offsets, &ctx, &m_ctx))
                .collect::<Result<_>>()?;

            res[methods[idx]].body = Some(Method {
                header,
                instructions: instrs,
                data_sections,
            });
        }
    }

    debug!("resolved module {}", res.module.name);

    Ok(res)
}
