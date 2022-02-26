use super::{
    binary::{
        cli::{Header, Metadata, RVASize},
        heap::*,
        metadata, method, stream,
    },
    convert,
    resolution::*,
    resolved,
};
use dotnetdll_macros::From;
use log::{debug, warn};
use object::{
    endian::{LittleEndian, U32Bytes},
    pe::{self, ImageDataDirectory},
    read::{
        pe::{PeFile32, PeFile64, SectionTable},
        Error as ObjectReadError, FileKind,
    },
    write::Error as ObjectWriteError,
};
use scroll::{Error as ScrollError, Pread, Pwrite};
use scroll_buffer::DynamicBuffer;
use std::collections::HashMap;
use DLLError::*;

#[derive(Debug)]
pub struct DLL<'a> {
    buffer: &'a [u8],
    pub cli: Header,
    sections: SectionTable<'a>,
}

#[derive(Debug, From)]
pub enum DLLError {
    PERead(ObjectReadError),
    PEWrite(ObjectWriteError),
    CLI(ScrollError),
    Other(&'static str),
}
impl std::fmt::Display for DLLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PERead(o) => write!(f, "PE parsing: {}", o),
            PEWrite(o) => write!(f, "PE writing: {}", o),
            CLI(s) => write!(f, "CLI parsing: {}", s),
            Other(s) => write!(f, "Other parsing: {}", s),
        }
    }
}
impl std::error::Error for DLLError {}

pub type Result<T> = std::result::Result<T, DLLError>;

#[derive(Debug, Default, Copy, Clone)]
pub struct ResolveOptions {
    pub skip_method_bodies: bool,
}

impl<'a> DLL<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<DLL<'a>> {
        let (sections, dir) = match FileKind::parse(bytes)? {
            FileKind::Pe32 => {
                let file = PeFile32::parse(bytes)?;
                (
                    file.section_table(),
                    file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
                )
            }
            FileKind::Pe64 => {
                let file = PeFile64::parse(bytes)?;
                (
                    file.section_table(),
                    file.data_directory(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
                )
            }
            _ => return Err(Other("invalid object type, must be PE32 or PE64")),
        };

        let cli_b = dir
            .ok_or(Other("missing CLI metadata data directory in PE image"))?
            .data(bytes, &sections)?;
        Ok(DLL {
            buffer: bytes,
            cli: cli_b.pread_with(0, scroll::LE)?,
            sections,
        })
    }

    pub fn at_rva(&self, rva: &RVASize) -> Result<&'a [u8]> {
        let dir = ImageDataDirectory {
            virtual_address: U32Bytes::new(LittleEndian, rva.rva),
            size: U32Bytes::new(LittleEndian, rva.size),
        };
        dir.data(self.buffer, &self.sections).map_err(PERead)
    }

    fn raw_rva(&self, rva: u32) -> Result<&'a [u8]> {
        self.sections
            .pe_data_at(self.buffer, rva)
            .ok_or(Other("bad stream offset"))
    }

    fn get_stream(&self, name: &'static str) -> Result<Option<&'a [u8]>> {
        let meta = self.get_cli_metadata()?;
        let header = match meta.stream_headers.iter().find(|h| h.name == name) {
            Some(h) => h,
            None => return Ok(None),
        };
        let data = self.raw_rva(self.cli.metadata.rva + header.offset)?;
        Ok(Some(&data[..header.size as usize]))
    }

    pub fn get_heap<T: HeapReader<'a>>(&self) -> Result<T> {
        // heap names from the traits are known to be good
        // so if we can't find them, assume they are empty
        Ok(T::new(self.get_stream(T::NAME)?.unwrap_or(&[])))
    }

    pub fn get_cli_metadata(&self) -> Result<Metadata<'a>> {
        self.at_rva(&self.cli.metadata)?.pread(0).map_err(CLI)
    }

    pub fn get_logical_metadata(&self) -> Result<metadata::header::Header> {
        self.get_stream("#~")?
            .ok_or(Other("unable to find metadata stream"))?
            .pread(0)
            .map_err(CLI)
    }

    #[allow(clippy::nonminimal_bool)]
    pub fn get_method(&self, def: &metadata::table::MethodDef) -> Result<method::Method> {
        let bytes = self.raw_rva(def.rva)?;
        let mut offset = 0;
        // if we don't see a method header at the beginning, we need to align
        if !check_bitmask!(bytes[0], 0x2) {
            offset = 4 - (def.rva as usize % 4);
        }
        bytes.pread(offset).map_err(CLI)
    }

    #[allow(clippy::nonminimal_bool, unused_mut)]
    pub fn resolve(&self, opts: ResolveOptions) -> Result<Resolution<'a>> {
        use convert::TypeKind;
        use resolved::{
            types::{MemberType, MethodType},
            *,
        };

        let strings: StringsReader = self.get_heap()?;
        let blobs: BlobReader = self.get_heap()?;
        let guids: GUIDReader = self.get_heap()?;
        let userstrings: UserStringReader = self.get_heap()?;
        let mut tables = self.get_logical_metadata()?.tables;

        let types_len = tables.type_def.len();
        let type_ref_len = tables.type_ref.len();

        let ctx = convert::read::Context {
            def_len: types_len,
            ref_len: type_ref_len,
            specs: &tables.type_spec,
            sigs: &tables.stand_alone_sig,
            blobs: &blobs,
            userstrings: &userstrings,
        };

        macro_rules! throw {
            ($($arg:tt)*) => {
                return Err(CLI(scroll::Error::Custom(format!($($arg)*))))
            }
        }

        macro_rules! heap_idx {
            ($heap:ident, $idx:expr) => {
                $heap.at_index($idx)?
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

        macro_rules! range_index {
            (enumerated $enum:expr => range $field:ident in $table:ident, indexes $index_table:ident with len $len:ident) => {{
                let (idx, var) = $enum;
                let range = (var.$field.0 - 1)..(match tables.$table.get(idx + 1) {
                    Some(r) => r.$field.0,
                    None => $len + 1,
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
                    if enclose_idx < types_len {
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

        let fields_len = tables.field.len();
        let method_len = tables.method_def.len();

        let owned_fields = tables
            .type_def
            .iter()
            .enumerate()
            .map(|e| Ok(range_index!(enumerated e => range field_list in type_def, indexes field with len fields_len)))
            .collect::<Result<Vec<_>>>()?;

        let owned_methods = tables
            .type_def
            .iter()
            .enumerate()
            .map(|e| {
                Ok(range_index!(enumerated e => range method_list in type_def, indexes method_def with len method_len))
            })
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

                let offset = r.offset as usize;

                Ok(ManifestResource {
                    attributes: vec![],
                    name,
                    visibility: match r.flags & 0x7 {
                        0x1 => Visibility::Public,
                        0x2 => Visibility::Private,
                        bad => throw!(
                            "invalid visibility {:#03x} for manifest resource {}",
                            bad,
                            name
                        ),
                    },
                    implementation: match r.implementation {
                        BinImpl::File(f) => {
                            let idx = f - 1;
                            if idx < files.len() {
                                Implementation::File { location: FileIndex(idx), offset }
                            } else {
                                throw!(
                                    "invalid file index {} for manifest resource {}",
                                    idx,
                                    name
                                )
                            }
                        }
                        BinImpl::AssemblyRef(a) => {
                            let idx = a - 1;

                            if idx < assembly_refs.len() {
                                Implementation::Assembly { location: AssemblyRefIndex(idx), offset }
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
                        BinImpl::Null => Implementation::CurrentFile(self.at_rva(&self.cli.resources)?[offset..].into())
                    },
                })
            })
            .collect::<Result<_>>()?;

        let export_len = tables.exported_type.len();
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
                    name,
                    namespace: optional_idx!(strings, e.type_namespace),
                    implementation: match e.implementation {
                        Implementation::File(f) => {
                            let idx = f - 1;
                            let t_idx = e.type_def_id as usize;

                            if idx < files.len() {
                                TypeImplementation::ModuleFile {
                                    type_def: if t_idx < types_len {
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
                            if idx < export_len {
                                TypeImplementation::Nested(ExportedTypeIndex(idx))
                            } else {
                                throw!("invalid nested type index {} in exported type {}", idx, name);
                            }
                        }
                        Implementation::Null => throw!("invalid null implementation index for exported type {}", name),
                    },
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
            mvid: heap_idx!(guids, module_row.mvid),
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

                Ok(types::ExternalTypeReference {
                    attributes: vec![],
                    name,
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
                            if idx < type_ref_len {
                                ResolutionScope::Nested(TypeRefIndex(idx))
                            } else {
                                throw!("invalid nested type index {} for type reference {}", idx, name);
                            }
                        }
                        BinRS::Null => ResolutionScope::Exported,
                    },
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
            use resolved::Accessibility::*;

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

        // this allows us to initialize the Vec out of order
        // we consider it safe because we guarantee that the body will fully initialize everything
        // it's much simpler and more efficient than trying to use a HashMap or something
        macro_rules! build_vec {
            ($name:ident = $t:ty[$len:ident], $body:expr) => {
                let mut $name = vec![std::mem::MaybeUninit::uninit(); $len];
                $body;
                let mut $name: Vec<$t> = unsafe { std::mem::transmute($name) };
            };
        }

        build_vec!(fields = FieldIndex[fields_len], {
            debug!("fields");

            for (type_idx, type_fields) in owned_fields.into_iter().enumerate() {
                use super::binary::signature::kinds::FieldSig;
                use members::*;

                let parent_fields = &mut types[type_idx].fields;
                parent_fields.reserve(type_fields.len());

                for (f_idx, f) in type_fields {
                    let FieldSig(cmod, t) = heap_idx!(blobs, f.signature).pread(0)?;

                    parent_fields.push(Field {
                        attributes: vec![],
                        name: heap_idx!(strings, f.name),
                        type_modifiers: cmod
                            .into_iter()
                            .map(|c| convert::read::custom_modifier(c, &ctx))
                            .collect::<Result<_>>()?,
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
                    get_field!(field).initial_value = Some(self.raw_rva(rva.rva)?);
                }
                None => throw!("bad parent field index {} for field RVA specification", idx),
            }
        }

        let params_len = tables.param.len();

        let mut owned_params = Vec::with_capacity(params_len);

        build_vec!(methods = MethodIndex[method_len], {
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
                        name: name.into(),
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
                            enumerated (m_idx, m) => range param_list in method_def,
                            indexes param with len params_len
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
                import_name: name,
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
                value: heap_idx!(blobs, s.permission_set).into(),
            });
        }

        debug!("generic parameters");

        let mut constraint_map = HashMap::new();

        // this table is supposed to be sorted by owner and number (ECMA-335, II.22, page 210)
        // thus no need to sort the generics by sequence after the fact
        for (idx, p) in tables.generic_param.iter().enumerate() {
            use generic::*;
            use metadata::index::TypeOrMethodDef;

            let name = heap_idx!(strings, p.name);

            macro_rules! make_generic {
                () => {
                    Generic {
                        attributes: vec![],
                        name,
                        variance: match p.flags & 0x3 {
                            0x0 => Variance::Invariant,
                            0x1 => Variance::Covariant,
                            0x2 => Variance::Invariant,
                            _ => {
                                throw!("invalid variance value 0x3 for generic parameter {}", name)
                            }
                        },
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
                                if c.owner.0 - 1 == idx {
                                    let (cmod, ty) = filter_map_try!(convert::read::idx_with_mod(c.constraint, &ctx));
                                    Some(Ok((
                                        c_idx,
                                        GenericConstraint {
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
                                constraint_map.insert(original, (idx, internal));
                                c
                            })
                            .collect(),
                    }
                };
            }

            match p.owner {
                TypeOrMethodDef::TypeDef(i) => {
                    let idx = i - 1;
                    match types.get_mut(idx) {
                        Some(t) => t.generic_parameters.push(make_generic!()),
                        None => throw!("invalid type index {} for generic parameter {}", idx, name),
                    }
                }
                TypeOrMethodDef::MethodDef(i) => {
                    let idx = i - 1;
                    let method = match methods.get(idx) {
                        Some(&m) => get_method!(m),
                        None => throw!("invalid method index {} for generic parameter {}", idx, name),
                    };

                    method.generic_parameters.push(make_generic!());
                }
                TypeOrMethodDef::Null => {
                    throw!("invalid null owner index for generic parameter {}", name)
                }
            }
        }

        build_vec!(params = (usize, usize)[params_len], {
            debug!("params");

            for (m_idx, iter) in owned_params {
                for (p_idx, param) in iter {
                    use members::*;

                    let sequence = param.sequence as usize;

                    let param_val = Some(ParameterMetadata {
                        attributes: vec![],
                        name: heap_idx!(strings, param.name),
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

        for marshal in tables.field_marshal {
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

        let prop_len = tables.property.len();

        build_vec!(properties = (usize, usize)[prop_len], {
            debug!("properties");

            for (map_idx, map) in tables.property_map.iter().enumerate() {
                let type_idx = map.parent.0 - 1;

                let parent_props = match types.get_mut(type_idx) {
                    Some(t) => &mut t.properties,
                    None => throw!("invalid parent type index {} for property map {}", type_idx, map_idx),
                };

                for (p_idx, prop) in range_index!(
                    enumerated (map_idx, map) => range property_list in property_map,
                    indexes property with len prop_len
                ) {
                    use super::binary::signature::kinds::PropertySig;
                    use members::*;

                    let sig = heap_idx!(blobs, prop.property_type).pread::<PropertySig>(0)?;

                    parent_props.push(Property {
                        attributes: vec![],
                        name: heap_idx!(strings, prop.name),
                        getter: None,
                        setter: None,
                        other: vec![],
                        property_type: convert::read::parameter(sig.property_type, &ctx)?,
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

        // since we're dealing with raw indices and not references, we have to think about what the other indices are pointing to
        // if we remove an element, all the indices above it need to be adjusted accordingly for future iterations
        macro_rules! extract_method {
            ($parent:ident, $idx:expr) => {{
                let idx = $idx;
                let internal_idx = match idx.member {
                    MethodMemberIndex::Method(i) => i,
                    _ => unreachable!(),
                };
                // NOTE: this is super inefficient, does a linear search every single time
                for m in methods.iter_mut() {
                    if m.parent_type == idx.parent_type {
                        match &mut m.member {
                            MethodMemberIndex::Method(i_idx) if *i_idx > internal_idx => {
                                *i_idx -= 1;
                            }
                            _ => {}
                        }
                    }
                }
                $parent.methods.remove(internal_idx)
            }};
        }

        let event_len = tables.event.len();

        build_vec!(events = (usize, usize)[event_len], {
            debug!("events");

            for (map_idx, map) in tables.event_map.iter().enumerate() {
                let type_idx = map.parent.0 - 1;

                let parent = types.get_mut(type_idx).ok_or_else(|| {
                    scroll::Error::Custom(format!(
                        "invalid parent type index {} for event map {}",
                        type_idx, map_idx
                    ))
                })?;
                let parent_events = &mut parent.events;

                for (e_idx, event) in range_index!(
                    enumerated (map_idx, map) => range event_list in event_map,
                    indexes event with len event_len
                ) {
                    use members::*;

                    let name = heap_idx!(strings, event.name);

                    let internal_idx = parent_events.len();

                    macro_rules! get_listener {
                        ($l_name:literal, $flag:literal, $variant:ident) => {{
                            let sem = tables.method_semantics.remove(tables.method_semantics.iter().position(|s| {
                                use metadata::index::HasSemantics;
                                check_bitmask!(s.semantics, $flag)
                                    && matches!(s.association, HasSemantics::Event(e) if e_idx == e - 1)
                            }).ok_or(scroll::Error::Custom(format!("could not find {} listener for event {}", $l_name, name)))?);
                            let m_idx = sem.method.0 - 1;
                            if m_idx < method_len {
                                let method = extract_method!(parent, methods[m_idx]);
                                methods[m_idx].member = MethodMemberIndex::$variant(internal_idx);
                                method
                            } else {
                                throw!("invalid method index {} in {} index for event {}", m_idx, $l_name, name);
                            }
                        }}
                    }

                    parent_events.push(Event {
                        attributes: vec![],
                        name,
                        delegate_type: convert::read::type_idx(event.event_type, &ctx)?,
                        add_listener: get_listener!("add", 0x8, EventAdd),
                        remove_listener: get_listener!("remove", 0x10, EventRemove),
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
            let method_idx = match methods.get(raw_idx) {
                Some(&m) => m,
                None => throw!("invalid method index {} for method semantics", raw_idx),
            };

            let parent = &mut types[method_idx.parent_type.0];

            let new_meth = extract_method!(parent, method_idx);

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

                let name = filter_map_try!(strings.at_index(r.name).map_err(CLI));
                let sig_blob = filter_map_try!(blobs.at_index(r.signature).map_err(CLI));

                // NOTE: discarding errors means wasted allocation of formatted messages
                let field_sig: FieldSig = match sig_blob.pread(0) {
                    Ok(s) => s,
                    Err(_) => return None,
                };

                let parent = match r.class {
                    MemberRefParent::TypeDef(i) => FieldReferenceParent::Type(filter_map_try!(
                        convert::read::type_idx(TypeDefOrRef::TypeDef(i), &ctx)
                    )),
                    MemberRefParent::TypeRef(i) => FieldReferenceParent::Type(filter_map_try!(
                        convert::read::type_idx(TypeDefOrRef::TypeRef(i), &ctx)
                    )),
                    MemberRefParent::TypeSpec(i) => FieldReferenceParent::Type(filter_map_try!(
                        convert::read::type_idx(TypeDefOrRef::TypeSpec(i), &ctx)
                    )),
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
                            .0
                            .into_iter()
                            .map(|c| convert::read::custom_modifier(c, &ctx))
                            .collect::<Result<_>>()),
                        return_type: filter_map_try!(MemberType::from_sig(field_sig.1, &ctx)),
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

                let name = filter_map_try!(strings.at_index(r.name).map_err(CLI));
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

                let parent = match r.class {
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

        let entry_token = self.cli.entry_point_token.to_le_bytes().pread::<Token>(0)?;

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
                value: optional_idx!(blobs, a.value).map(|v| v.into()),
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
                                .push(attr)
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

        let sig_len = tables.stand_alone_sig.len();

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

                let raw_body = self.get_method(m)?;

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
                            if matches!(tok.target, TokenTarget::Table(Kind::StandAloneSig)) && tok.index <= sig_len {
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
                                                    .ok_or_else(|| scroll::Error::Custom(
                                                        format!(
                                                            "could not find corresponding instruction for {} offset {}",
                                                            $name,
                                                            $byte
                                                        )
                                                    ))?
                                            }
                                        }}
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

    pub fn write(res: &Resolution, is_32_bit: bool, is_executable: bool) -> Result<Vec<u8>> {
        use metadata::{header, index, table::*};
        use object::write::pe::*;
        use resolved::{
            assembly::HashAlgorithm,
            attribute::Attribute,
            body,
            generic::Variance,
            members::{
                BodyFormat, BodyManagement, CharacterSet, Constant as ConstantValue, FieldReferenceParent, FieldSource,
                MethodReferenceParent, UnmanagedCallingConvention, UserMethod, VtableLayout,
            },
            resource::{Implementation, Visibility},
            types::{Layout, ResolutionScope, TypeImplementation},
        };

        // writer setup
        let mut buffer = vec![];
        let mut writer = Writer::new(!is_32_bit, 0x200, 0x200, &mut buffer);

        let mut num_sections = 1; // .text
        if is_executable {
            // add .idata and .reloc
            num_sections += 2;
        }

        // begin reservations

        writer.reserve_dos_header_and_stub();
        writer.reserve_nt_headers(pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        writer.reserve_section_headers(num_sections);

        let mut text = vec![];

        let imports = if is_executable {
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
            if is_32_bit {
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
                $heap.write($val)?
            };
        }

        macro_rules! opt_heap {
            ($heap:ident, $val:expr) => {
                match $val {
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

            write_attrs!(r.attributes, ManifestResource(idx + 1))
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
            let simple_idx = idx.into();

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
                    Some(t) => convert::write::source_index(t, build_ctx!())?,
                    None => metadata::index::TypeDefOrRef::Null,
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
                    class: idx.into(),
                    interface: convert::write::source_index(i, build_ctx!())?,
                });
                write_attrs!(attrs, InterfaceImpl(impl_idx));
            }

            write_attrs!(t.attributes, TypeDef(idx));
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
                                heap_idx!(blobs, &$v.to_le_bytes())
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

                if let Some(v) = f.initial_value {
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
                    property_type: convert::write::parameter(&p.property_type, build_ctx!())?,
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
                    signature: convert::write::method_def(&m.signature, build_ctx!())?,
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
                            name: heap_idx!(strings, p.name),
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
            let offsets: Vec<_> = instructions
                .iter()
                .scan(0, |state, i| {
                    let my_offset = *state;
                    *state += i.bytesize();
                    Some(my_offset)
                })
                .collect();

            use crate::binary::il::Instruction;

            // now that we have final bytesizes, we can fix offsets
            for (i, &current_off) in instructions.iter_mut().zip(offsets.iter()) {
                use Instruction::*;

                let bytesize = i.bytesize();
                let convert_offset = |o: &mut i32, can_shorten: bool| {
                    let base = current_off + bytesize;
                    let target = offsets[*o as usize];
                    *o = (target as i32) - (base as i32);
                    if can_shorten && i8::try_from(*o).is_ok() {
                        // this instruction will become 3 bytes shorter, need to adjust offset for change in bytesize
                        *o += 3;
                    }
                };

                match i {
                    Beq(o) | Bge(o) | BgeUn(o) | Bgt(o) | BgtUn(o) | Ble(o) | BleUn(o) | Blt(o) | BltUn(o)
                    | BneUn(o) | Br(o) | Brfalse(o) | Brtrue(o) | Leave(o) => convert_offset(o, true),
                    Switch(os) => os.iter_mut().for_each(|o| convert_offset(o, false)),
                    _ => continue,
                }

                use paste::paste;

                macro_rules! make_short {
                    ($($ins:ident),+) => {
                        match i {
                            $(
                                $ins(o) => match i8::try_from(*o) {
                                    Ok(s) => {
                                        paste! {
                                            *i = [<$ins S>](s);
                                        }
                                    },
                                    _ => {}
                                }
                            )+
                            _ => {}
                        }
                    }
                }

                make_short!(Beq, Bge, BgeUn, Bgt, BgtUn, Ble, BleUn, Blt, BltUn, BneUn, Br, Brfalse, Brtrue, Leave);
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
                                        Filter { offset } => *offset as u32,
                                        _ => 0,
                                    };

                                    let convert_pair = |off: usize, len: usize| {
                                        (
                                            offsets[off] as u32,
                                            instructions[off..=off + len].iter().map(|i| i.bytesize() as u32).sum(),
                                        )
                                    };

                                    let (try_offset, try_length) = convert_pair(e.try_offset, e.try_length);
                                    let (handler_offset, handler_length) =
                                        convert_pair(e.handler_offset, e.handler_length);

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
                                target: index::TokenTarget::Table(metadata::table::Kind::StandAloneSig),
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
                let rem = text.len() % 4;
                if rem != 0 {
                    text.extend(vec![0; 4 - rem])
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

        if is_executable {
            writer.add_reloc(
                text_range.virtual_address,
                if is_32_bit {
                    pe::IMAGE_REL_BASED_HIGHLOW
                } else {
                    pe::IMAGE_REL_BASED_DIR64
                },
            );
            writer.reserve_reloc_section();
        }

        // begin writing

        writer.write_dos_header_and_stub()?;
        writer.write_nt_headers(NtHeaders {
            machine: if is_32_bit {
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
                if !is_executable {
                    flags |= pe::IMAGE_FILE_DLL;
                }
                flags
            },
            major_linker_version: 6,
            minor_linker_version: 0,
            address_of_entry_point: if is_executable { text_range.virtual_address } else { 0 },
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
}
