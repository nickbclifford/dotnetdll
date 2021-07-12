use super::{
    binary::{
        cli::{Header, Metadata, RVASize},
        heap::*,
        metadata, method,
    },
    convert,
    resolution::*,
    resolved,
};
use object::{
    endian::{LittleEndian, U32Bytes},
    pe::{ImageDataDirectory, ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64},
    read::{
        pe::{ImageNtHeaders, SectionTable},
        Error as ObjectError,
    },
};
use scroll::{Error as ScrollError, Pread};
use std::{collections::HashMap, rc::Rc};
use DLLError::*;

#[derive(Debug)]
pub struct DLL<'a> {
    buffer: &'a [u8],
    pub cli: Header,
    sections: SectionTable<'a>,
}

#[derive(Debug)]
pub enum DLLError {
    PE(ObjectError),
    CLI(ScrollError),
    Other(&'static str),
}
impl std::fmt::Display for DLLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PE(o) => write!(f, "PE parsing: {}", o),
            CLI(s) => write!(f, "CLI parsing: {}", s),
            Other(s) => write!(f, "Other parsing: {}", s),
        }
    }
}
impl std::error::Error for DLLError {}

// allows for clean usage with ? operator
impl From<ObjectError> for DLLError {
    fn from(e: ObjectError) -> Self {
        PE(e)
    }
}
impl From<ScrollError> for DLLError {
    fn from(e: ScrollError) -> Self {
        CLI(e)
    }
}

pub type Result<T> = std::result::Result<T, DLLError>;

impl<'a> DLL<'a> {
    pub fn parse(bytes: &[u8]) -> Result<DLL> {
        let dos = ImageDosHeader::parse(bytes)?;
        let dirs: &[ImageDataDirectory];
        let sections: SectionTable;

        // PE vs PE32+ format detection
        let original_offset = dos.nt_headers_offset() as u64;
        let mut offset = original_offset;
        match ImageNtHeaders32::parse(bytes, &mut offset) {
            Ok((nt, dirs32)) => {
                sections = nt.sections(bytes, offset)?;
                dirs = dirs32;
            }
            Err(_) => {
                offset = original_offset;

                let (nt, dirs64) = ImageNtHeaders64::parse(bytes, &mut offset)?;

                sections = nt.sections(bytes, offset)?;
                dirs = dirs64;
            }
        }
        let cli_b = dirs
            .get(14)
            .ok_or(Other("missing CLI metadata data directory in PE image"))?
            .data(bytes, &sections)?;
        Ok(DLL {
            buffer: bytes,
            cli: cli_b.pread_with(0, scroll::LE)?,
            sections,
        })
    }

    pub fn at_rva(&self, rva: &RVASize) -> Result<&[u8]> {
        let dir = ImageDataDirectory {
            virtual_address: U32Bytes::new(LittleEndian, rva.rva),
            size: U32Bytes::new(LittleEndian, rva.size),
        };
        dir.data(self.buffer, &self.sections).map_err(PE)
    }

    fn raw_rva(&self, rva: u32) -> Result<&'a [u8]> {
        self.sections
            .pe_data_at(self.buffer, rva)
            .ok_or(Other("bad stream offset"))
    }

    fn get_stream(&self, name: &'static str) -> Result<&'a [u8]> {
        let meta = self.get_cli_metadata()?;
        let header = meta
            .stream_headers
            .iter()
            .find(|h| h.name == name)
            .ok_or(Other("unable to find stream"))?;
        let data = self.raw_rva(self.cli.metadata.rva + header.offset)?;
        Ok(&data[..header.size as usize])
    }

    pub fn get_heap<T: Heap<'a>>(&self, name: &'static str) -> Result<T> {
        Ok(T::new(self.get_stream(name)?))
    }

    pub fn get_cli_metadata(&self) -> Result<Metadata> {
        self.at_rva(&self.cli.metadata)?.pread(0).map_err(CLI)
    }

    pub fn get_logical_metadata(&self) -> Result<metadata::header::Header> {
        self.get_stream("#~")?.pread(0).map_err(CLI)
    }

    pub fn get_method(&self, def: &metadata::table::MethodDef) -> Result<method::Method> {
        self.raw_rva(def.rva)?.pread(0).map_err(CLI)
    }

    pub fn resolve(&self) -> Result<Resolution<'a>> {
        let strings: Strings = self.get_heap("#Strings")?;
        let blobs: Blob = self.get_heap("#Blob")?;
        let guids: GUID = self.get_heap("#GUID")?;
        let userstrings: UserString = self.get_heap("#US")?;
        let mut tables = self.get_logical_metadata()?.tables;

        let types_len = tables.type_def.len();
        let type_ref_len = tables.type_ref.len();

        let ctx = convert::Context {
            def_len: types_len,
            ref_len: type_ref_len,
            specs: &tables.type_spec,
            blobs: &blobs,
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

        use resolved::*;

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

                Ok(Rc::new(ExternalAssemblyReference {
                    attributes: vec![],
                    version: build_version!(a),
                    flags: Flags::new(a.flags),
                    public_key_or_token: optional_idx!(blobs, a.public_key_or_token),
                    name: heap_idx!(strings, a.name),
                    culture: optional_idx!(strings, a.culture),
                    hash_value: optional_idx!(blobs, a.hash_value),
                }))
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
                    flags: TypeFlags::new(
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
                        Some(convert::member_type_source(t.extends, &ctx)?)
                    },
                    implements: vec![],
                    generic_parameters: vec![],
                    security: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        for n in tables.nested_class.iter() {
            let nest_idx = n.nested_class.0 - 1;
            match types.get_mut(nest_idx) {
                Some(t) => {
                    let enclose_idx = n.enclosing_class.0 - 1;
                    if enclose_idx < types_len {
                        t.encloser = Some(enclose_idx);
                    } else {
                        throw!(
                            "invalid enclosing type index {} for nested class declaration of type {}",
                            nest_idx, t.name
                        );
                    }
                }
                None => throw!(
                    "invalid type index {} for nested class declaration",
                    nest_idx
                ),
            }
        }

        let fields_len = tables.field.len();
        let method_len = tables.method_def.len();

        let owned_fields = tables.type_def.iter().enumerate().map(|e| {
            Ok(range_index!(enumerated e => range field_list in type_def, indexes field with len fields_len))
        }).collect::<Result<Vec<_>>>()?;

        let owned_methods = tables.type_def.iter().enumerate().map(|e| {
            Ok(range_index!(enumerated e => range method_list in type_def, indexes method_def with len method_len))
        }).collect::<Result<Vec<_>>>()?;

        let files: Vec<_> = tables
            .file
            .iter()
            .map(|f| {
                Ok(Rc::new(module::File {
                    attributes: vec![],
                    has_metadata: !check_bitmask!(f.flags, 0x0001),
                    name: heap_idx!(strings, f.name),
                    hash_value: heap_idx!(blobs, f.hash_value),
                }))
            })
            .collect::<Result<_>>()?;

        let resources: Vec<_> = tables
            .manifest_resource
            .iter()
            .map(|r| {
                use metadata::index::Implementation as BinImpl;
                use resource::*;

                let name = heap_idx!(strings, r.name);

                Ok(ManifestResource {
                    attributes: vec![],
                    offset: r.offset as usize,
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
                            match files.get(idx) {
                                Some(f) => Some(Implementation::File(Rc::clone(f))),
                                None => throw!(
                                    "invalid file index {} for manifest resource {}",
                                    idx,
                                    name
                                ),
                            }
                        }
                        BinImpl::AssemblyRef(a) => {
                            let idx = a - 1;
                            match assembly_refs.get(idx) {
                                Some(a) => Some(Implementation::Assembly(Rc::clone(a))),
                                None => throw!(
                                    "invalid assembly reference index {} for manifest resource {}",
                                    idx,
                                    name
                                ),
                            }
                        }
                        BinImpl::ExportedType(_) => throw!(
                            "exported type indices are invalid in manifest resource implementations (found in resource {})",
                            name
                        ),
                        BinImpl::Null => None
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
                Ok(Rc::new(ExportedType {
                    attributes: vec![],
                    flags: TypeFlags::new(e.flags, Layout::Automatic),
                    name,
                    namespace: optional_idx!(strings, e.type_namespace),
                    implementation: match e.implementation {
                        Implementation::File(f) => {
                            let idx = f - 1;
                            match files.get(idx) {
                                Some(f) => TypeImplementation::ModuleFile {
                                    type_def_idx: e.type_def_id as usize,
                                    file: Rc::clone(f),
                                },
                                None => {
                                    throw!("invalid file index {} in exported type {}", idx, name)
                                }
                            }
                        }
                        Implementation::AssemblyRef(a) => {
                            let idx = a - 1;
                            match assembly_refs.get(idx) {
                                Some(a) => TypeImplementation::TypeForwarder(Rc::clone(a)),
                                None => {
                                    throw!(
                                        "invalid assembly reference index {} in exported type {}",
                                        idx,
                                        name
                                    )
                                }
                            }
                        }
                        Implementation::ExportedType(t) => {
                            let idx = t - 1;
                            if idx < export_len {
                                TypeImplementation::Nested(idx)
                            } else {
                                throw!(
                                    "invalid nested type index {} in exported type {}",
                                    idx,
                                    name
                                );
                            }
                        }
                        Implementation::Null => throw!(
                            "invalid null implementation index for exported type {}",
                            name
                        ),
                    },
                }))
            })
            .collect::<Result<_>>()?;

        let module_row = tables.module.first().ok_or(scroll::Error::Custom(
            "missing required module metadata table".to_string(),
        ))?;
        let module = module::Module {
            attributes: vec![],
            name: heap_idx!(strings, module_row.name),
            mvid: heap_idx!(guids, module_row.mvid),
        };

        let module_refs = tables
            .module_ref
            .iter()
            .map(|r| {
                Ok(Rc::new(module::ExternalModuleReference {
                    attributes: vec![],
                    name: heap_idx!(strings, r.name),
                }))
            })
            .collect::<Result<Vec<_>>>()?;

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
                            match module_refs.get(idx) {
                                Some(m) => ResolutionScope::ExternalModule(Rc::clone(m)),
                                None => throw!(
                                    "invalid module reference index {} for type reference {}",
                                    idx,
                                    name
                                ),
                            }
                        }
                        BinRS::AssemblyRef(a) => {
                            let idx = a - 1;
                            match assembly_refs.get(idx) {
                                Some(a) => ResolutionScope::Assembly(Rc::clone(a)),
                                None => throw!(
                                    "invalid assembly reference index {} for type reference {}",
                                    idx,
                                    name
                                ),
                            }
                        }
                        BinRS::TypeRef(t) => {
                            let idx = t - 1;
                            if idx < type_ref_len {
                                ResolutionScope::Nested(idx)
                            } else {
                                throw!(
                                    "invalid nested type index {} for type reference {}",
                                    idx,
                                    name
                                );
                            }
                        }
                        BinRS::Null => ResolutionScope::Exported(Rc::clone(
                            exports
                                .iter()
                                .find(|e| e.name == name && e.namespace == namespace)
                                .ok_or(scroll::Error::Custom(format!(
                                    "missing exported type for type reference {}",
                                    name
                                )))?,
                        )),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;

        for i in tables.interface_impl.iter() {
            let idx = i.class.0 - 1;
            match types.get_mut(idx) {
                Some(t) => t
                    .implements
                    .push((vec![], convert::member_type_source(i.interface, &ctx)?)),
                None => throw!("invalid type index {} for interface implementation", idx),
            }
        }

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

        // this allows us to initialize the Vec out of order, which is safe because we know that everything
        // will eventually be initialized in the end
        // it's much simpler/more efficient than trying to use a HashMap or something
        macro_rules! new_with_len {
            ($name:ident, $len:ident) => {
                let mut $name = Vec::with_capacity($len);
                unsafe {
                    $name.set_len($len);
                }
            };
        }

        new_with_len!(fields, fields_len);

        for (type_idx, type_fields) in owned_fields.into_iter().enumerate() {
            use super::binary::signature::kinds::FieldSig;
            use members::*;

            let parent_fields = &mut types[type_idx].fields;

            for (f_idx, f) in type_fields {
                let FieldSig(cmod, t) = heap_idx!(blobs, f.signature).pread(0)?;

                parent_fields.push(Field {
                    attributes: vec![],
                    name: heap_idx!(strings, f.name),
                    type_modifier: opt_map_try!(cmod, |c| convert::custom_modifier(c, &ctx)),
                    return_type: convert::member_type_sig(t, &ctx)?,
                    accessibility: member_accessibility(f.flags)?,
                    static_member: check_bitmask!(f.flags, 0x10),
                    init_only: check_bitmask!(f.flags, 0x20),
                    literal: check_bitmask!(f.flags, 0x40),
                    default: None,
                    not_serialized: check_bitmask!(f.flags, 0x80),
                    special_name: check_bitmask!(f.flags, 0x200),
                    pinvoke: check_bitmask!(f.flags, 0x2000),
                    runtime_special_name: check_bitmask!(f.flags, 0x400),
                    offset: None,
                    marshal: None,
                    start_of_initial_value: None,
                });
                fields[f_idx] = (type_idx, parent_fields.len() - 1);
            }
        }

        macro_rules! get_field {
            ($f_idx:expr) => {{
                let (type_idx, internal_idx) = $f_idx;
                &mut types[type_idx].fields[internal_idx]
            }};
        }

        for layout in tables.field_layout.iter() {
            let idx = layout.field.0 - 1;
            match fields.get(idx) {
                Some(&field) => {
                    get_field!(field).offset = Some(layout.offset as usize);
                }
                None => throw!(
                    "bad parent field index {} for field layout specification",
                    idx
                ),
            }
        }

        for rva in tables.field_rva.iter() {
            let idx = rva.field.0 - 1;
            match fields.get(idx) {
                Some(&field) => {
                    get_field!(field).start_of_initial_value =
                        Some(&self.buffer[rva.rva as usize..])
                }
                None => throw!("bad parent field index {} for field RVA specification", idx),
            }
        }

        let params_len = tables.param.len();

        new_with_len!(methods, method_len);

        let mut owned_params = Vec::with_capacity(params_len);
        for (type_idx, type_methods) in owned_methods.into_iter().enumerate() {
            let parent_methods = &mut types[type_idx].methods;

            for (m_idx, m) in type_methods {
                use members::*;

                let name = heap_idx!(strings, m.name);

                let sig = convert::managed_method(
                    heap_idx!(blobs, m.signature).pread_with(0, ())?,
                    &ctx,
                )?;
                let param_len = sig.parameters.len();

                parent_methods.push(Method {
                    attributes: vec![],
                    name,
                    body: Some(body::Method {
                        header: body::Header {
                            initialize_locals: false,
                            maximum_stack_size: 0,
                            local_variables: vec![],
                        },
                        body: vec![],
                        data_sections: vec![],
                    }),
                    signature: sig,
                    accessibility: member_accessibility(m.flags)?,
                    generic_parameters: vec![],
                    parameter_metadata: vec![None; param_len + 1],
                    static_member: check_bitmask!(m.flags, 0x10),
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

                methods[m_idx] = MethodIndex {
                    parent_type: type_idx,
                    member: MethodMemberIndex::Method(parent_methods.len() - 1),
                };

                owned_params.push((
                    m_idx,
                    range_index!(
                        enumerated (m_idx, m) => range param_list in method_def,
                        indexes param with len params_len
                    ),
                ));
            }
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

        // TODO: convert member ref indices

        let field_refs = tables
            .member_ref
            .iter()
            .filter_map(|r| {
                use crate::binary::signature::kinds::FieldSig;
                use members::*;
                use metadata::index::{MemberRefParent, TypeDefOrRef};

                let name = filter_map_try!(strings.at_index(r.name).map_err(CLI));
                let sig_blob = filter_map_try!(blobs.at_index(r.signature).map_err(CLI));

                let parent = match r.class {
                    MemberRefParent::TypeDef(i) => FieldReferenceParent::Type(filter_map_try!(
                        convert::method_type_source(TypeDefOrRef::TypeDef(i), &ctx)
                    )),
                    MemberRefParent::TypeRef(i) => FieldReferenceParent::Type(filter_map_try!(
                        convert::method_type_source(TypeDefOrRef::TypeRef(i), &ctx)
                    )),
                    MemberRefParent::TypeSpec(i) => FieldReferenceParent::Type(filter_map_try!(
                        convert::method_type_source(TypeDefOrRef::TypeSpec(i), &ctx)
                    )),
                    MemberRefParent::ModuleRef(i) => {
                        let idx = i - 1;
                        match module_refs.get(idx) {
                            Some(m) => FieldReferenceParent::Module(m),
                            None => {
                                return Some(Err(CLI(scroll::Error::Custom(format!(
                                    "invalid module reference index {} for field reference {}",
                                    idx, name
                                )))))
                            }
                        }
                    }
                    bad => {
                        return Some(Err(CLI(scroll::Error::Custom(format!(
                            "bad parent index {:?} for field reference {}",
                            bad, name
                        )))))
                    }
                };

                match sig_blob.pread::<FieldSig>(0) {
                    Ok(field_sig) => Some(Ok(ExternalFieldReference {
                        attributes: vec![],
                        parent,
                        name,
                        return_type: filter_map_try!(convert::member_type_sig(field_sig.1, &ctx)),
                    })),
                    Err(_) => None,
                }
            })
            .collect::<Result<Vec<_>>>()?;

        // only should be used before the event/method semantics phase
        // since before then we know member index is a Method(usize)
        macro_rules! get_method {
            ($unwrap:expr) => {{
                let MethodIndex {
                    parent_type,
                    member,
                } = $unwrap;
                &mut types[parent_type].methods[match member {
                    MethodMemberIndex::Method(i) => i,
                    _ => unreachable!(),
                }]
            }};
        }

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

        for (idx, p) in tables.generic_param.iter().enumerate() {
            use generic::*;
            use metadata::index::TypeOrMethodDef;

            let name = heap_idx!(strings, p.name);

            macro_rules! make_generic {
                ($convert_meth:ident) => {
                    Generic {
                        attributes: vec![],
                        sequence: p.number as usize,
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
                        type_constraints: (
                            vec![],
                            tables
                                .generic_param_constraint
                                .iter()
                                .filter_map(|c| {
                                    if c.owner.0 - 1 == idx {
                                        Some(convert::$convert_meth(c.constraint, &ctx))
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Result<_>>()?,
                        ),
                    }
                };
            }

            match p.owner {
                TypeOrMethodDef::TypeDef(i) => {
                    let idx = i - 1;
                    match types.get_mut(idx) {
                        Some(t) => t.generic_parameters.push(make_generic!(member_type_idx)),
                        None => throw!("invalid type index {} for generic parameter {}", idx, name),
                    }
                }
                TypeOrMethodDef::MethodDef(i) => {
                    let idx = i - 1;
                    let method =
                        get_method!(*methods.get(idx).ok_or(scroll::Error::Custom(format!(
                            "invalid method index {} for generic parameter {}",
                            idx, name
                        )))?);

                    method
                        .generic_parameters
                        .push(make_generic!(method_type_idx));
                }
                TypeOrMethodDef::Null => {
                    throw!("invalid null owner index for generic parameter {}", name)
                }
            }
        }

        // this doesn't really matter that much, just to make the sequences nicer
        // I originally tried to do this with uninitialized Vecs and no sequence field,
        // but for reasons I don't understand, that broke
        for t in types.iter_mut() {
            t.generic_parameters.sort_by_key(|p| p.sequence);

            for m in t.methods.iter_mut() {
                m.generic_parameters.sort_by_key(|p| p.sequence);
            }
        }

        new_with_len!(params, params_len);

        for (m_idx, iter) in owned_params {
            for (p_idx, param) in iter {
                use members::*;

                let meta_idx = param.sequence as usize;

                let param_val = Some(ParameterMetadata {
                    attributes: vec![],
                    name: heap_idx!(strings, param.name),
                    is_in: check_bitmask!(param.flags, 0x1),
                    is_out: check_bitmask!(param.flags, 0x2),
                    optional: check_bitmask!(param.flags, 0x10),
                    default: None,
                    marshal: None,
                });

                get_method!(methods[m_idx]).parameter_metadata[meta_idx] = param_val;

                params[p_idx] = (m_idx, meta_idx);
            }
        }

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
                            get_method!(methods[m_idx]).parameter_metadata[p_idx]
                                .as_mut()
                                .unwrap()
                                .marshal = value;
                        }
                        None => throw!("bad parameter index {} for field marshal", idx),
                    }
                }
                HasFieldMarshal::Null => throw!("invalid null parent index for field marshal"),
            }
        }

        let prop_len = tables.property.len();

        new_with_len!(properties, prop_len);

        for (map_idx, map) in tables.property_map.iter().enumerate() {
            let type_idx = map.parent.0 - 1;

            let parent_props = match types.get_mut(type_idx) {
                Some(t) => &mut t.properties,
                None => throw!(
                    "invalid parent type index {} for property map {}",
                    type_idx,
                    map_idx
                ),
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
                    type_modifier: opt_map_try!(sig.custom_modifier, |c| convert::custom_modifier(
                        c, &ctx
                    )),
                    return_type: convert::member_type_sig(sig.ret_type, &ctx)?,
                    special_name: check_bitmask!(prop.flags, 0x200),
                    runtime_special_name: check_bitmask!(prop.flags, 0x1000),
                    default: None,
                });
                properties[p_idx] = (type_idx, parent_props.len() - 1);
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

        new_with_len!(events, event_len);

        for (map_idx, map) in tables.event_map.iter().enumerate() {
            let type_idx = map.parent.0 - 1;

            let parent = types
                .get_mut(type_idx)
                .ok_or(scroll::Error::Custom(format!(
                    "invalid parent type index {} for event map {}",
                    type_idx, map_idx
                )))?;
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
                    delegate_type: convert::member_type_idx(event.event_type, &ctx)?,
                    add_listener: get_listener!("add", 0x8, EventAdd),
                    remove_listener: get_listener!("remove", 0x10, EventRemove),
                    raise_event: None,
                    other: vec![],
                    special_name: check_bitmask!(event.event_flags, 0x200),
                    runtime_special_name: check_bitmask!(event.event_flags, 0x400),
                });
                events[e_idx] = (type_idx, internal_idx);
            }
        }

        for s in tables.method_semantics.iter() {
            use metadata::index::HasSemantics;

            let raw_idx = s.method.0 - 1;
            let method_idx = *methods.get(raw_idx).ok_or(scroll::Error::Custom(format!(
                "invalid method index {} for method semantics",
                raw_idx
            )))?;

            let parent = &mut types[method_idx.parent_type];

            let new_meth = extract_method!(parent, method_idx);

            let member_idx = &mut methods[raw_idx].member;

            match s.association {
                HasSemantics::Event(i) => {
                    let idx = i - 1;
                    let &(_, internal_idx) = events.get(idx).ok_or(scroll::Error::Custom(
                        format!("invalid event index {} for method semantics", idx),
                    ))?;
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
                    let &(_, internal_idx) = properties.get(idx).ok_or(scroll::Error::Custom(
                        format!("invalid property index {} for method semantics", idx),
                    ))?;
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

        let mut method_map = HashMap::new();
        let method_refs = tables
            .member_ref
            .iter()
            .enumerate()
            .filter_map(|(idx, r)| {
                use crate::binary::signature::kinds::{CallingConvention, MethodRefSig};
                use members::*;
                use metadata::index::{MemberRefParent, TypeDefOrRef};

                let name = filter_map_try!(strings.at_index(r.name).map_err(CLI));
                let sig_blob = filter_map_try!(blobs.at_index(r.signature).map_err(CLI));

                match sig_blob.pread_with::<MethodRefSig>(0, ()) {
                    Ok(ref_sig) => {
                        let mut signature =
                            filter_map_try!(convert::managed_method(ref_sig.method_def, &ctx));
                        if signature.calling_convention == CallingConvention::Vararg {
                            signature.varargs = Some(filter_map_try!(ref_sig
                                .varargs
                                .into_iter()
                                .map(|p| convert::parameter(p, &ctx))
                                .collect::<Result<_>>()));
                        }

                        let parent = match r.class {
                            MemberRefParent::TypeDef(i) => {
                                MethodReferenceParent::Type(filter_map_try!(
                                    convert::method_type_source(TypeDefOrRef::TypeDef(i), &ctx)
                                ))
                            }
                            MemberRefParent::TypeRef(i) => {
                                MethodReferenceParent::Type(filter_map_try!(
                                    convert::method_type_source(TypeDefOrRef::TypeRef(i), &ctx)
                                ))
                            }
                            MemberRefParent::TypeSpec(i) => {
                                MethodReferenceParent::Type(filter_map_try!(
                                    convert::method_type_source(TypeDefOrRef::TypeSpec(i), &ctx)
                                ))
                            }
                            MemberRefParent::ModuleRef(i) => {
                                let idx = i - 1;
                                match module_refs.get(idx) {
                                    Some(m) => MethodReferenceParent::Module(Rc::clone(m)),
                                    None => {
                                        return Some(Err(CLI(scroll::Error::Custom(format!(
                                            "bad module ref index {} for method reference {}",
                                            idx, name
                                        )))))
                                    }
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
                    }
                    Err(_) => None,
                }
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .enumerate()
            .map(|(current_idx, (orig_idx, r))| {
                method_map.insert(orig_idx, current_idx);
                Rc::new(r)
            })
            .collect::<Vec<_>>();

        for i in tables.method_impl.iter() {
            use members::*;
            use metadata::index::MethodDefOrRef;
            use types::*;

            let idx = i.class.0 - 1;
            let t = types.get_mut(idx).ok_or(scroll::Error::Custom(format!(
                "invalid parent type index {} for method override",
                idx
            )))?;

            macro_rules! build_method {
                ($idx:expr, $name:literal) => {
                    match $idx {
                        MethodDefOrRef::MethodDef(i) => {
                            let m_idx = i - 1;
                            match methods.get(m_idx) {
                                Some(&m) => UserMethod::Definition(m),
                                None => throw!(
                                    "invalid method index {} for method override {} in type {}",
                                    m_idx, $name, t.name
                                )
                            }
                        }
                        MethodDefOrRef::MemberRef(i) => {
                            let r_idx = i - 1;
                            match method_map.get(&r_idx) {
                                Some(&m_idx) => UserMethod::Reference(Rc::clone(&method_refs[m_idx])),
                                None => throw!(
                                    "invalid member reference index {} for method override {} in type {}",
                                    r_idx, $name, t.name
                                )
                            }
                        }
                        MethodDefOrRef::Null => throw!(
                            "invalid null {} index for method override in type {}",
                            $name, t.name
                        )
                    }
                }
            }

            t.overrides.push(MethodOverride {
                implementation: build_method!(i.method_body, "implementation"),
                declaration: build_method!(i.method_declaration, "declaration"),
            });
        }

        Ok(Resolution {
            assembly,
            assembly_references: assembly_refs,
            manifest_resources: resources,
            module,
            module_references: module_refs,
            type_definitions: types,
            type_references: type_refs,
        })
    }
}
