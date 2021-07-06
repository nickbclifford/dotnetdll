use super::{
    binary::{
        cli::{Header, Metadata, RVASize},
        heap::*,
        metadata, method,
    },
    convert, resolved,
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

use std::rc::Rc;

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

use DLLError::*;

pub type Result<T> = std::result::Result<T, DLLError>;

pub struct Resolution<'a> {
    pub assembly: Option<resolved::assembly::Assembly<'a>>,
    pub module: resolved::module::Module<'a>,
    pub type_definitions: Vec<resolved::types::TypeDefinition<'a>>,
    pub type_references: Vec<resolved::types::ExternalTypeReference<'a>>,
    // TODO
}

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

        macro_rules! range_index {
            (($idx:expr, $var:expr), $field:ident, $len:expr, $table:ident) => {
                ($var.$field.0 - 1)..(match tables.$table.get($idx + 1) {
                    Some(r) => r.$field.0,
                    None => $len + 1,
                } - 1)
            };
        }

        use resolved::*;

        let mut assembly = None;
        if let Some(a) = tables.assembly.first() {
            use assembly::*;

            assembly = Some(Assembly {
                attributes: vec![],
                hash_algorithm: match a.hash_alg_id {
                    0x0000 => HashAlgorithm::None,
                    0x8003 => HashAlgorithm::ReservedMD5,
                    0x8004 => HashAlgorithm::SHA1,
                    other => {
                        return Err(CLI(scroll::Error::Custom(format!(
                            "unrecognized assembly hash algorithm {:#06x}",
                            other
                        ))))
                    }
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
                    name: heap_idx!(strings, t.type_name),
                    namespace: optional_idx!(strings, t.type_namespace),
                    fields: vec![],
                    properties: vec![],
                    methods: vec![],
                    events: vec![],
                    nested_types: vec![],
                    overrides: vec![],
                    extends: None,
                    implements: vec![],
                    generic_parameters: vec![],
                    security: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let fields_len = tables.field.len();
        let method_len = tables.method_def.len();

        let owned_fields = tables.type_def.iter().enumerate().map(|(idx, t)| {
            let f_range = range_index!((idx, t), field_list, fields_len, type_def);
            f_range.clone().zip(&tables.field[f_range])
        });

        let owned_methods = tables.type_def.iter().enumerate().map(|(idx, t)| {
            let m_range = range_index!((idx, t), method_list, method_len, type_def);
            m_range.clone().zip(&tables.method_def[m_range])
        });

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

        let exports: Vec<_> = tables
            .exported_type
            .iter()
            .map(|e| {
                use metadata::index::Implementation;
                use types::*;

                Ok(Rc::new(ExportedType {
                    attributes: vec![],
                    flags: TypeFlags::new(e.flags, Layout::Automatic),
                    name: heap_idx!(strings, e.type_name),
                    namespace: optional_idx!(strings, e.type_namespace),
                    implementation: match e.implementation {
                        Implementation::File(f) => TypeImplementation::ModuleFile {
                            type_def_idx: e.type_def_id as usize,
                            file: Rc::clone(&files[f - 1]),
                        },
                        Implementation::AssemblyRef(a) => {
                            TypeImplementation::TypeForwarder(Rc::clone(&assembly_refs[a - 1]))
                        }
                        Implementation::ExportedType(t) => TypeImplementation::Nested(t - 1),
                        Implementation::Null => {
                            return Err(CLI(scroll::Error::Custom(format!(
                                "invalid null implementation index for exported type {}",
                                heap_idx!(strings, e.type_name)
                            ))))
                        }
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
                    name: heap_idx!(strings, r.type_name),
                    namespace: optional_idx!(strings, r.type_namespace),
                    scope: match r.resolution_scope {
                        BinRS::Module(_) => ResolutionScope::CurrentModule,
                        BinRS::ModuleRef(m) => {
                            ResolutionScope::ExternalModule(Rc::clone(&module_refs[m - 1]))
                        }
                        BinRS::AssemblyRef(a) => {
                            ResolutionScope::Assembly(Rc::clone(&assembly_refs[a - 1]))
                        }
                        BinRS::TypeRef(t) => ResolutionScope::Nested(t - 1),
                        BinRS::Null => ResolutionScope::Exported(Rc::clone(
                            exports
                                .iter()
                                .find(|e| e.name == name && e.namespace == namespace)
                                .ok_or(scroll::Error::Custom(format!(
                                    "missing exported type for type ref {}",
                                    name
                                )))?,
                        )),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let ctx = convert::Context {
            specs: &tables.type_spec,
            blobs: &blobs,
        };

        fn member_accessibility(flags: u16) -> Result<members::Accessibility> {
            use members::Accessibility::*;
            use resolved::Accessibility::*;

            Ok(match flags & 0x7 {
                0x0 => CompilerControlled,
                0x1 => Access(Private),
                0x2 => Access(PrivateProtected),
                0x3 => Access(Internal),
                0x4 => Access(Protected),
                0x5 => Access(ProtectedInternal),
                0x6 => Access(Public),
                _ => {
                    return Err(CLI(scroll::Error::Custom(
                        "flags value 0x7 has no meaning for member accessibility".to_string(),
                    )))
                }
            })
        }

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
                    type_modifier: opt_map_try!(cmod, |c| convert::custom_modifier(c)),
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
                None => {
                    return Err(CLI(scroll::Error::Custom(format!(
                        "bad parent field index {} for field layout specification",
                        idx
                    ))));
                }
            }
        }

        for rva in tables.field_rva.iter() {
            let idx = rva.field.0 - 1;
            match fields.get(idx) {
                Some(&field) => {
                    get_field!(field).start_of_initial_value =
                        Some(&self.buffer[rva.rva as usize..])
                }
                None => {
                    return Err(CLI(scroll::Error::Custom(format!(
                        "bad parent field index {} for field RVA specification",
                        idx
                    ))));
                }
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
                let range = range_index!((m_idx, m), param_list, params_len, method_def);

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
                        0x2 => {
                            return Err(CLI(scroll::Error::Custom(format!(
                                "invalid code type value OPTIL (0x2) for method {}",
                                name
                            ))))
                        }
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

                methods[m_idx] = (type_idx, parent_methods.len() - 1);

                owned_params.push((m_idx, range.clone().zip(&tables.param[range])));
            }
        }

        macro_rules! get_method {
            ($m_idx:expr) => {{
                let (type_idx, internal_idx) = methods[$m_idx];
                &mut types[type_idx].methods[internal_idx]
            }};
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
                                return Err(CLI(scroll::Error::Custom(format!(
                                    "invalid variance value 0x3 for generic parameter {}",
                                    name
                                ))))
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
                        None => {
                            return Err(CLI(scroll::Error::Custom(format!(
                                "invalid type index {} for generic parameter {}",
                                idx, name
                            ))))
                        }
                    }
                }
                TypeOrMethodDef::MethodDef(i) => {
                    let idx = i - 1;
                    match methods.get(idx) {
                        Some(&(t, m)) => types[t].methods[m]
                            .generic_parameters
                            .push(make_generic!(method_type_idx)),
                        None => {
                            return Err(CLI(scroll::Error::Custom(format!(
                                "invalid method index {} for generic parameter {}",
                                idx, name
                            ))))
                        }
                    }
                }
                TypeOrMethodDef::Null => {
                    return Err(CLI(scroll::Error::Custom(format!(
                        "invalid null owner index for generic parameter {}",
                        name
                    ))))
                }
            }
        }

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

                get_method!(m_idx).parameter_metadata[meta_idx] = param_val;

                params[p_idx] = (m_idx, meta_idx);
            }
        }

        for marshal in tables.field_marshal {
            use crate::binary::{metadata::index::HasFieldMarshal, signature::kinds::MarshalSpec};

            let value = Some(heap_idx!(blobs, marshal.native_type).pread::<MarshalSpec>(0)?);

            match marshal.parent {
                HasFieldMarshal::Field(i) => match fields.get(i) {
                    Some(&field) => get_field!(field).marshal = value,
                    None => {
                        return Err(CLI(scroll::Error::Custom(format!(
                            "bad field index {} for field marshal",
                            i
                        ))))
                    }
                },
                HasFieldMarshal::Param(i) => match params.get(i) {
                    Some(&(m_idx, p_idx)) => {
                        get_method!(m_idx).parameter_metadata[p_idx]
                            .as_mut()
                            .unwrap()
                            .marshal = value;
                    }
                    None => {
                        return Err(CLI(scroll::Error::Custom(format!(
                            "bad parameter index {} for field marshal",
                            i
                        ))))
                    }
                },
                HasFieldMarshal::Null => {
                    return Err(CLI(scroll::Error::Custom(
                        "invalid null parent index for field marshal".to_string(),
                    )))
                }
            }
        }

        let prop_len = tables.property.len();

        new_with_len!(properties, prop_len);

        for (map_idx, map) in tables.property_map.iter().enumerate() {
            let type_idx = map.parent.0 - 1;

            let parent_props = &mut types[type_idx].properties;

            let range = range_index!((map_idx, map), property_list, prop_len, property_map);
            for (p_idx, prop) in range.clone().zip(&tables.property[range]) {
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
                        c
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
        // TODO: indices for owned methods if anything needs to come after this stage
        macro_rules! extract_method {
            ($parent:ident, $type_idx:ident, $internal_idx:ident) => {{
                for (t_idx, i_idx) in methods.iter_mut() {
                    if *t_idx == $type_idx && *i_idx > $internal_idx {
                        *i_idx -= 1;
                    }
                }
                $parent.methods.remove($internal_idx)
            }};
        }

        let event_len = tables.event.len();

        new_with_len!(events, event_len);

        for (map_idx, map) in tables.event_map.iter().enumerate() {
            let type_idx = map.parent.0 - 1;

            let parent = &mut types[type_idx];
            let parent_events = &mut parent.events;

            let range = range_index!((map_idx, map), event_list, event_len, event_map);
            for (e_idx, event) in range.clone().zip(&tables.event[range]) {
                use members::*;

                let name = heap_idx!(strings, event.name);

                macro_rules! get_listener {
                    ($l_name:literal, $flag:literal) => {{
                        let m = tables.method_semantics.remove(tables.method_semantics.iter().position(|s| {
                            use metadata::index::HasSemantics;
                            check_bitmask!(s.semantics, $flag)
                                && matches!(s.association, HasSemantics::Event(e) if e_idx == e - 1)
                        }).ok_or(scroll::Error::Custom(format!("could not find {} listener for event {}", $l_name, name)))?);
                        let (_, internal_idx) = methods[m.method.0 - 1];
                        extract_method!(parent, type_idx, internal_idx)
                    }}
                }

                parent_events.push(Event {
                    attributes: vec![],
                    name,
                    delegate_type: convert::member_type_idx(event.event_type, &ctx)?,
                    add_listener: get_listener!("add", 0x8),
                    remove_listener: get_listener!("remove", 0x10),
                    raise_event: None,
                    other: vec![],
                    special_name: check_bitmask!(event.event_flags, 0x200),
                    runtime_special_name: check_bitmask!(event.event_flags, 0x400),
                });
                events[e_idx] = (type_idx, parent_events.len() - 1);
            }
        }

        for s in tables.method_semantics.iter() {
            use metadata::index::HasSemantics;

            let m_idx = s.method.0 - 1;
            let &(type_idx, internal_method_idx) =
                methods.get(m_idx).ok_or(scroll::Error::Custom(format!(
                    "invalid method index {} for method semantics",
                    m_idx
                )))?;

            let parent = &mut types[type_idx];
            if internal_method_idx >= parent.methods.len() {
                return Err(CLI(scroll::Error::Custom(format!(
                    "invalid method index {} for type {}",
                    internal_method_idx,
                    parent.type_name()
                ))));
            }

            let new_meth = extract_method!(parent, type_idx, internal_method_idx);

            match s.association {
                HasSemantics::Event(i) => {
                    let &(_, internal_idx) = events.get(i - 1).ok_or(scroll::Error::Custom(
                        format!("invalid event index {} for method semantics", i),
                    ))?;
                    let event = &mut parent.events[internal_idx];

                    if check_bitmask!(s.semantics, 0x20) {
                        event.raise_event = Some(new_meth);
                    } else if check_bitmask!(s.semantics, 0x4) {
                        event.other.push(new_meth);
                    }
                }
                HasSemantics::Property(i) => {
                    let &(_, internal_idx) = properties.get(i - 1).ok_or(scroll::Error::Custom(
                        format!("invalid property index {} for method semantics", i),
                    ))?;
                    let property = &mut parent.properties[internal_idx];

                    if check_bitmask!(s.semantics, 0x1) {
                        property.setter = Some(new_meth);
                    } else if check_bitmask!(s.semantics, 0x2) {
                        property.getter = Some(new_meth);
                    } else if check_bitmask!(s.semantics, 0x4) {
                        property.other.push(new_meth);
                    }
                }
                HasSemantics::Null => {
                    return Err(CLI(scroll::Error::Custom(
                        "invalid null index for method semantics".to_string(),
                    )));
                }
            }
        }

        Ok(Resolution {
            assembly,
            module,
            type_definitions: types,
            type_references: type_refs,
        })
    }
}