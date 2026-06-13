use std::sync::OnceLock;

use rustc_hash::FxHashMap;
use scroll::Pread;

use crate::{
    binary::{
        heap::{BlobReader, Reader, UserStringReader},
        metadata::{
            index::{Blob as BlobIndex, Token, TokenTarget},
            table::{Kind, MethodSpec, StandAloneSig, TypeSpec},
        },
        method,
        signature::kinds::{CallingConvention, LocalVar, LocalVarSig, MethodRefSig},
    },
    convert::{self, TypeKind},
    dll::{DLLError::*, Result},
    resolved::{
        body,
        signature::ManagedMethod,
        types::{LocalVariable, MethodType},
    },
};

use super::{FieldIndex, MethodIndex};

/// Raw bytes and alignment offset for a single method, captured at parse time.
pub(crate) struct MethodPendingRaw<'a> {
    pub bytes: &'a [u8],
    pub offset: usize,
}

/// All context needed to decode method bodies and/or signatures on demand, shared across
/// `Resolution` clones.
pub(crate) struct LazyParseState<'a> {
    /// Whether method bodies are decoded lazily (mirrors `ReadOptions::lazy_method_bodies`).
    pub lazy_bodies: bool,
    /// Whether method signatures are decoded lazily (mirrors `ReadOptions::lazy_method_signatures`).
    pub lazy_signatures: bool,

    pub def_len: usize,
    pub ref_len: usize,
    // Owned copies of the table rows needed by Context/MethodContext
    pub specs: Vec<TypeSpec>,
    pub sigs: Vec<StandAloneSig>,
    pub method_spec_table: Vec<MethodSpec>,
    // Heap readers are Copy (&'a [u8] wrappers)
    pub blobs: BlobReader<'a>,
    pub userstrings: UserStringReader<'a>,
    // Owned copies of the index maps
    pub field_map: FxHashMap<usize, usize>,
    pub field_indices: Vec<FieldIndex>,
    pub method_indices: Vec<MethodIndex>,
    pub method_map: FxHashMap<usize, usize>,

    // ── Lazy body fields (populated only when lazy_bodies is true) ──────────
    // Per-method: [method_def_idx] -> raw bytes (None for abstract/rva==0)
    pub pending: Vec<Option<MethodPendingRaw<'a>>>,
    /// MethodIndex -> method_def_idx (for methods with bodies; used by method_body)
    pub method_idx_to_def: FxHashMap<MethodIndex, usize>,
    /// [method_def_idx] -> decoded body; shared across all Resolution clones via Arc
    pub body_cache: Vec<OnceLock<body::Method>>,

    // ── Lazy signature fields (populated only when lazy_signatures is true) ──
    /// MethodIndex -> method_def_idx for ALL methods (including abstract); used by
    /// method_signature.
    pub sig_method_idx_to_def: FxHashMap<MethodIndex, usize>,
    /// [method_def_idx] -> (blob index, is_static flag) captured from the MethodDef row.
    pub sig_pending_def: Vec<(BlobIndex, bool)>,
    /// [method_def_idx] -> decoded signature cache; shared across all Resolution clones via Arc.
    pub sig_cache_def: Vec<OnceLock<ManagedMethod<MethodType>>>,
    /// [method_ref_idx] -> blob index captured from the MemberRef row.
    pub sig_pending_ref: Vec<BlobIndex>,
    /// [method_ref_idx] -> decoded signature cache; shared across all Resolution clones via Arc.
    pub sig_cache_ref: Vec<OnceLock<ManagedMethod<MethodType>>>,

    // ── Lazy attribute fields (populated only when lazy_attributes is true) ──────
    /// Whether attributes are decoded lazily (mirrors `ReadOptions::lazy_attributes`).
    pub lazy_attributes: bool,
    /// type_def_idx (0-based) → pre-resolved (constructor, blob_idx) pairs.
    /// Populated in one pass at construction; only entries with attributes are present.
    pub attr_by_type: FxHashMap<usize, Vec<AttrRaw>>,
    /// method_def_idx (0-based) → pre-resolved pairs.
    pub attr_by_method: FxHashMap<usize, Vec<AttrRaw>>,
    /// field_def_idx (0-based) → pre-resolved pairs.
    pub attr_by_field: FxHashMap<usize, Vec<AttrRaw>>,
    /// Assembly custom attributes (usually empty or a handful).
    pub attr_by_assembly: Vec<AttrRaw>,
    /// O(1) reverse map: MethodIndex → method_def_idx. Populated when `lazy_attributes` is true
    /// so `method_attributes` avoids a linear scan over `method_indices`.
    pub attr_method_idx_to_def: FxHashMap<super::MethodIndex, usize>,
    /// O(1) reverse map: FieldIndex → field_def_idx. Populated when `lazy_attributes` is true
    /// so `field_attributes` avoids a linear scan over `field_indices`.
    pub attr_field_idx_to_def: FxHashMap<super::FieldIndex, usize>,
}

/// Pre-resolved attribute row: (constructor method, optional blob index).
/// Stores no `'a` lifetime so that `LazyParseState<'a>` stays covariant.
pub(crate) type AttrRaw = (crate::resolved::members::UserMethod, Option<BlobIndex>);

impl<'a> std::fmt::Debug for LazyParseState<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyParseState")
            .field("def_len", &self.def_len)
            .field("ref_len", &self.ref_len)
            .field("lazy_bodies", &self.lazy_bodies)
            .field("lazy_signatures", &self.lazy_signatures)
            .field("lazy_attributes", &self.lazy_attributes)
            .field("pending_count", &self.pending.iter().filter(|p| p.is_some()).count())
            .field("body_cached_count", &self.body_cache.iter().filter(|c| c.get().is_some()).count())
            .field("sig_def_cached_count", &self.sig_cache_def.iter().filter(|c| c.get().is_some()).count())
            .field("sig_ref_cached_count", &self.sig_cache_ref.iter().filter(|c| c.get().is_some()).count())
            .field("attr_type_count", &self.attr_by_type.len())
            .field("attr_method_count", &self.attr_by_method.len())
            .field("attr_field_count", &self.attr_by_field.len())
            .finish_non_exhaustive()
    }
}

impl<'a> LazyParseState<'a> {
    /// Decode the body for `method_def_idx`, or return a cached result if already decoded.
    ///
    /// On decode failure the `OnceLock` cell is left empty so the next call retries.
    pub fn decode_body(&self, def_idx: usize) -> Result<&body::Method> {
        // get_or_try_init isn't stable yet; use get/set manually.
        // In a rare race two threads may decode the same body simultaneously; the second
        // set() call is silently discarded by OnceLock, which is correct behaviour.
        if let Some(cached) = self.body_cache[def_idx].get() {
            return Ok(cached);
        }
        let body = self.decode_body_inner(def_idx)?;
        let _ = self.body_cache[def_idx].set(body);
        Ok(self.body_cache[def_idx].get().unwrap())
    }

    /// Decode the signature for method def at `def_idx`, or return a cached result.
    ///
    /// On decode failure the `OnceLock` cell is left empty so the next call retries.
    pub fn decode_method_def_sig(&self, def_idx: usize) -> Result<&ManagedMethod<MethodType>> {
        if let Some(cached) = self.sig_cache_def[def_idx].get() {
            return Ok(cached);
        }
        let sig = self.decode_method_def_sig_inner(def_idx)?;
        let _ = self.sig_cache_def[def_idx].set(sig);
        Ok(self.sig_cache_def[def_idx].get().unwrap())
    }

    fn decode_method_def_sig_inner(&self, def_idx: usize) -> Result<ManagedMethod<MethodType>> {
        let (blob_idx, is_static) = self.sig_pending_def[def_idx];
        let ctx = self.make_ctx();
        let mut sig =
            convert::read::managed_method(self.blobs.at_index(blob_idx)?.pread(0).map_err(CLI)?, &ctx)?;
        if is_static {
            sig.instance = false;
        }
        Ok(sig)
    }

    /// Decode the signature for method ref at `ref_idx`, or return a cached result.
    ///
    /// On decode failure the `OnceLock` cell is left empty so the next call retries.
    pub fn decode_method_ref_sig(&self, ref_idx: usize) -> Result<&ManagedMethod<MethodType>> {
        if let Some(cached) = self.sig_cache_ref[ref_idx].get() {
            return Ok(cached);
        }
        let sig = self.decode_method_ref_sig_inner(ref_idx)?;
        let _ = self.sig_cache_ref[ref_idx].set(sig);
        Ok(self.sig_cache_ref[ref_idx].get().unwrap())
    }

    fn decode_method_ref_sig_inner(&self, ref_idx: usize) -> Result<ManagedMethod<MethodType>> {
        let blob_idx = self.sig_pending_ref[ref_idx];
        let sig_blob = self.blobs.at_index(blob_idx)?;
        let ref_sig: MethodRefSig = sig_blob.pread(0).map_err(CLI)?;
        let ctx = self.make_ctx();
        let mut signature = convert::read::managed_method(ref_sig.method_def, &ctx)?;
        if signature.calling_convention == CallingConvention::Vararg {
            let mut varargs = Vec::with_capacity(ref_sig.varargs.len());
            for p in ref_sig.varargs {
                varargs.push(convert::read::parameter(p, &ctx)?);
            }
            signature.varargs = Some(varargs);
        }
        Ok(signature)
    }

    fn raw_to_attrs(&self, raw: &[AttrRaw]) -> Result<Vec<crate::resolved::attribute::Attribute<'a>>> {
        use crate::resolved::attribute::Attribute;
        raw.iter()
            .map(|&(constructor, blob_idx)| {
                let value = match blob_idx {
                    Some(idx) => Some(std::borrow::Cow::Borrowed(self.blobs.at_index(idx)?)),
                    None => None,
                };
                Ok(Attribute { constructor, value })
            })
            .collect()
    }

    pub fn type_attributes(
        &self,
        type_def_idx: usize,
    ) -> Result<Vec<crate::resolved::attribute::Attribute<'a>>> {
        self.raw_to_attrs(self.attr_by_type.get(&type_def_idx).map_or(&[], Vec::as_slice))
    }

    pub fn method_attributes(
        &self,
        method_def_idx: usize,
    ) -> Result<Vec<crate::resolved::attribute::Attribute<'a>>> {
        self.raw_to_attrs(self.attr_by_method.get(&method_def_idx).map_or(&[], Vec::as_slice))
    }

    pub fn field_attributes(
        &self,
        field_def_idx: usize,
    ) -> Result<Vec<crate::resolved::attribute::Attribute<'a>>> {
        self.raw_to_attrs(self.attr_by_field.get(&field_def_idx).map_or(&[], Vec::as_slice))
    }

    pub fn assembly_attributes(&self) -> Result<Vec<crate::resolved::attribute::Attribute<'a>>> {
        self.raw_to_attrs(&self.attr_by_assembly)
    }

    fn make_ctx(&self) -> convert::read::Context<'_, 'a> {
        convert::read::Context {
            def_len: self.def_len,
            ref_len: self.ref_len,
            specs: &self.specs,
            sigs: &self.sigs,
            blobs: &self.blobs,
            userstrings: &self.userstrings,
        }
    }

    fn decode_body_inner(&self, def_idx: usize) -> Result<body::Method> {
        let pending = self.pending[def_idx].as_ref().ok_or_else(|| {
            CLI(scroll::Error::Custom(format!(
                "method_def[{}] has no body (rva == 0)",
                def_idx
            )))
        })?;

        let raw_body: method::Method = pending.bytes.pread(pending.offset).map_err(CLI)?;

        let ctx = self.make_ctx();
        let m_ctx = convert::read::MethodContext {
            field_map: &self.field_map,
            field_indices: &self.field_indices,
            method_specs: &self.method_spec_table,
            method_indices: &self.method_indices,
            method_map: &self.method_map,
        };

        decode_body_with_ctx(raw_body, &ctx, &m_ctx)
    }
}

/// Decode a pre-parsed method body using the given read contexts.
/// Shared between the lazy decode path and the eager rayon parallel path.
pub(crate) fn decode_body_with_ctx(
    raw_body: method::Method,
    ctx: &convert::read::Context<'_, '_>,
    m_ctx: &convert::read::MethodContext<'_>,
) -> Result<body::Method> {
    let header = match raw_body.header {
        method::Header::Tiny { .. } => body::Header {
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
                let tok: Token = local_var_sig_tok.to_le_bytes().pread(0).map_err(CLI)?;
                if matches!(tok.target, TokenTarget::Table(Kind::StandAloneSig))
                    && tok.index <= ctx.sigs.len()
                {
                    let vars: LocalVarSig = ctx
                        .blobs
                        .at_index(ctx.sigs[tok.index - 1].signature)?
                        .pread(0)
                        .map_err(CLI)?;

                    let mut lv = Vec::with_capacity(vars.0.len());
                    for v in vars.0 {
                        lv.push(match v {
                            LocalVar::TypedByRef => LocalVariable::TypedReference,
                            LocalVar::Variable {
                                custom_modifiers,
                                pinned,
                                by_ref,
                                var_type,
                            } => {
                                let mut cmods = Vec::with_capacity(custom_modifiers.len());
                                for c in custom_modifiers {
                                    cmods.push(convert::read::custom_modifier(c, ctx)?);
                                }
                                LocalVariable::Variable {
                                    custom_modifiers: cmods,
                                    pinned,
                                    by_ref,
                                    var_type: MethodType::from_sig(var_type, ctx)?,
                                }
                            }
                        });
                    }
                    lv
                } else {
                    return Err(CLI(scroll::Error::Custom(format!(
                        "invalid local variable signature token {:?}",
                        tok
                    ))));
                }
            };
            body::Header {
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
            let o = init_offset;
            init_offset += i.bytesize();
            o
        })
        .collect();

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
                        CLI(scroll::Error::Custom(format!(
                            "could not find corresponding instruction for {} offset {}",
                            $name, $byte
                        )))
                    })?
            }
        }};
    }

    let mut data_sections = Vec::with_capacity(raw_body.data_sections.len());
    for d in raw_body.data_sections {
        use crate::binary::method::SectionKind;
        data_sections.push(match d.section {
            SectionKind::Exceptions(e) => {
                let mut exceptions = Vec::with_capacity(e.len());
                for h in e {
                    let kind = match h.flags {
                        0 => body::ExceptionKind::TypedException(convert::read::type_token(
                            h.class_token_or_filter
                                .to_le_bytes()
                                .pread::<Token>(0)
                                .map_err(CLI)?,
                            ctx,
                        )?),
                        1 => body::ExceptionKind::Filter {
                            offset: get_offset!(h.class_token_or_filter, "filter"),
                        },
                        2 => body::ExceptionKind::Finally,
                        4 => body::ExceptionKind::Fault,
                        bad => {
                            return Err(CLI(scroll::Error::Custom(format!(
                                "invalid exception clause type {:#06x}",
                                bad
                            ))))
                        }
                    };

                    let try_offset = get_offset!(h.try_offset, "try");
                    let handler_offset = get_offset!(h.handler_offset, "handler");

                    exceptions.push(body::Exception {
                        kind,
                        try_offset,
                        try_length: get_offset!(h.try_offset + h.try_length, "try") - try_offset,
                        handler_offset,
                        handler_length: get_offset!(h.handler_offset + h.handler_length, "handler")
                            - handler_offset,
                    });
                }
                body::DataSection::ExceptionHandlers(exceptions)
            }
            SectionKind::Unrecognized { is_fat, length } => body::DataSection::Unrecognized {
                fat: is_fat,
                size: length,
            },
        });
    }

    let mut instrs = Vec::with_capacity(raw_instrs.len());
    for (idx, i) in raw_instrs.into_iter().enumerate() {
        instrs.push(convert::read::instruction(i, idx, &instr_offsets, ctx, m_ctx)?);
    }

    Ok(body::Method {
        header,
        instructions: instrs,
        data_sections,
    })
}
