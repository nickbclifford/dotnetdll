use std::sync::OnceLock;

use rustc_hash::FxHashMap;
use scroll::Pread;

use crate::{
    binary::{
        heap::{BlobReader, Reader, UserStringReader},
        metadata::{
            index::{Token, TokenTarget},
            table::{Kind, MethodSpec, StandAloneSig, TypeSpec},
        },
        method,
        signature::kinds::{LocalVar, LocalVarSig},
    },
    convert::{self, TypeKind},
    dll::{DLLError::*, Result},
    resolved::{
        body,
        types::{LocalVariable, MethodType},
        *,
    },
};

use super::{FieldIndex, MethodIndex};

/// Raw bytes and alignment offset for a single method, captured at parse time.
pub(crate) struct MethodPendingRaw<'a> {
    pub bytes: &'a [u8],
    pub offset: usize,
}

/// All context needed to decode method bodies on demand, shared across `Resolution` clones.
#[allow(dead_code)]
pub(crate) struct LazyParseState<'a> {
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
    // Per-method: [method_def_idx] -> raw bytes (None for abstract/rva==0)
    pub pending: Vec<Option<MethodPendingRaw<'a>>>,
    /// MethodIndex -> method_def_idx (inverse of method_indices for non-abstract methods)
    pub method_idx_to_def: FxHashMap<MethodIndex, usize>,
    /// [method_def_idx] -> decoded body; shared across all Resolution clones via Arc
    pub body_cache: Vec<OnceLock<body::Method>>,
}

impl<'a> std::fmt::Debug for LazyParseState<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyParseState")
            .field("def_len", &self.def_len)
            .field("ref_len", &self.ref_len)
            .field("pending_count", &self.pending.iter().filter(|p| p.is_some()).count())
            .field("cached_count", &self.body_cache.iter().filter(|c| c.get().is_some()).count())
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

    fn decode_body_inner(&self, def_idx: usize) -> Result<body::Method> {
        let pending = self.pending[def_idx].as_ref().ok_or_else(|| {
            CLI(scroll::Error::Custom(format!(
                "method_def[{}] has no body (rva == 0)",
                def_idx
            )))
        })?;

        let raw_body: method::Method = pending.bytes.pread(pending.offset).map_err(CLI)?;

        let ctx = convert::read::Context {
            def_len: self.def_len,
            ref_len: self.ref_len,
            specs: &self.specs,
            sigs: &self.sigs,
            blobs: &self.blobs,
            userstrings: &self.userstrings,
        };
        let m_ctx = convert::read::MethodContext {
            field_map: &self.field_map,
            field_indices: &self.field_indices,
            method_specs: &self.method_spec_table,
            method_indices: &self.method_indices,
            method_map: &self.method_map,
        };

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
                        && tok.index <= self.sigs.len()
                    {
                        let vars: LocalVarSig = self
                            .blobs
                            .at_index(self.sigs[tok.index - 1].signature)?
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
                                        cmods.push(convert::read::custom_modifier(c, &ctx)?);
                                    }
                                    LocalVariable::Variable {
                                        custom_modifiers: cmods,
                                        pinned,
                                        by_ref,
                                        var_type: MethodType::from_sig(var_type, &ctx)?,
                                    }
                                }
                            });
                        }
                        lv
                    } else {
                        return Err(CLI(scroll::Error::Custom(format!(
                            "invalid local variable signature token {:?} for method_def[{}]",
                            tok, def_idx
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
                                &ctx,
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
                            try_length: get_offset!(h.try_offset + h.try_length, "try")
                                - try_offset,
                            handler_offset,
                            handler_length: get_offset!(
                                h.handler_offset + h.handler_length,
                                "handler"
                            ) - handler_offset,
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
            instrs.push(convert::read::instruction(i, idx, &instr_offsets, &ctx, &m_ctx)?);
        }

        Ok(body::Method {
            header,
            instructions: instrs,
            data_sections,
        })
    }
}
