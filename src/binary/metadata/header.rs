use super::{
    index::Sizes,
    table::{Kind, Tables},
};
use bitvec::{order::Lsb0, view::BitView};
use num_traits::{FromPrimitive, ToPrimitive};
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};
use std::collections::HashMap;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Header {
    pub reserved0: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub heap_sizes: u8,
    pub reserved1: u8,
    pub valid: u64,
    pub sorted: u64,
    pub tables: Tables,
}

impl TryFromCtx<'_> for Header {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let res0 = from.gread_with(offset, scroll::LE)?;
        let maj = from.gread_with(offset, scroll::LE)?;
        let min = from.gread_with(offset, scroll::LE)?;
        let heap: u8 = from.gread_with(offset, scroll::LE)?;
        let res1 = from.gread_with(offset, scroll::LE)?;
        let valid: u64 = from.gread_with(offset, scroll::LE)?;
        let sorted = from.gread_with(offset, scroll::LE)?;

        let mut rows = vec![0u32; valid.count_ones() as usize];
        from.gread_inout_with(offset, &mut rows, scroll::LE)?;

        let mut kinds = vec![];
        for (num, exists) in valid.view_bits::<Lsb0>().into_iter().enumerate() {
            if *exists {
                kinds.push(Kind::from_usize(num).unwrap());
            }
        }
        let iter = kinds.into_iter().zip(rows.into_iter());
        let sizes_map: HashMap<_, _> = iter.clone().collect();

        let ctx = Sizes {
            heap: heap.view_bits::<Lsb0>(),
            tables: &sizes_map,
        };

        let mut tables = Tables::new();

        for (kind, size) in iter {
            for _ in 0..size {
                tables_kind_push!(tables, kind, from.gread_with(offset, ctx)?);
            }
        }

        Ok((
            Header {
                reserved0: res0,
                major_version: maj,
                minor_version: min,
                heap_sizes: heap,
                reserved1: res1,
                valid,
                sorted,
                tables,
            },
            *offset,
        ))
    }
}
impl TryIntoCtx for Header {
    type Error = scroll::Error;

    fn try_into_ctx(mut self, into: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(self.reserved0, offset, scroll::LE)?;
        into.gwrite_with(self.major_version, offset, scroll::LE)?;
        into.gwrite_with(self.minor_version, offset, scroll::LE)?;
        into.gwrite_with(self.heap_sizes, offset, scroll::LE)?;
        into.gwrite_with(self.reserved1, offset, scroll::LE)?;
        into.gwrite_with(self.valid, offset, scroll::LE)?;
        into.gwrite_with(self.sorted, offset, scroll::LE)?;

        let mut sizes_map = HashMap::new();

        for_each_table!(self.tables, |t, k| {
            sizes_map.insert(k, t.len() as u32);
        });

        let ctx = Sizes {
            heap: self.heap_sizes.view_bits::<Lsb0>(),
            tables: &sizes_map,
        };

        let mut tables_map = HashMap::new();

        // ECMA-335, II.22 (page 210)
        self.tables.class_layout.sort_by_key(|r| r.parent);
        self.tables.constant.sort_by_key(|r| r.parent);
        self.tables.custom_attribute.sort_by_key(|r| r.parent);
        self.tables.decl_security.sort_by_key(|r| r.parent);
        self.tables.field_layout.sort_by_key(|r| r.field);
        self.tables.field_marshal.sort_by_key(|r| r.parent);
        self.tables.field_rva.sort_by_key(|r| r.field);
        self.tables
            .generic_param
            .sort_by_key(|r| (r.owner, r.number));
        self.tables
            .generic_param_constraint
            .sort_by_key(|r| r.owner);
        self.tables.impl_map.sort_by_key(|r| r.member_forwarded);
        self.tables
            .interface_impl
            .sort_by_key(|r| (r.class, r.interface));
        self.tables.method_impl.sort_by_key(|r| r.class);
        self.tables.method_semantics.sort_by_key(|r| r.association);
        self.tables.nested_class.sort_by_key(|r| r.nested_class);

        // callers must make sure that TypeDefs that enclose any types
        // precede their nested types (ECMA-335, II.22, page 210)

        for_each_row!(self.tables, |r, k| {
            let mut buf = [0u8; 64];
            let mut offset = 0;
            buf.gwrite_with(r, &mut offset, ctx)?;
            tables_map
                .entry(k.to_u8().unwrap())
                .or_insert(vec![])
                .extend(&buf[..offset]);
        });

        let mut sizes: Vec<_> = sizes_map.into_iter().collect();
        sizes.sort_by_key(|&(k, _)| k.to_u8());
        for (_, size) in sizes {
            if size != 0 {
                into.gwrite_with(size, offset, scroll::LE)?;
            }
        }


        let mut all_tables: Vec<_> = tables_map.into_iter().collect();
        all_tables.sort_by_key(|&(k, _)| k);
        for (_, buffer) in all_tables {
            into.gwrite(&*buffer, offset)?;
        }

        Ok(*offset)
    }
}
