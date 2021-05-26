use super::{
    index::{Context, Sizes},
    table::*,
};
use bitvec::order::Lsb0;
use bitvec::view::BitView;
use num_traits::FromPrimitive;
use scroll::{ctx::TryFromCtx, Endian, Pread};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Header {
    pub reserved0: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub heap_sizes: u8,
    pub reserved1: u8,
    pub valid: u64,
    pub sorted: u64,
    pub rows: Vec<u32>,
    pub tables: Vec<Table>,
}

impl TryFromCtx<'_, Endian> for Header {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], ctx: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let res0 = from.gread_with(offset, ctx)?;
        let maj = from.gread_with(offset, ctx)?;
        let min = from.gread_with(offset, ctx)?;
        let heap: u8 = from.gread_with(offset, ctx)?;
        let res1 = from.gread_with(offset, ctx)?;
        let valid: u64 = from.gread_with(offset, ctx)?;
        let sorted = from.gread_with(offset, ctx)?;

        let mut rows = vec![0; valid.count_ones() as usize];
        from.gread_inout_with(offset, &mut rows, ctx)?;

        let mut kinds = vec![];
        for (num, exists) in valid.view_bits::<Lsb0>().into_iter().enumerate() {
            if *exists {
                kinds.push(Kind::from_usize(num).unwrap());
            }
        }
        let iter = kinds.into_iter().zip(rows.iter());
        let sizes_map: HashMap<_, _> = iter.clone().map(|(k, &i)| (k, i)).collect();

        let meta_ctx = Context(
            ctx,
            Sizes {
                heap: heap.view_bits::<Lsb0>(),
                tables: &sizes_map,
            },
        );

        let mut tables = vec![];
        for (kind, size) in iter {
            for _ in 0..*size {
                tables.push(build_match!(kind, from, offset, meta_ctx));
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
                rows,
                tables,
            },
            *offset,
        ))
    }
}
