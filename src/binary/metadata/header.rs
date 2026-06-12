use super::{
    index::{Sizes, TableRowCounts},
    table::{Kind, Tables},
};
use bitvec::access::BitSafeU8;
use bitvec::{order::Lsb0, store::BitStore, view::BitView};
use num_traits::{FromPrimitive, ToPrimitive};
use scroll::{
    ctx::{TryFromCtx, TryIntoCtx},
    Pread, Pwrite,
};
use scroll_buffer::DynamicBuffer;
use std::collections::HashMap;

/// Header of the `#~` logical metadata stream (metadata tables stream).
///
/// This is the binary prefix that declares table-presence bits, row counts,
/// heap index widths, and then the table row payloads themselves. In practice,
/// this struct is the root of the parsed metadata table graph in the binary
/// layer. See ECMA-335, II.24.2.6.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Header {
    /// Reserved field at the start of the stream header (must be zero).
    pub reserved0: u32,
    /// Major version of the metadata tables stream format.
    pub major_version: u8,
    /// Minor version of the metadata tables stream format.
    pub minor_version: u8,
    /// Heap-size flags for `#Strings`, `#GUID`, and `#Blob` indices.
    ///
    /// This is a 3-bit field: when a bit is set, indices into the corresponding
    /// heap are 4 bytes; otherwise they are 2 bytes.
    pub heap_sizes: u8,
    /// Reserved field after [`Header::heap_sizes`] (must be 1 in valid images).
    pub reserved1: u8,
    /// 64-bit bitmask of metadata tables present in this stream.
    ///
    /// For each set bit, the header stores one row count (in table-number order)
    /// before the table data begins.
    pub valid: u64,
    /// 64-bit bitmask declaring which present tables are guaranteed sorted.
    pub sorted: u64,
    /// Parsed rows for all metadata tables present in this stream.
    ///
    /// The set of populated tables is determined by [`Header::valid`], and each
    /// table length is encoded by the row-count array in the stream header.
    pub tables: Tables,
}

impl TryFromCtx<'_> for Header {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], (): ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let res0 = from.gread_with(offset, scroll::LE)?;
        let maj = from.gread_with(offset, scroll::LE)?;
        let min = from.gread_with(offset, scroll::LE)?;
        let heap: u8 = from.gread_with(offset, scroll::LE)?;
        let res1 = from.gread_with(offset, scroll::LE)?;
        let valid: u64 = from.gread_with(offset, scroll::LE)?;
        let sorted = from.gread_with(offset, scroll::LE)?;

        let mut rows = vec![0_u32; valid.count_ones() as usize];
        from.gread_inout_with(offset, &mut rows, scroll::LE)?;

        let mut kinds = vec![];
        for (num, exists) in valid.view_bits::<Lsb0>().into_iter().enumerate() {
            if *exists {
                kinds.push(Kind::from_usize(num).unwrap());
            }
        }
        let pairs: Vec<(Kind, u32)> = kinds.into_iter().zip(rows).collect();

        let mut sizes_arr = [0u32; 45];
        for &(kind, size) in &pairs {
            sizes_arr[kind as usize] = size;
        }
        let table_sizes = TableRowCounts::from(sizes_arr);

        let heap_bits = BitSafeU8::new(heap);
        let ctx = Sizes {
            heap: heap_bits.view_bits::<Lsb0>(),
            tables: &table_sizes,
        };

        let mut tables = Tables::new();

        // NOTE: this would be easy to parallelize and is the main read bottleneck
        for (kind, size) in pairs {
            tables_kind_reserve!(tables, kind, size as usize);
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
impl TryIntoCtx<(), DynamicBuffer> for Header {
    type Error = scroll::Error;

    fn try_into_ctx(mut self, into: &mut DynamicBuffer, (): ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        into.gwrite_with(self.reserved0, offset, scroll::LE)?;
        into.gwrite_with(self.major_version, offset, scroll::LE)?;
        into.gwrite_with(self.minor_version, offset, scroll::LE)?;
        into.gwrite_with(self.heap_sizes, offset, scroll::LE)?;
        into.gwrite_with(self.reserved1, offset, scroll::LE)?;
        into.gwrite_with(self.valid, offset, scroll::LE)?;
        into.gwrite_with(self.sorted, offset, scroll::LE)?;

        let mut sizes_arr = [0u32; 45];
        for_each_table!(self.tables, |t, k| {
            sizes_arr[k as usize] = t.len() as u32;
        });
        let table_sizes = TableRowCounts::from(sizes_arr);

        let heap_bits = BitSafeU8::new(self.heap_sizes);
        let ctx = Sizes {
            heap: heap_bits.view_bits::<Lsb0>(),
            tables: &table_sizes,
        };

        let mut tables_map = HashMap::new();

        // ECMA-335, II.22 (page 210)
        self.tables.sort();

        // callers must make sure that TypeDefs that enclose any types
        // precede their nested types (ECMA-335, II.22, page 210)

        let mut buf = [0_u8; 32];
        for_each_row!(self.tables, |r, k| {
            let mut offset = 0;
            buf.gwrite_with(r, &mut offset, ctx)?;
            tables_map
                .entry(k.to_u8().unwrap())
                .or_insert_with(Vec::new)
                .extend_from_slice(&buf[..offset]);
        });

        // sizes_arr is indexed by discriminant value, so iterating 0..45 is already sorted
        for &size in sizes_arr.iter() {
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
