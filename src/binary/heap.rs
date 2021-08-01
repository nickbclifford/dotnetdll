use super::{metadata::index, signature::compressed};
use scroll::{ctx::StrCtx, Pread, Pwrite, Result};

pub trait Heap<'a> {
    type Index;
    type Value;

    fn new(bytes: &'a [u8]) -> Self;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value>;

    // TODO: mutating internal buffer?
    fn write(value: Self::Value) -> Result<Vec<u8>>;
}

macro_rules! heap_struct {
    ($name:ident, { $($i:item)* }) => {
        pub struct $name<'a> {
            bytes: &'a [u8],
        }

        impl<'a> Heap<'a> for $name<'a> {
            fn new(bytes: &'a [u8]) -> $name<'a> {
                $name {
                    bytes: &bytes,
                }
            }

            $($i)*
        }
    };
}

fn read_bytes(bytes: &[u8], idx: usize) -> Result<&[u8]> {
    let mut offset = idx;

    let compressed::Unsigned(size) = bytes.gread(&mut offset)?;

    bytes.pread_with(offset, size as usize)
}

fn write_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let len = bytes.len();

    let mut buf = vec![0_u8; len];

    let len_size = buf.pwrite(compressed::Unsigned(len as u32), 0)?;

    buf.extend(vec![0_u8; len_size]);

    buf.pwrite(bytes, len_size)?;

    Ok(buf)
}

heap_struct!(Strings, {
    type Index = index::String;
    type Value = &'a str;

    fn at_index(&self, index::String(idx): Self::Index) -> Result<Self::Value> {
        self.bytes.pread_with(idx, StrCtx::Delimiter(0))
    }

    fn write(value: Self::Value) -> Result<Vec<u8>> {
        let mut buf = vec![0_u8; value.len() + 1];

        buf.pwrite(value.as_bytes(), 0)?;

        // null terminator included in buffer

        Ok(buf)
    }
});
heap_struct!(Blob, {
    type Index = index::Blob;
    type Value = &'a [u8];

    fn at_index(&self, index::Blob(idx): Self::Index) -> Result<Self::Value> {
        read_bytes(self.bytes, idx)
    }

    fn write(value: Self::Value) -> Result<Vec<u8>> {
        write_bytes(value)
    }
});
heap_struct!(GUID, {
    type Index = index::GUID;
    type Value = [u8; 16];

    fn at_index(&self, index::GUID(idx): Self::Index) -> Result<Self::Value> {
        let mut buf = [0_u8; 16];
        self.bytes
            .gread_inout_with(&mut ((idx - 1) * 16), &mut buf, scroll::LE)?;
        Ok(buf)
    }

    fn write(value: Self::Value) -> Result<Vec<u8>> {
        Ok(value.to_vec())
    }
});
heap_struct!(UserString, {
    type Index = usize;
    type Value = Vec<u16>;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value> {
        let bytes = read_bytes(self.bytes, idx)?;

        let num_utf16 = (bytes.len() - 1) / 2;
        let offset = &mut 0;
        let chars = (0..num_utf16)
            .map(|_| bytes.gread_with::<u16>(offset, scroll::LE))
            .collect::<Result<_>>()?;

        Ok(chars)
    }

    fn write(value: Self::Value) -> Result<Vec<u8>> {
        let final_byte: u8 = if value.iter().any(|u| {
            let [high, low] = u.to_le_bytes();
            high != 0 || matches!(low, 0x01..=0x08 | 0x0E..=0x1F | 0x27 | 0x2D | 0x7F)
        }) {
            1
        } else {
            0
        };

        write_bytes(
            &value
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .chain(std::iter::once(final_byte))
                .collect::<Vec<_>>(),
        )
    }
});
