use super::{metadata::index, signature::compressed};
use scroll::{ctx::StrCtx, Pread, Result};

pub trait Heap<'a> {
    type Index;
    type Value;

    fn new(bytes: &'a [u8]) -> Self;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value>;
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

heap_struct!(Strings, {
    type Index = index::String;
    type Value = &'a str;

    fn at_index(&self, index::String(idx): Self::Index) -> Result<Self::Value> {
        self.bytes.pread_with(idx, StrCtx::Delimiter(0))
    }
});
heap_struct!(Blob, {
    type Index = index::Blob;
    type Value = &'a [u8];

    fn at_index(&self, index::Blob(idx): Self::Index) -> Result<Self::Value> {
        read_bytes(self.bytes, idx)
    }
});
heap_struct!(GUID, {
    type Index = index::GUID;
    type Value = [u8; 16];

    fn at_index(&self, index::GUID(idx): Self::Index) -> Result<Self::Value> {
        let mut buf = [0u8; 16];
        self.bytes
            .gread_inout_with(&mut ((idx - 1) * 16), &mut buf, scroll::LE)?;
        Ok(buf)
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
});
