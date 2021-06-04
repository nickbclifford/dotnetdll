use super::{metadata::index, signature::compressed};
use scroll::{ctx::StrCtx, Error, Pread};

pub trait Heap<'a> {
    type Index;
    type Value;

    fn new(bytes: &'a [u8]) -> Self;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value, Error>;
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

fn read_bytes(bytes: &[u8], idx: usize) -> Result<&[u8], Error> {
    let mut offset = idx;

    let compressed::Unsigned(size) = bytes.gread(&mut offset)?;

    bytes.pread_with(offset, size as usize)
}

heap_struct!(Strings, {
    type Index = index::String;
    type Value = &'a str;

    fn at_index(&self, index::String(idx): Self::Index) -> Result<Self::Value, Error> {
        self.bytes.pread_with(idx, StrCtx::Delimiter(0))
    }
});
heap_struct!(Blob, {
    type Index = index::Blob;
    type Value = &'a [u8];

    fn at_index(&self, index::Blob(idx): Self::Index) -> Result<Self::Value, Error> {
        read_bytes(self.bytes, idx)
    }
});
heap_struct!(GUID, {
    type Index = index::GUID;
    type Value = u128;

    fn at_index(&self, index::GUID(idx): Self::Index) -> Result<Self::Value, Error> {
        self.bytes.pread_with((idx - 1) * 16, scroll::LE)
    }
});
heap_struct!(UserString, {
    type Index = usize;
    type Value = String;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value, Error> {
        let bytes = read_bytes(self.bytes, idx)?;

        let num_utf16 = (bytes.len() - 1) / 2;
        let offset = &mut 0;
        let mut chars = vec![];
        for _ in 0..num_utf16 {
            chars.push(bytes.gread_with::<u16>(offset, scroll::LE)?);
        }

        String::from_utf16(&chars).map_err(|e| scroll::Error::Custom(e.to_string()))
    }
});
