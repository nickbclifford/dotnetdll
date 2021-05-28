use super::metadata::index;
use scroll::{ctx::StrCtx, Endian, Error, Pread};

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
        let mut offset = idx;
        let mut size = 0usize;

        let indicator = self.bytes.gread_with::<u8>(&mut offset, Endian::Little)? as usize;
        if (indicator >> 7) == 0 {
            size = indicator as usize;
        } else if (indicator >> 6) == 0b10 {
            let b2 = self.bytes.gread_with::<u8>(&mut offset, Endian::Little)? as usize;
            size = (((indicator & 0b111111) << 8) | b2) as usize;
        } else if (indicator >> 5) == 0b110 {
            let b2 = self.bytes.gread_with::<u8>(&mut offset, Endian::Little)? as usize;
            let b3 = self.bytes.gread_with::<u8>(&mut offset, Endian::Little)? as usize;
            let b4 = self.bytes.gread_with::<u8>(&mut offset, Endian::Little)? as usize;
            size = (((indicator & 0b11111) << 24) | (b2 << 16) | (b3 << 8) | b4) as usize;
        }

        Ok(self.bytes.pread_with(offset, size)?)
    }
});
heap_struct!(GUID, {
    type Index = index::GUID;
    type Value = u128;

    fn at_index(&self, index::GUID(idx): Self::Index) -> Result<Self::Value, Error> {
        Ok(self.bytes.pread_with(idx, Endian::Little)?)
    }
});
