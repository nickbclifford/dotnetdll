use super::{metadata::index, signature::compressed};
use scroll::{ctx::StrCtx, Pread, Pwrite, Result};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::*,
};

pub trait HeapReader<'a> {
    type Index;
    type Value;

    fn new(bytes: &'a [u8]) -> Self;

    fn at_index(&self, idx: Self::Index) -> Result<Self::Value>;
}

macro_rules! heap_reader {
    ($name:ident, { $($i:item)* }) => {
        pub struct $name<'a> {
            bytes: &'a [u8],
        }

        impl<'a> HeapReader<'a> for $name<'a> {
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

heap_reader!(StringsReader, {
    type Index = index::String;
    type Value = &'a str;

    fn at_index(&self, index::String(idx): Self::Index) -> Result<Self::Value> {
        self.bytes.pread_with(idx, StrCtx::Delimiter(0))
    }
});
heap_reader!(BlobReader, {
    type Index = index::Blob;
    type Value = &'a [u8];

    fn at_index(&self, index::Blob(idx): Self::Index) -> Result<Self::Value> {
        read_bytes(self.bytes, idx)
    }
});
heap_reader!(GUIDReader, {
    type Index = index::GUID;
    type Value = [u8; 16];

    fn at_index(&self, index::GUID(idx): Self::Index) -> Result<Self::Value> {
        let mut buf = [0_u8; 16];
        self.bytes
            .gread_inout_with(&mut ((idx - 1) * 16), &mut buf, scroll::LE)?;
        Ok(buf)
    }
});
heap_reader!(UserStringReader, {
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

pub trait HeapWriter {
    type Index;
    type Value: ?Sized;

    fn new() -> Self;

    fn write(&mut self, value: &Self::Value) -> Result<Self::Index>;

    fn into_vec(self) -> Vec<u8>;
}

fn hash(val: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    val.hash(&mut hasher);
    hasher.finish()
}

macro_rules! heap_writer {
    ($name:ident, ($buf:expr, $map:expr), $index:ty, $value:ty, |$s:ident, $n:ident| $e:expr) => {
        pub struct $name {
            buffer: Vec<u8>,
            index_cache: HashMap<u64, <Self as HeapWriter>::Index>,
        }

        impl HeapWriter for $name {
            type Index = $index;
            type Value = $value;

            fn new() -> Self {
                $name {
                    buffer: $buf,
                    index_cache: $map,
                }
            }

            fn into_vec(self) -> Vec<u8> {
                self.buffer
            }

            fn write(&mut $s, $n: &Self::Value) -> Result<Self::Index> {
                let h = hash($n);

                Ok(match $s.index_cache.get(&h) {
                    Some(&i) => i,
                    None => {
                        let idx = $e;
                        $s.index_cache.insert(h, idx);
                        idx
                    }
                })
            }
        }
    };
}

heap_writer!(
    StringsWriter,
    (vec![0], HashMap::from([(hash(""), 0.into())])),
    index::String,
    str,
    |self, value| {
        let start = self.buffer.len();
        self.buffer.extend(value.as_bytes());
        self.buffer.push(0u8);
        index::String(start)
    }
);
heap_writer!(
    BlobWriter,
    (vec![0], HashMap::from([(hash(&[] as &Self::Value), 0.into())])),
    index::Blob,
    [u8],
    |self, value| {
        let start = self.buffer.len();
        self.buffer.extend(write_bytes(value)?);
        index::Blob(start)
    }
);
heap_writer!(
    GUIDWriter,
    (vec![], HashMap::new()),
    index::GUID,
    [u8; 16],
    |self, value| {
        let start = self.buffer.len();
        self.buffer.extend(value);
        index::GUID((start + 1) / 16)
    }
);
heap_writer!(
    UserStringWriter,
    (vec![0], HashMap::from([(hash(&[] as &Self::Value), 0)])),
    usize,
    [u16],
    |self, value| {
        let final_byte: u8 = if value.iter().any(|u| {
            let [high, low] = u.to_le_bytes();
            high != 0 || matches!(low, 0x01..=0x08 | 0x0E..=0x1F | 0x27 | 0x2D | 0x7F)
        }) {
            1
        } else {
            0
        };

        let start = self.buffer.len();
        self.buffer.extend(write_bytes(
            &value
                .into_iter()
                .flat_map(|&u| u.to_le_bytes())
                .chain(std::iter::once(final_byte))
                .collect::<Vec<_>>(),
        )?);
        start
    }
);
