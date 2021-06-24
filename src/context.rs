use super::binary::{heap, metadata::table::Tables};

pub struct Context<'a> {
    pub strings: heap::Strings<'a>,
    pub blobs: heap::Blob<'a>,
    pub guids: heap::GUID<'a>,
    pub userstrings: heap::UserString<'a>,
    pub tables: Tables,
}
