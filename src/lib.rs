pub mod read;

#[cfg(test)]
mod tests {
    use crate::read::{heap::Heap, *};
    use scroll::Pread;

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.203/System.Text.Json.dll")?;
        let dll = dll::DLL::parse(&file)?;
        let strings = dll.get_stream_offset("#Strings")?;
        let heap = heap::Strings::new(&file, strings);
        let meta = dll.get_stream_offset("#~")?;
        let header: metadata::header::Header = file.pread(meta)?;
        for table in header.tables {
            use metadata::table::Table::*;
            match table {
                TypeDef(t) => {
                    println!(
                        "{}.{}",
                        heap.at_index(t.type_namespace)?,
                        heap.at_index(t.type_name)?
                    )
                }
                _ => {}
            }
        }
        Ok(())
    }
}
