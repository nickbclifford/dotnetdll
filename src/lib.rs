pub mod read;

#[cfg(test)]
mod tests {
    use crate::read::*;

    use heap::Heap;
    use metadata::table::Table::*;

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.203/System.Text.Json.dll")?;
        let dll = dll::DLL::parse(&file)?;
        let strs: heap::Strings = dll.get_heap("#Strings")?;
        let meta = dll.get_logical_metadata()?;
        for table in meta.tables {
            match table {
                TypeDef(t) => {
                    println!("{}.{} extends {:?}", strs.at_index(t.type_namespace)?, strs.at_index(t.type_name)?, t.extends);
                },
                _ => {}
            }
        }
        Ok(())
    }
}
