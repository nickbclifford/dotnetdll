pub mod read;

#[cfg(test)]
mod tests {
    use crate::read::*;

    use heap::Heap;
    use metadata::table::*;

    trait HasTypeName {
        fn type_name(&self, heap: &heap::Strings) -> String;
    }

    macro_rules! name_impl {
        ($t:ident) => {
            impl HasTypeName for $t {
                fn type_name(&self, heap: &heap::Strings) -> String {
                    format!(
                        "{}.{}",
                        heap.at_index(self.type_namespace).unwrap(),
                        heap.at_index(self.type_name).unwrap()
                    )
                }
            }
        };
    }

    name_impl!(TypeDef);
    name_impl!(TypeRef);

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.203/Newtonsoft.Json.dll")?;
        let dll = dll::DLL::parse(&file)?;
        let strs: heap::Strings = dll.get_heap("#Strings")?;
        let meta = dll.get_logical_metadata()?;

        for row in meta.tables[&Kind::TypeDef].iter() {
            match row {
                Table::TypeDef(t) => {
                    print!("type name: {} ", t.type_name(&strs));
                    match t.extends.0 {
                        Some((idx, kind)) => match &meta.tables[&kind][idx.saturating_sub(1)] {
                            Table::TypeDef(t) => print!("extends {}", t.type_name(&strs)),
                            Table::TypeRef(t) => print!("extends {}", t.type_name(&strs)),
                            _ => {}
                        },
                        None => {
                            print!("nah")
                        }
                    }
                    println!();
                }
                _ => {}
            }
        }
        Ok(())
    }
}
