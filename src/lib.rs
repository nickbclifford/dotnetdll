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
        let strs = dll.get_heap("#Strings")?;
        let meta = dll.get_logical_metadata()?;

        for row in meta.tables.type_def.iter() {
            print!("type name: {} ", row.type_name(&strs));
            match row.extends.0 {
                Some((idx, kind)) => {
                    if idx != 0 {
                        match kind {
                            Kind::TypeDef => {
                                print!("extends {}", meta.tables.type_def[idx - 1].type_name(&strs))
                            }
                            Kind::TypeRef => {
                                print!("extends {}", meta.tables.type_ref[idx - 1].type_name(&strs))
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            println!();
        }
        Ok(())
    }
}
