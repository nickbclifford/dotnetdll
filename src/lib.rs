pub mod read;

#[cfg(test)]
mod tests {
    use crate::read::*;

    use heap::Heap;
    use metadata::table::*;

    macro_rules! name_impl {
        ($t:ident) => {
            impl $t {
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

        let method_len = meta.tables.method_def.len();

        for (t_idx, row) in meta.tables.type_def.iter().enumerate() {
            let name = row.type_name(&strs);
            if name.starts_with(".") {
                continue;
            }
            if let Some(idx) = row.method_list.0 {
                println!("type name: {} ", name);
                let last_method = std::cmp::min(
                    method_len,
                    meta.tables
                        .type_def
                        .get(t_idx) // skip index 0, which is .<Module>
                        .and_then(|t| t.method_list.0)
                        .unwrap_or(method_len),
                );

                for method in &meta.tables.method_def[idx..last_method] {
                    println!("\thas method {}", strs.at_index(method.name)?);
                    let m_data = dll.get_method(&method)?;
                    if !m_data.data_sections.is_empty() {
                        println!("\t\thas exception handlers");
                    }
                }
            }
        }
        Ok(())
    }

    use scroll::Pread;
    use signature::compressed::*;

    #[test]
    fn decompress() {
        let Unsigned(u1) = [0x03].pread(0).unwrap();
        assert_eq!(u1, 0x03);
        let Unsigned(u2) = [0xBF, 0xFF].pread(0).unwrap();
        assert_eq!(u2, 0x3FFF);
        let Unsigned(u4) = [0xC0, 0x00, 0x40, 0x00].pread(0).unwrap();
        assert_eq!(u4, 0x4000);
        let Signed(sp1) = [0x06].pread(0).unwrap();
        assert_eq!(sp1, 3);
        let Signed(sn1) = [0x7B].pread(0).unwrap();
        assert_eq!(sn1, -3);
        let Signed(sp2) = [0x80, 0x80].pread(0).unwrap();
        assert_eq!(sp2, 64);
        let Signed(sn2) = [0x80, 0x01].pread(0).unwrap();
        assert_eq!(sn2, -8192);
        let Signed(sp4) = [0xDF, 0xFF, 0xFF, 0xFE].pread(0).unwrap();
        assert_eq!(sp4, 268435455);
        let Signed(sn4) = [0xC0, 0x00, 0x00, 0x01].pread(0).unwrap();
        assert_eq!(sn4, -268435456);
    }
}
