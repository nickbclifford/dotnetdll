pub mod read;

#[cfg(test)]
mod tests {
    use super::*;
    use scroll::Pread;

    #[test]
    fn parse() -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::read("/usr/share/dotnet/sdk/5.0.203/System.Text.Json.dll")?;
        let dll = read::dll::DLL::parse(&file)?;
        let offset = dll.get_stream_offset("#~")?;
        let m_header: read::metadata::header::Header = file[offset..].pread(0)?;
        println!("{:#?}", m_header);
        Ok(())
    }
}
