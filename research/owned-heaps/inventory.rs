use dotnetdll::dll::DLL;
use std::hash::Hasher;
fn main() {
    let bytes = std::fs::read(std::env::args().nth(1).expect("DLL path")).unwrap();
    let dll = DLL::parse(&bytes).unwrap();
    let (_, _, _, _, logical) = dll.get_all_streams().unwrap();
    let t = logical.tables;
    println!(
        "bytes={} types={} type_refs={} fields={} methods={} parameters={} member_refs={} properties={} events={} attributes={} field_rvas={} resources={} body_slices={} type_specs={} standalone_sigs={}",
        bytes.len(),
        t.type_def.len(),
        t.type_ref.len(),
        t.field.len(),
        t.method_def.len(),
        t.param.len(),
        t.member_ref.len(),
        t.property.len(),
        t.event.len(),
        t.custom_attribute.len(),
        t.field_rva.len(),
        t.manifest_resource.len(),
        t.method_def.iter().filter(|m| m.rva != 0).count(),
        t.type_spec.len(),
        t.stand_alone_sig.len()
    );
    for h in dll.get_cli_metadata().unwrap().stream_headers {
        let data = dll
            .at_rva(&dotnetdll::binary::cli::RVASize {
                rva: dll.cli.metadata.rva + h.offset,
                size: h.size,
            })
            .unwrap();
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        hash.write(data);
        println!("{} {} bytes hash={:016x}", h.name, h.size, hash.finish());
    }
}
