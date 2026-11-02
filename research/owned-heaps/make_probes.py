#!/usr/bin/env python3
"""Create disposable, instrumented crates; never modify the production parser.

python3 research/owned-heaps/make_probes.py /tmp/heap-classes
python3 research/owned-heaps/make_probes.py /tmp/heap-ranges --ranges

heap_probe arguments: DLL owned|borrowed all|strings|blobs|split
native_probe arguments: DLL iterations owned|borrowed consumer|production|eager|bodies
Set DOTNETDLL_PROBE_CLASS for native_probe class selection (use args for Miri).
"""
import argparse
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('destination', type=Path)
parser.add_argument('--ranges', action='store_true')
args = parser.parse_args()
dest = args.destination.resolve()
if dest.exists():
    raise SystemExit(f'{dest} already exists; choose an empty destination')
dest.mkdir(parents=True)
for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'src', 'dotnetdll-macros', 'examples', 'tests', 'benches']:
    source, target = ROOT / name, dest / name
    if source.is_dir():
        shutil.copytree(source, target, ignore=shutil.ignore_patterns('target', '.git'))
    else:
        shutil.copy2(source, target)

def change(path, old, new, count=1):
    p = dest / path
    s = p.read_text()
    assert s.count(old) == count, (path, old, s.count(old))
    p.write_text(s.replace(old, new))

read = 'src/resolution/read.rs'
change(read, "pub(crate) fn read_impl<'a>(dll: &DLL<'a>, opts: Options) -> Result<Resolution<'a>> {", """pub(crate) fn read_impl<'a>(dll: &DLL<'a>, opts: Options) -> Result<Resolution<'a>> {
    read_impl_split(dll, opts, None)
}
pub(crate) fn read_impl_split<'a>(dll: &DLL<'a>, opts: Options, heaps: Option<(&'a [u8], &'a [u8])>) -> Result<Resolution<'a>> {""")
change(read, '    let (strings, blobs, guids, userstrings, logical) = dll.get_all_streams()?;', '''    let (strings, blobs, guids, userstrings, logical) = dll.get_all_streams()?;
    let (strings, blobs) = match heaps {
        Some((s,b)) => (StringsReader::new(s), BlobReader::new(b)),
        None => (strings, blobs),
    };
    let class = std::env::var("DOTNETDLL_PROBE_CLASS")
        .unwrap_or_else(|_| std::env::args().nth(3).unwrap_or_default());''')
for heap, excluded in [('strings', 'blobs'), ('blobs', 'strings')]:
    change(read, f'        reader: {heap},\n        own: opts.own_heap_values,', f'        reader: {heap},\n        own: opts.own_heap_values && class != "{excluded}",')
p = dest / read
s = p.read_text()
a, b = s.index('macro_rules! stage_start {'), s.index('/// Minimum number', s.index('macro_rules! stage_start {'))
s = s[:a] + '''macro_rules! stage_start {
    ($start:ident) => { #[cfg(miri)] let $start = std::time::Instant::now(); };
}
macro_rules! stage_end {
    ($start:ident, $name:literal) => { #[cfg(miri)] eprintln!("STAGE {} {:?}", $name, $start.elapsed()); };
}

''' + s[b:]
p.write_text(s)
change('src/resolution/mod.rs', "    pub fn parse(bytes: &'a [u8], opts: ReadOptions)", """    pub fn parse_split(bytes: &'a [u8], opts: ReadOptions, strings: &'a [u8], blobs: &'a [u8]) -> crate::dll::Result<Self> {
        read::read_impl_split(&DLL::parse(bytes)?, opts, Some((strings, blobs)))
    }
    pub fn parse(bytes: &'a [u8], opts: ReadOptions)""")
heap_setup = '''    let split = std::env::var("DOTNETDLL_PROBE_CLASS")
        .unwrap_or_else(|_| std::env::args().nth(3).unwrap_or_default()) == "split";
    let dll = dotnetdll::dll::DLL::parse(&bytes).unwrap();
    let metadata = dll.get_cli_metadata().unwrap();
    let heap = |name: &str| {
        let h = metadata.stream_headers.iter().find(|h| h.name == name).unwrap();
        dll.at_rva(&dotnetdll::binary::cli::RVASize {
            rva: dll.cli.metadata.rva + h.offset, size: h.size
        }).unwrap().to_vec()
    };
    let strings = if split { heap("#Strings") } else { vec![] };
    let blobs = if split { heap("#Blob") } else { vec![] };
    let heaps = if split { Some((&strings[..], &blobs[..])) } else { None };
'''
helper = '''fn parse<'a>(bytes: &'a [u8], opts: ReadOptions, heaps: Option<(&'a [u8], &'a [u8])>) -> Resolution<'a> {
    match heaps { Some((s,b)) => Resolution::parse_split(bytes,opts,s,b), None => Resolution::parse(bytes,opts) }.unwrap()
}
'''
s = (HERE / 'parse_probe.rs').read_text()
s = s.replace('    let start =', heap_setup + '    let start =')
s = s.replace('Resolution::parse(&bytes, options).unwrap()', 'parse(&bytes, options, heaps)')
s = s.replace(')), own);', ')), own && std::env::args().nth(3).as_deref() != Some("blobs"));')
s = s.replace('fn main()', helper + 'fn main()')
s = s.replace('    let own =', '    eprintln!("CLASS={:?}", std::env::args().nth(3));\n    let own =')
(dest / 'examples/heap_probe.rs').write_text(s)
s = (HERE / 'native_probe.rs').read_text()
s = s.replace('fn parse_once(bytes: &[u8], opts: ReadOptions)', 'fn parse_once(bytes: &[u8], opts: ReadOptions, heaps: Option<(&[u8], &[u8])>)')
s = s.replace('Resolution::parse(std::hint::black_box(bytes), opts).unwrap()', 'parse(std::hint::black_box(bytes), opts, heaps)')
s = s.replace('    parse_once(&bytes, opts);', heap_setup + '    parse_once(&bytes, opts, heaps);')
s = s.replace('parse_once(&bytes, opts)', 'parse_once(&bytes, opts, heaps)')
s = s.replace('Resolution::parse(&bytes, opts).unwrap()', 'parse(&bytes, opts, heaps)')
s = s.replace('fn main()', helper + 'fn main()')
(dest / 'examples/native_probe.rs').write_text(s)
shutil.copy2(HERE / 'tree_borrows.rs', dest / 'examples/tb_repro.rs')
if not args.ranges:
    # Recreate A alone from the final A+D parser for class isolation.
    change('src/resolution/lazy.rs', 'struct MethodPendingRaw {', "struct MethodPendingRaw<'a> {")
    change('src/resolution/lazy.rs', '    pub range: std::ops::Range<usize>,', "    pub bytes: &'a [u8],")
    change('src/resolution/lazy.rs', "    pub body_source: &'a [u8],\n", '')
    change('src/resolution/lazy.rs', 'Vec<Option<MethodPendingRaw>>', "Vec<Option<MethodPendingRaw<'a>>>")
    change('src/resolution/lazy.rs', '        let bytes = &self.body_source[pending.range.clone()];', '        let bytes = pending.bytes;')
    change(read, 'let (range, offset) = dll.method_range(m)?;', 'let (bytes, offset) = dll.method_bytes(m)?;')
    change(read, 'lazy::MethodPendingRaw { range, offset }', 'lazy::MethodPendingRaw { bytes, offset }')
    p = dest / read
    s = p.read_text()
    start = s.index('            body_source: if opts.lazy_method_bodies {')
    end = s.index('            pending,', start)
    p.write_text(s[:start] + s[end:])
    change('src/dll.rs', "impl<'a> DLL<'a> {", """impl<'a> DLL<'a> {
    pub(crate) fn method_bytes(&self, def: &metadata::table::MethodDef) -> Result<(&'a [u8], usize)> {
        let bytes = self.raw_rva(def.rva)?;
        let offset = if !check_bitmask!(bytes[0], 0x2) { 4 - (def.rva as usize % 4) } else { 0 };
        Ok((bytes, offset))
    }
""")
print(dest)
