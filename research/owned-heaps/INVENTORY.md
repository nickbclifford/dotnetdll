# Borrow inventory

Audited `src/resolution/{read,lazy,mod}.rs`, `src/resolved/*.rs`, and
`src/binary/{heap,stream,cli,signature/attribute,signature/kinds}.rs`.
An occurrence of a lifetime in a constructor/decoder signature is not another
retained value. The following lists all input-backed fields and variants,
including ones produced only by a later accessor.

| Class | Fields/variants | Retained after `Resolution::parse`? | Ownership mode |
|---|---|---|---|
| (a), public Cow strings | `Assembly.{name,culture}`, `ExternalAssemblyReference.{name,culture}` | Yes | Owned |
| (a), public Cow strings | `Module.name`, `ExternalModuleReference.name`, `File.name` | Yes | Owned |
| (a), public Cow strings | `TypeDefinition.{name,namespace}`, `ExternalTypeReference.{name,namespace}`, `ExportedType.{name,namespace}` | Yes | Owned |
| (a), public Cow strings | `Field.name`, `ExternalFieldReference.name`, `Property.name`, `Event.name` | Yes | Owned |
| (a), public Cow strings | `Method.name`, `ExternalMethodReference.name`, `ParameterMetadata.name`, `PInvoke.import_name`, `Generic.name` | Yes | Owned |
| (a), public Cow strings | `ManifestResource.name` | Yes | Owned |
| (a), public Cow blobs | `Assembly.public_key`, `ExternalAssemblyReference.{public_key_or_token,hash_value}`, `File.hash_value` | Yes | Owned |
| (a), public Cow bytes outside metadata heaps | `Field.initial_value` (the existing parser retains the remainder of its RVA region), `resource::Implementation::CurrentFile` | If present | Still borrowed; deliberately outside `own_heap_values` |
| (c), private Cow blobs within public types | `Attribute.value`, `SecurityDeclaration.value` | Eager attributes/security: yes; deferred attributes: heap index until access | Owned, including lazy attribute accessors |
| (b), public borrowed binary fields | `cli::Metadata.version`, `stream::Header.name` | No: temporary binary metadata/header values are dropped; these are not `Resolution` fields | Unchanged |
| (b), public binary heap lookup results | `Reader::Value` for `StringsReader` (`&str`) and `BlobReader` (`&[u8]`) | Only if retained by the caller; resolution converts retained values to Cow | Unchanged |
| (c), internal/lazy heap state | Each heap reader's private `bytes`; lazy state keeps `BlobReader` and `UserStringReader` when any lazy option is set | Two broad input borrows, even if a particular lazy feature does not use both readers | Unchanged |
| (c), internal lazy body state | `MethodPendingRaw.bytes` and its alignment offset before this change; one slice per concrete method | With `lazy_method_bodies` | Implemented D replaces slices with `MethodPendingRaw.range` and one `body_source` input borrow; see report |
| (c), lazy signatures/attributes | Pending method/property signatures, attribute maps, TypeSpec/StandAloneSig/MethodSpec rows | Numeric indices and owned table rows, not one input borrow per signature/attribute | Lazy blob access uses the same ownership policy for retained attribute values |
| Accessor results, not parse retention | `SerString.0`, `FieldOrPropType::Enum`, `FixedArg::{String,Enum,Type}`, `NamedArg::{Field,Property}`, `Permission.type_name` | Only after `Attribute::instantiation_data` / `SecurityDeclaration::requested_permissions`; they borrow their blob | An owned attribute/security blob isolates these borrows from the DLL input allocation |
| Transient parser infrastructure | `DLL.buffer`, `DLL.sections`, stream/header vectors, temporary signature/blob slices, `resolved::attribute` decoding helper slices | DLL created inside `Resolution::parse` and intermediate readers are dropped; a caller can independently retain a `DLL` | Unchanged |

Method bodies' IL strings (`Instruction::LoadString`), string constants,
GUIDs, decoded signatures, marshaling descriptors and index maps own their data
or contain numbers. They do not retain input slices. `Resolution::lazy_state`
is an `Arc` and cloning a resolution shares caches and reader state; owned Cow
payloads clone normally. No public resolved `&'a str` / `&'a [u8]` field needs to
change for this implementation.

## Inputs inspected

The measured support DLL is 46,592 bytes: 50 type definitions, 135 type references,
73 fields, 482 methods, 455 parameters, 215 member references, 96 properties,
485 custom attributes, 373 nonzero method RVAs, zero FieldRVA rows and zero resources.
Its strings/blob heaps are 7,520/5,436 bytes. Thus the two excluded public byte
categories cannot contribute to this support-DLL parse. Class-isolated allocation
measurements find 1,724 extra string allocations (18,111 requested bytes) and six
extra blob allocations (205 bytes). Eager serialized custom-attribute payloads are
not retained under the consumer's lazy-attribute configuration; the attribute maps
store indices and resolve values on access.

The measured CoreLib is the local debug runtime's 6,389,248-byte DLL: 2,849 types,
43,393 methods, 69,595 parameters, 8,817 member references, 28,506 attributes,
41,270 nonzero method RVAs, 130 FieldRVA rows and four resources. Its strings/blob
heaps are 602,884/451,768 bytes. CoreLib therefore exercises the excluded raw byte
categories and has a much larger lazy-body slice population.
