//! Self-contained fixture; no .NET SDK/runtime required, including under Miri.
use dotnetdll::prelude::*;
use std::borrow::Cow;

fn fixture() -> Vec<u8> {
    let mut r = Resolution::new(Module::new("owned-heaps.dll"));
    r.assembly = Some(Assembly::new("owned-heaps"));
    r.assembly.as_mut().unwrap().public_key = Some(vec![1, 2, 3].into());
    let attribute_type = r.push_type_definition(TypeDefinition::new(Some("Example".into()), "TestAttribute"));
    let ctor = r.push_method(
        attribute_type,
        Method::constructor(
            Accessibility::Public,
            vec![Parameter::value(ctype! { string })],
            Some(body::Method::new(asm! { Return; })),
        ),
    );
    let subject = r.push_type_definition(TypeDefinition::new(Some("Example".into()), "Subject"));
    let attr = Attribute::new(
        ctor.into(),
        CustomAttributeData {
            constructor_args: vec![FixedArg::String(Some("payload".into()))],
            named_args: vec![],
        },
    );
    r[subject].attributes.push(attr.clone());
    r.assembly.as_mut().unwrap().attributes.push(attr.clone());
    let field = r.push_field(
        subject,
        Field::static_member(Accessibility::Public, "Value", ctype! { int }),
    );
    r[field].attributes.push(attr.clone());
    let run = r.push_method(
        subject,
        Method::new(
            Accessibility::Public,
            msig! { static void () },
            "Run",
            Some(body::Method::new(asm! { Return; })),
        ),
    );
    r[run].attributes.push(attr);
    let property = r.push_property(
        subject,
        Property::new(false, "Answer", Parameter::value(ctype! { int })),
    );
    r.set_property_getter(
        property,
        Method::new(
            Accessibility::Public,
            msig! { int () },
            "get_Answer",
            Some(body::Method::new(asm! { LoadConstantInt32 42; Return; })),
        ),
    );
    r.write(WriteOptions::default()).unwrap()
}

fn equal_debug<T: std::fmt::Debug>(a: &T, b: &T) {
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

fn compare(bytes: &[u8], opts: ReadOptions) {
    let mut borrowed = Resolution::parse(bytes, opts).unwrap();
    let mut owned = Resolution::parse(bytes, opts.with_own_heap_values(true)).unwrap();
    assert!(matches!(borrowed.module.name, Cow::Borrowed(_)));
    assert!(matches!(owned.module.name, Cow::Owned(_)));
    assert!(matches!(
        owned.assembly.as_ref().unwrap().public_key,
        Some(Cow::Owned(_))
    ));
    equal_debug(&borrowed.assembly, &owned.assembly);
    equal_debug(&borrowed.type_definitions, &owned.type_definitions);
    equal_debug(
        &borrowed.assembly_attributes().unwrap(),
        &owned.assembly_attributes().unwrap(),
    );
    // Attribute value decoding uses the public constructor signature. Materialize it
    // when signatures are lazy, just as callers of instantiation_data must do.
    let methods: Vec<_> = borrowed
        .enumerate_type_definitions()
        .flat_map(|(ti, _)| borrowed.enumerate_methods(ti).map(|(mi, _)| mi))
        .collect();
    for mi in methods {
        let bs = borrowed.method_signature(mi).unwrap().clone();
        let os = owned.method_signature(mi).unwrap().clone();
        borrowed[mi].signature = bs;
        owned[mi].signature = os;
    }
    for ((ti, bt), (_, ot)) in borrowed
        .enumerate_type_definitions()
        .zip(owned.enumerate_type_definitions())
    {
        assert!(matches!(ot.name, Cow::Owned(_)));
        assert!(ot.namespace.as_ref().is_none_or(|n| matches!(n, Cow::Owned(_))));
        let ba = borrowed.type_attributes(ti).unwrap();
        let oa = owned.type_attributes(ti).unwrap();
        equal_debug(&ba, &oa);
        for (b, o) in ba.iter().zip(&oa) {
            equal_debug(
                &b.instantiation_data(&AlwaysFailsResolver, &borrowed).unwrap(),
                &o.instantiation_data(&AlwaysFailsResolver, &owned).unwrap(),
            );
        }
        for ((mi, bm), (_, om)) in borrowed.enumerate_methods(ti).zip(owned.enumerate_methods(ti)) {
            assert_eq!(bm.name, om.name);
            assert!(matches!(om.name, Cow::Owned(_)));
            equal_debug(
                borrowed.method_signature(mi).unwrap(),
                owned.method_signature(mi).unwrap(),
            );
            equal_debug(borrowed.method_body(mi).unwrap(), owned.method_body(mi).unwrap());
            equal_debug(
                &borrowed.method_attributes(mi).unwrap(),
                &owned.method_attributes(mi).unwrap(),
            );
        }
        for (fi, _) in borrowed.enumerate_fields(ti) {
            equal_debug(
                &borrowed.field_attributes(fi).unwrap(),
                &owned.field_attributes(fi).unwrap(),
            );
        }
        for (pi, _) in borrowed.enumerate_properties(ti) {
            equal_debug(
                &borrowed.property_signature(pi).unwrap(),
                &owned.property_signature(pi).unwrap(),
            );
        }
        assert_eq!(bt.name, ot.name);
    }
    // Lazy state and owned payloads must also survive cloning and dropping the original.
    let cloned = owned.clone();
    drop(owned);
    assert!(matches!(cloned.module.name, Cow::Owned(_)));
    assert!(!cloned.assembly_attributes().unwrap().is_empty());
}

#[test]
fn owned_heap_values_match_borrowed_in_all_lazy_modes() {
    let bytes = fixture();
    for mask in 0..16 {
        compare(
            &bytes,
            ReadOptions::default()
                .with_lazy_method_bodies(mask & 1 != 0)
                .with_lazy_method_signatures(mask & 2 != 0)
                .with_lazy_property_signatures(mask & 4 != 0)
                .with_lazy_attributes(mask & 8 != 0),
        );
    }
}

/// Run with MIRIFLAGS="-Zmiri-tree-borrows -Zmiri-disable-isolation -Zmiri-ignore-leaks"
/// cargo +nightly-2026-05-27 miri test --test owned_heap_values miri_owned_heap_smoke
#[test]
fn miri_owned_heap_smoke() {
    const OPTIONS: ReadOptions = ReadOptions::new()
        .with_lazy_method_bodies(true)
        .with_lazy_attributes(true);
    compare(&fixture(), OPTIONS);
}
