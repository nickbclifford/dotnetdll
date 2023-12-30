use dotnetdll::prelude::*;

#[macro_use]
mod common;

#[test]
pub fn read() {
    common::read_fixture(
        "pinvoke",
        r#"
        .class public Program extends [mscorlib]System.Object {
            .method public static pinvokeimpl("libc.so.6" cdecl) void puts(string s) {}
        }
        "#,
        |res| {
            assert_inner_eq!(res.type_definitions[1].methods[0], {
                pinvoke => Some(ref p) if res[p.import_scope].name == "libc.so.6",
                name: "puts"
            });
        },
    )
    .unwrap();
}

#[test]
pub fn write() {
    common::write_fixture(
        "pinvoke",
        |ctx| {
            let libc = ctx
                .resolution
                .push_module_reference(ExternalModuleReference::new("libc.so.6"));
            let mut libc_method = |name, signature| {
                ctx.resolution.push_method(
                    ctx.class,
                    Method {
                        pinvoke: Some(PInvoke::new(libc, name)),
                        ..Method::new(Accessibility::Public, signature, name, None)
                    },
                )
            };

            let puts = libc_method("puts", msig! { static void (string) });

            common::MainMethod::Body(
                asm! {
                    load_string "hello from libc";
                    call puts;
                    Return;
                },
            )
        },
        b"hello from libc\n",
    )
    .unwrap();
}
