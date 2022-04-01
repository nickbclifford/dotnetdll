use dotnetdll::prelude::*;

mod common;

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

            (
                vec![],
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
