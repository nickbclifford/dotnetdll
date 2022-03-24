use dotnetdll::prelude::*;

mod common;

#[test]
pub fn write() {
    common::write_fixture(
        "hello_world",
        |ctx| {
            let console_type = BaseType::class(ctx.console.into()).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console_type::WriteLine(string) });

            (
                vec![],
                vec![
                    Instruction::load_string("Hello, world!"),
                    Instruction::call(write_line),
                    Instruction::Return,
                ],
            )
        },
        b"Hello, world!\n",
    )
    .unwrap();
}
