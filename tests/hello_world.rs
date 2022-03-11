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
            ctx.resolution[ctx.main].body.as_mut().unwrap().instructions.extend([
                Instruction::LoadString("Hello, world!".encode_utf16().collect()),
                Instruction::Call {
                    tail_call: false,
                    method: write_line.into(),
                },
                Instruction::Return,
            ]);
        },
        b"Hello, world!\n",
    ).unwrap();
}
