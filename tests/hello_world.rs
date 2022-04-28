use dotnetdll::prelude::*;

mod common;

#[test]
pub fn read() {
    common::read_fixture(
        "hello_world",
        r#"
        .assembly hello_world { }
        .assembly extern mscorlib { }

        .class public Program extends [mscorlib]System.Object {
            .method public static void Main(string[] args) {
                .entrypoint
                ldstr "Hello, world!"
                call void [mscorlib]System.Console::WriteLine(string)
                ret
            }
        }
        "#,
        |res| {
            let program = &res.type_definitions[1];
            assert_eq!(program.name, "Program");

            let main = &program.methods[0];
            assert_eq!(main.name, "Main");

            let body = main.body.as_ref().unwrap();
            assert_eq!(body.instructions[0], Instruction::load_string("Hello, world!"));
        },
    )
    .unwrap();
}

#[test]
pub fn write() {
    common::write_fixture(
        "hello_world",
        |ctx| {
            let console_type = BaseType::class(ctx.console).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console_type::WriteLine(string) });

            (
                vec![],
                vec![],
                asm! {
                    load_string "Hello, world!";
                    call write_line;
                    Return;
                },
            )
        },
        b"Hello, world!\n",
    )
    .unwrap();
}
