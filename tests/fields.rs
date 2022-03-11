use dotnetdll::prelude::*;

mod common;

#[test]
pub fn write() {
    common::write_fixture(
        "fields",
        |ctx| {
            let console_type = BaseType::class(ctx.console.into()).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console_type::WriteLine(string, object, object) });

            let static_field = ctx.resolution.push_field(
                ctx.class,
                Field::static_member(Accessibility::Public, "static_field".into(), ctype! { int }),
            );
            let instance_field = ctx.resolution.push_field(
                ctx.class,
                Field::instance(Accessibility::Public, "instance_field".into(), ctype! { uint }),
            );

            let main_body = ctx.resolution[ctx.main].body.as_mut().unwrap();
            main_body
                .header
                .local_variables
                .push(LocalVariable::new(BaseType::class(ctx.class.into()).into()));
            main_body.instructions.extend([
                // init static
                Instruction::LoadConstantInt32(-1),
                Instruction::StoreStaticField {
                    volatile: false,
                    field: static_field.into(),
                },
                // init instance
                Instruction::NewObject(ctx.default_ctor.into()),
                Instruction::Duplicate,
                Instruction::StoreLocal(0),
                Instruction::LoadConstantInt32(1),
                Instruction::StoreField {
                    unaligned: None,
                    volatile: false,
                    field: instance_field.into(),
                },
                // increment static
                Instruction::LoadStaticField {
                    volatile: false,
                    field: static_field.into(),
                },
                Instruction::LoadConstantInt32(1),
                Instruction::Add,
                Instruction::StoreStaticField {
                    volatile: false,
                    field: static_field.into(),
                },
                // increment instance
                Instruction::LoadLocalVariable(0),
                Instruction::Duplicate,
                Instruction::LoadField {
                    unaligned: None,
                    volatile: false,
                    field: instance_field.into(),
                },
                Instruction::LoadConstantInt32(1),
                Instruction::Add,
                Instruction::StoreField {
                    unaligned: None,
                    volatile: false,
                    field: instance_field.into(),
                },
                // print
                Instruction::LoadString("{0}, {1}".encode_utf16().collect()),
                Instruction::LoadStaticField {
                    volatile: false,
                    field: static_field.into(),
                },
                Instruction::Box(ctype! { int }),
                Instruction::LoadLocalVariable(0),
                Instruction::LoadField {
                    unaligned: None,
                    volatile: false,
                    field: instance_field.into(),
                },
                Instruction::Box(ctype! { uint }),
                Instruction::Call {
                    tail_call: false,
                    method: write_line.into(),
                },
                Instruction::Return,
            ]);
        },
        b"0, 2\n",
    )
    .unwrap();
}
