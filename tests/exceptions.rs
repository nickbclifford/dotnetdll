use dotnetdll::prelude::*;

#[macro_use]
mod common;

#[test]
pub fn read() {
    common::read_fixture(
        "exceptions",
        r#"
        .class public Program extends [mscorlib]System.Object {
            .method public static void Main() {
                .try {
                    nop
                    leave afterCatchFinally
                } catch [mscorlib]System.Exception {
                    pop
                    leave afterCatchFinally
                } finally {
                    endfinally
                }
                afterCatchFinally:
                .try {
                    nop
                    leave afterFilterFault
                } filter {
                    pop
                    ldc.i4.1
                    endfilter
                } {
                    pop
                    leave afterFilterFault
                } fault {
                    endfault
                }
                afterFilterFault:
                ret
            }
        }
        "#,
        |res| {
            let main = res.type_definitions[1].methods[0].body.as_ref().unwrap();
            let exceptions = match &main.data_sections[0] {
                body::DataSection::ExceptionHandlers(e) => e,
                rest => panic!("bad data section {:?}, expected exception handlers", rest),
            };

            assert_inner_eq!(exceptions[0], {
                kind => body::ExceptionKind::TypedException(MethodType::Base(ref b)) if matches!(&**b,
                    BaseType::Type { source: TypeSource::User(u), .. } if u.type_name(&res) == "System.Exception"
                ),
                try_offset: 0,
                try_length: 2,
                handler_offset: 2,
                handler_length: 2
            });
            assert_inner_eq!(exceptions[1], {
                kind => body::ExceptionKind::Finally,
                try_offset: 0,
                try_length: 2,
                handler_offset => h if main.instructions[h] == Instruction::EndFinally,
                handler_length: 1
            });

            assert_inner_eq!(exceptions[2], {
                kind => body::ExceptionKind::Filter { offset } if main.instructions[offset + 2] == Instruction::EndFilter,
                try_offset: 5,
                try_length: 2
            });
            assert_inner_eq!(exceptions[3], {
                kind => body::ExceptionKind::Fault,
                try_offset: 5,
                try_length: 2,
                handler_offset => h if main.instructions[h] == Instruction::EndFinally
            });
        },
    )
    .unwrap();
}

#[test]
pub fn write() {
    common::write_fixture(
        "exceptions",
        |ctx| {
            let mscorlib = ctx.mscorlib;
            let console: MethodType = BaseType::class(ctx.console).into();

            let exception = ctx
                .resolution
                .push_type_reference(type_ref! { System.Exception in #mscorlib });

            let my_exception = ctx
                .resolution
                .push_type_definition(TypeDefinition::new(None, "MyException"));
            let my_exception_t: MethodType = BaseType::class(my_exception).into();
            ctx.resolution[my_exception].extends = Some(exception.into());
            let code = ctx.resolution.push_field(
                my_exception,
                Field::new(false, Accessibility::Public, "code", ctype! { int }),
            );
            let object_ctor = ctx.resolution.object_ctor();
            let my_exception_ctor = ctx.resolution.push_method(
                my_exception,
                Method::constructor(
                    Accessibility::Public,
                    vec![Parameter::value(ctype! { int })],
                    Some(body::Method::new(asm! {
                        LoadArgument 0;
                        call object_ctor;
                        LoadArgument 0;
                        LoadArgument 1;
                        store_field code;
                        Return;
                    })),
                ),
            );

            let write_str = ctx.resolution.push_method_reference(method_ref! { static void @console::WriteLine(string) });

            let (
                instructions,
                try_start,
                filter_start,
                handler_start,
                finally_start,
                ret
            ) = asm! {
            +try_start
                // try {
                load_string "before throw";
                call write_str;
                LoadConstantInt32 1;
                new_object my_exception_ctor;
                Throw;
                load_string "after throw";
                call write_str;
                Leave ret;
            +filter_start
                // } when (
                Duplicate;
                IsInstance my_exception_t.clone();
                BranchFalsy pop;
                cast_class my_exception_t.clone();
                load_field code;
                Branch end_filter;
            @pop
                Pop;
                LoadConstantInt32 0; // false
            @end_filter
                EndFilter;
            +handler_start
                // ) {
                StoreLocal 0;
                load_string "error code {0}";
                LoadLocal 0;
                cast_class my_exception_t;
                load_field code;
                BoxValue ctype! { int };
                call ctx.resolution.push_method_reference(method_ref! { static void #console::WriteLine(string, object) });
                Leave ret;
            +finally_start
                // } finally {
                load_string "finally";
                call write_str;
                EndFinally;
                // }
            +ret
                Return;
            };

            (
                vec![
                    body::Exception {
                        kind: body::ExceptionKind::Filter { offset: filter_start },
                        try_offset: try_start,
                        try_length: filter_start - try_start,
                        handler_offset: handler_start,
                        handler_length: finally_start - handler_start
                    },
                    body::Exception {
                        kind: body::ExceptionKind::Finally,
                        try_offset: try_start,
                        try_length: finally_start - try_start,
                        handler_offset: finally_start,
                        handler_length: ret - finally_start
                    }
                ],
                vec![LocalVariable::new(ctype! { object })],
                instructions
            )
        },
        b"before throw\nerror code 1\nfinally\n",
    )
    .unwrap();
}
