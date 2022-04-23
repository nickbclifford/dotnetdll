use dotnetdll::prelude::*;

mod common;

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
