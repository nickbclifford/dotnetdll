use dotnetdll::prelude::*;

mod common;

#[test]
pub fn write() {
    common::write_fixture(
        "events",
        |ctx| {
            let mscorlib = ctx.mscorlib;
            let handler_del = ctx
                .resolution
                .push_type_reference(type_ref! { System.EventHandler in #mscorlib });
            let handler_member: MemberType = BaseType::class(handler_del.into()).into();
            let handler_method: MethodType = handler_member.clone().into();

            let delegate_t: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Delegate in #mscorlib })
                    .into(),
            )
            .into();
            let combine = ctx.resolution.push_method_reference(
                method_ref! { static @delegate_t @delegate_t::Combine(@delegate_t, @delegate_t) },
            );
            let remove = ctx.resolution.push_method_reference(
                method_ref! { static @delegate_t @delegate_t::Remove(@delegate_t, @delegate_t) },
            );

            let field = ctx.resolution.push_field(
                ctx.class,
                Field::new(
                    false,
                    Accessibility::Private,
                    "eventHandler".into(),
                    handler_member.clone(),
                ),
            );
            let event_sig = msig! { void (@handler_method) };
            let event = ctx.resolution.push_event(
                ctx.class,
                Event::new(
                    "MyEvent".into(),
                    handler_member,
                    Method::new(
                        Accessibility::Public,
                        event_sig.clone(),
                        "add_MyEvent".into(),
                        Some(body::Method::new(vec![
                            Instruction::LoadArgument(0),
                            Instruction::Duplicate,
                            Instruction::LoadField {
                                unaligned: None,
                                volatile: false,
                                field: field.into(),
                            },
                            Instruction::LoadArgument(1),
                            Instruction::Call {
                                tail_call: false,
                                method: combine.into(),
                            },
                            Instruction::StoreField {
                                unaligned: None,
                                volatile: false,
                                field: field.into(),
                            },
                            Instruction::Return,
                        ])),
                    ),
                    Method::new(
                        Accessibility::Public,
                        event_sig,
                        "remove_MyEvent".into(),
                        Some(body::Method::new(vec![
                            Instruction::LoadArgument(0),
                            Instruction::Duplicate,
                            Instruction::LoadField {
                                unaligned: None,
                                volatile: false,
                                field: field.into(),
                            },
                            Instruction::LoadArgument(1),
                            Instruction::Call {
                                tail_call: false,
                                method: remove.into(),
                            },
                            Instruction::StoreField {
                                unaligned: None,
                                volatile: false,
                                field: field.into(),
                            },
                            Instruction::Return,
                        ])),
                    ),
                ),
            );

            let event_args_member: MemberType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.EventArgs in #mscorlib })
                    .into(),
            )
            .into();
            let event_args: MethodType = event_args_member.clone().into();

            let console: MethodType = BaseType::class(ctx.console.into()).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console::WriteLine(string) });
            let listener = ctx.resolution.push_method(
                ctx.class,
                Method::new(
                    Accessibility::Private,
                    msig! { static void (object, @event_args) },
                    "Listener".into(),
                    Some(body::Method::new(vec![
                        Instruction::LoadString("listener triggered".encode_utf16().collect()),
                        Instruction::Call {
                            tail_call: false,
                            method: write_line.into(),
                        },
                        Instruction::Return,
                    ])),
                ),
            );

            let empty = ctx
                .resolution
                .push_field_reference(field_ref! { #event_args_member @event_args::Empty });
            let delegate_invoke = ctx
                .resolution
                .push_method_reference(method_ref! { void @handler_method::Invoke(object, @event_args) });
            let invoke = ctx.resolution.push_method(
                ctx.class,
                Method::new(
                    Accessibility::Public,
                    msig! { void () },
                    "Invoke".into(),
                    Some(body::Method::with_locals(
                        vec![LocalVariable::new(handler_method.clone())],
                        vec![
                            Instruction::LoadArgument(0),
                            Instruction::LoadField {
                                unaligned: None,
                                volatile: false,
                                field: field.into(),
                            },
                            Instruction::Duplicate,
                            Instruction::StoreLocal(0),
                            Instruction::BranchFalsy(9),
                            Instruction::LoadLocalVariable(0),
                            Instruction::LoadArgument(0),
                            Instruction::LoadStaticField {
                                volatile: false,
                                field: empty.into(),
                            },
                            Instruction::CallVirtual {
                                skip_null_check: false,
                                method: delegate_invoke.into(),
                            },
                            Instruction::Return,
                        ],
                    )),
                ),
            );

            let handler_ctor = ctx
                .resolution
                .push_method_reference(method_ref! { void @handler_method::.ctor(object, nint) });

            let add = ctx.resolution.event_add_index(event);
            let remove = ctx.resolution.event_remove_index(event);

            let body = ctx.resolution[ctx.main].body.as_mut().unwrap();
            body.header.local_variables.extend([
                LocalVariable::new(BaseType::class(ctx.class.into()).into()),
                LocalVariable::new(handler_method),
            ]);
            body.instructions.extend([
                // init obj
                Instruction::NewObject(ctx.default_ctor.into()),
                Instruction::StoreLocal(0),
                // init delegate
                Instruction::LoadNull,
                Instruction::LoadMethodPointer(listener.into()),
                Instruction::NewObject(handler_ctor.into()),
                Instruction::StoreLocal(1),
                // invoke first time (should have no output)
                Instruction::LoadLocalVariable(0),
                Instruction::Call {
                    tail_call: false,
                    method: invoke.into(),
                },
                // add delegate
                Instruction::LoadLocalVariable(0),
                Instruction::LoadLocalVariable(1),
                Instruction::Call {
                    tail_call: false,
                    method: add.into(),
                },
                // invoke second time (should have output)
                Instruction::LoadLocalVariable(0),
                Instruction::Call {
                    tail_call: false,
                    method: invoke.into(),
                },
                // remove delegate
                Instruction::LoadLocalVariable(0),
                Instruction::LoadLocalVariable(1),
                Instruction::Call {
                    tail_call: false,
                    method: remove.into(),
                },
                // invoke last time (should have no output)
                Instruction::LoadLocalVariable(0),
                Instruction::Call {
                    tail_call: false,
                    method: invoke.into(),
                },
                Instruction::Return,
            ]);
        },
        b"listener triggered\n",
    )
    .unwrap();
}
