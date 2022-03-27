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
            let handler_member: MemberType = BaseType::class(handler_del).into();
            let handler_method: MethodType = handler_member.clone().into();

            let delegate_t: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Delegate in #mscorlib }),
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
                Field::new(false, Accessibility::Private, "eventHandler", handler_member.clone()),
            );
            let event_sig = msig! { void (@handler_method) };
            let event = ctx.resolution.push_event(
                ctx.class,
                Event::new(
                    "MyEvent",
                    handler_member,
                    Method::new(
                        Accessibility::Public,
                        event_sig.clone(),
                        "add_MyEvent",
                        Some(body::Method::new(vec![
                            Instruction::LoadArgument(0),
                            Instruction::Duplicate,
                            Instruction::load_field(field),
                            Instruction::LoadArgument(1),
                            Instruction::call(combine),
                            Instruction::cast_class(handler_method.clone()),
                            Instruction::store_field(field),
                            Instruction::Return,
                        ])),
                    ),
                    Method::new(
                        Accessibility::Public,
                        event_sig,
                        "remove_MyEvent",
                        Some(body::Method::new(vec![
                            Instruction::LoadArgument(0),
                            Instruction::Duplicate,
                            Instruction::load_field(field),
                            Instruction::LoadArgument(1),
                            Instruction::call(remove),
                            Instruction::cast_class(handler_method.clone()),
                            Instruction::store_field(field),
                            Instruction::Return,
                        ])),
                    ),
                ),
            );

            let event_args_member: MemberType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.EventArgs in #mscorlib }),
            )
            .into();
            let event_args: MethodType = event_args_member.clone().into();

            let console: MethodType = BaseType::class(ctx.console).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console::WriteLine(string) });
            let listener = ctx.resolution.push_method(
                ctx.class,
                Method::new(
                    Accessibility::Private,
                    msig! { static void (object, @event_args) },
                    "Listener",
                    Some(body::Method::new(vec![
                        Instruction::load_string("listener triggered"),
                        Instruction::call(write_line),
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
                    "Invoke",
                    Some(body::Method::with_locals(
                        vec![LocalVariable::new(handler_method.clone())],
                        vec![
                            Instruction::LoadArgument(0),
                            Instruction::load_field(field),
                            Instruction::Duplicate,
                            Instruction::StoreLocal(0),
                            Instruction::BranchFalsy(9),
                            Instruction::LoadLocal(0),
                            Instruction::LoadArgument(0),
                            Instruction::load_static_field(empty),
                            Instruction::call_virtual(delegate_invoke),
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

            (
                vec![
                    LocalVariable::new(BaseType::class(ctx.class).into()),
                    LocalVariable::new(handler_method),
                ],
                vec![
                    // init obj
                    Instruction::new_object(ctx.default_ctor),
                    Instruction::StoreLocal(0),
                    // init delegate
                    Instruction::LoadNull,
                    Instruction::load_method_pointer(listener),
                    Instruction::new_object(handler_ctor),
                    Instruction::StoreLocal(1),
                    // invoke first time (should have no output)
                    Instruction::LoadLocal(0),
                    Instruction::call(invoke),
                    // add delegate
                    Instruction::LoadLocal(0),
                    Instruction::LoadLocal(1),
                    Instruction::call(add),
                    // invoke second time (should have output)
                    Instruction::LoadLocal(0),
                    Instruction::call(invoke),
                    // remove delegate
                    Instruction::LoadLocal(0),
                    Instruction::LoadLocal(1),
                    Instruction::call(remove),
                    // invoke last time (should have no output)
                    Instruction::LoadLocal(0),
                    Instruction::call(invoke),
                    Instruction::Return,
                ],
            )
        },
        b"listener triggered\n",
    )
    .unwrap();
}
