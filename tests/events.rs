use dotnetdll::prelude::*;

#[macro_use]
mod common;

#[test]
pub fn read() {
    common::read_fixture(
        "events",
        r#"
        .class public Program extends [mscorlib]System.Object {
            .event class [mscorlib]System.EventHandler MyEvent {
                .addon void Program::add_MyEvent(class [mscorlib]System.EventHandler)
                .removeon void Program::remove_MyEvent(class [mscorlib]System.EventHandler)
            }
            .method private static specialname void add_MyEvent(class [mscorlib]System.EventHandler) { }
            .method private static specialname void remove_MyEvent(class [mscorlib]System.EventHandler)  { }
        }
        "#,
        |res| {
            assert_inner_eq!(res.type_definitions[1].events[0], {
                name: "MyEvent",
                // hideous hackery because no box/deref patterns
                delegate_type => MemberType::Base(ref b) if matches!(&**b,
                    BaseType::Type { source: TypeSource::User(u), .. } if u.type_name(&res) == "System.EventHandler"
                ),
                add_listener => Method { ref name, ref signature, .. } if name == "add_MyEvent" && !signature.instance,
                remove_listener => Method { ref name, ref signature, .. } if name == "remove_MyEvent" && !signature.instance
            });
        },
    )
    .unwrap();
}

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
                        Some(body::Method::new(asm! {
                            LoadArgument 0;
                            Duplicate;
                            load_field field;
                            LoadArgument 1;
                            call combine;
                            cast_class handler_method.clone();
                            store_field field;
                            Return;
                        })),
                    ),
                    Method::new(
                        Accessibility::Public,
                        event_sig,
                        "remove_MyEvent",
                        Some(body::Method::new(asm! {
                            LoadArgument 0;
                            Duplicate;
                            load_field field;
                            LoadArgument 1;
                            call remove;
                            cast_class handler_method.clone();
                            store_field field;
                            Return;
                        })),
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
                    Some(body::Method::new(asm! {
                        load_string "listener triggered";
                        call write_line;
                        Return;
                    })),
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
                        asm! {
                            LoadArgument 0;
                            load_field field;
                            Duplicate;
                            StoreLocal 0;
                            BranchFalsy ret;
                            LoadLocal 0;
                            LoadArgument 0;
                            load_static_field empty;
                            call_virtual delegate_invoke;
                        @ret
                            Return;
                        },
                    )),
                ),
            );

            let handler_ctor = ctx
                .resolution
                .push_method_reference(method_ref! { void @handler_method::.ctor(object, nint) });

            let add = ctx.resolution.event_add_index(event);
            let remove = ctx.resolution.event_remove_index(event);

            (
                vec![],
                vec![
                    LocalVariable::new(BaseType::class(ctx.class).into()),
                    LocalVariable::new(handler_method),
                ],
                asm! {
                    // init obj
                    new_object ctx.default_ctor;
                    StoreLocal 0;
                    // init delegate
                    LoadNull;
                    load_method_pointer listener;
                    new_object handler_ctor;
                    StoreLocal 1;
                    // invoke first time (should have no output)
                    LoadLocal 0;
                    call invoke;
                    // add delegate
                    LoadLocal 0;
                    LoadLocal 1;
                    call add;
                    // invoke second time (should have output)
                    LoadLocal 0;
                    call invoke;
                    // remove delegate
                    LoadLocal 0;
                    LoadLocal 1;
                    call remove;
                    // invoke last time (should have no output)
                    LoadLocal 0;
                    call invoke;
                    Return;
                },
            )
        },
        b"listener triggered\n",
    )
    .unwrap();
}
