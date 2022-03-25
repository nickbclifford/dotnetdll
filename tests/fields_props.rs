use dotnetdll::prelude::*;

mod common;

#[test]
pub fn write() {
    common::write_fixture(
        "fields_props",
        |ctx| {
            let console_type = BaseType::class(ctx.console.into()).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console_type::WriteLine(string, object, object) });

            let static_field = ctx.resolution.push_field(
                ctx.class,
                Field::static_member(Accessibility::Private, "static_field", ctype! { int }),
            );
            let instance_field = ctx.resolution.push_field(
                ctx.class,
                Field::instance(Accessibility::Private, "instance_field", ctype! { uint }),
            );

            let static_type: MethodType = ctx.resolution[static_field].return_type.clone().into();
            let static_prop = ctx.resolution.push_property(
                ctx.class,
                Property::new(
                    "StaticProperty",
                    Parameter::value(static_type.clone()),
                ),
            );
            let static_getter = ctx.resolution.set_property_getter(
                static_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { static @static_type () },
                    "get_StaticProperty",
                    Some(body::Method::new(vec![
                        Instruction::load_static_field(static_field),
                        Instruction::Return,
                    ])),
                ),
            );
            let static_setter = ctx.resolution.set_property_setter(
                static_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { static void (@static_type) },
                    "set_StaticProperty",
                    Some(body::Method::new(vec![
                        Instruction::LoadArgument(0),
                        Instruction::store_static_field(static_field),
                        Instruction::Return,
                    ])),
                ),
            );

            let instance_type: MethodType = ctx.resolution[instance_field].return_type.clone().into();
            let instance_prop = ctx.resolution.push_property(
                ctx.class,
                Property::new(
                    "InstanceProperty",
                    Parameter::value(instance_type.clone()),
                ),
            );
            let instance_getter = ctx.resolution.set_property_getter(
                instance_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { @instance_type () },
                    "get_InstanceProperty",
                    Some(body::Method::new(vec![
                        Instruction::LoadArgument(0),
                        Instruction::load_field(instance_field),
                        Instruction::Return,
                    ])),
                ),
            );
            let instance_setter = ctx.resolution.set_property_setter(
                instance_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { void (@instance_type) },
                    "set_InstanceProperty",
                    Some(body::Method::new(vec![
                        Instruction::LoadArgument(0),
                        Instruction::LoadArgument(1),
                        Instruction::store_field(instance_field),
                        Instruction::Return,
                    ])),
                ),
            );

            (
                vec![LocalVariable::new(BaseType::class(ctx.class.into()).into())],
                vec![
                    // init static
                    Instruction::LoadConstantInt32(-1),
                    Instruction::call(static_setter),
                    // init object and instance
                    Instruction::NewObject(ctx.default_ctor.into()),
                    Instruction::Duplicate,
                    Instruction::StoreLocal(0),
                    Instruction::LoadConstantInt32(1),
                    Instruction::call(instance_setter),
                    // increment static
                    Instruction::call(static_getter),
                    Instruction::LoadConstantInt32(1),
                    Instruction::Add,
                    Instruction::call(static_setter),
                    // increment instance
                    Instruction::LoadLocal(0),
                    Instruction::Duplicate,
                    Instruction::call(instance_getter),
                    Instruction::LoadConstantInt32(1),
                    Instruction::Add,
                    Instruction::call(instance_setter),
                    // call writeline
                    Instruction::load_string("{0}, {1}"),
                    Instruction::call(static_getter),
                    Instruction::box_value(static_type),
                    Instruction::LoadLocal(0),
                    Instruction::call(instance_getter),
                    Instruction::box_value(instance_type),
                    Instruction::call(write_line),
                    Instruction::Return,
                ],
            )
        },
        b"0, 2\n",
    )
    .unwrap();
}
