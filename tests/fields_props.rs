use dotnetdll::prelude::*;

mod common;

#[test]
pub fn write() {
    common::write_fixture(
        "fields_props",
        |ctx| {
            let console_type = BaseType::class(ctx.console).into();
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
                Property::new("StaticProperty", Parameter::value(static_type.clone())),
            );
            let static_getter = ctx.resolution.set_property_getter(
                static_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { static @static_type () },
                    "get_StaticProperty",
                    Some(body::Method::new(common::asm! {
                        load_static_field static_field;
                        Return;
                    })),
                ),
            );
            let static_setter = ctx.resolution.set_property_setter(
                static_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { static void (@static_type) },
                    "set_StaticProperty",
                    Some(body::Method::new(common::asm! {
                        LoadArgument 0;
                        store_static_field static_field;
                        Return;
                    })),
                ),
            );

            let instance_type: MethodType = ctx.resolution[instance_field].return_type.clone().into();
            let instance_prop = ctx.resolution.push_property(
                ctx.class,
                Property::new("InstanceProperty", Parameter::value(instance_type.clone())),
            );
            let instance_getter = ctx.resolution.set_property_getter(
                instance_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { @instance_type () },
                    "get_InstanceProperty",
                    Some(body::Method::new(common::asm! {
                        LoadArgument 0;
                        load_field instance_field;
                        Return;
                    })),
                ),
            );
            let instance_setter = ctx.resolution.set_property_setter(
                instance_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { void (@instance_type) },
                    "set_InstanceProperty",
                    Some(body::Method::new(common::asm! {
                        LoadArgument 0;
                        LoadArgument 1;
                        store_field instance_field;
                        Return;
                    })),
                ),
            );

            (
                vec![LocalVariable::new(BaseType::class(ctx.class).into())],
                common::asm! {
                    // init static
                    LoadConstantInt32 -1;
                    call static_setter;
                    // init object and instance
                    new_object ctx.default_ctor;
                    Duplicate;
                    StoreLocal 0;
                    LoadConstantInt32 1;
                    call instance_setter;
                    // increment static
                    call static_getter;
                    LoadConstantInt32 1;
                    Add;
                    call static_setter;
                    // increment instance
                    LoadLocal 0;
                    Duplicate;
                    call instance_getter;
                    LoadConstantInt32 1;
                    Add;
                    call instance_setter;
                    // call writeline
                    load_string "{0}, {1}";
                    call static_getter;
                    box_value static_type;
                    LoadLocal 0;
                    call instance_getter;
                    box_value instance_type;
                    call write_line;
                    Return;
                },
            )
        },
        b"0, 2\n",
    )
    .unwrap();
}
