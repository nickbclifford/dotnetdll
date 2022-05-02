use dotnetdll::prelude::*;

#[macro_use]
mod common;

#[test]
pub fn read() {
    common::read_fixture(
        "fields_props",
        r#"
        .class public Program extends [mscorlib]System.Object {
            .field private static int32 static_field
            .field private uint32 instance_field

            .property int32 StaticProperty() {
                .get int32 Program::get_StaticProperty()
                .set void Program::set_StaticProperty(int32)
            }
            .method public static int32 get_StaticProperty() { }
            .method public static void set_StaticProperty(int32) { }

            .property instance uint32 InstanceProperty() {
                .get instance uint32 Program::get_InstanceProperty()
                .set instance void Program::set_InstanceProperty(uint32)
            }
            .method public instance uint32 get_InstanceProperty() { }
            .method public void set_InstanceProperty(uint32) { }
        }
        "#,
        |res| {
            let program = &res.type_definitions[1];

            assert_inner_eq!(program.fields[0], {
                name: "static_field",
                return_type: ctype! { int },
                static_member => true
            });
            assert_inner_eq!(program.fields[1], {
                name: "instance_field",
                return_type: ctype! { uint },
                static_member => false
            });

            assert_inner_eq!(program.properties[0], {
                name: "StaticProperty",
                property_type: Parameter::value(ctype! { int }),
                static_member => true,
                getter => Some(Method { ref name, .. }) if name == "get_StaticProperty",
                setter => Some(Method { ref name, .. }) if name == "set_StaticProperty"
            });
            assert_inner_eq!(program.properties[1], {
                name: "InstanceProperty",
                property_type: Parameter::value(ctype! { uint }),
                static_member => false,
                getter => Some(Method { ref name, .. }) if name == "get_InstanceProperty",
                setter => Some(Method { ref name, .. }) if name == "set_InstanceProperty"
            });
        },
    )
    .unwrap();
}

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
                Property::new(false, "StaticProperty", Parameter::value(static_type.clone())),
            );
            let static_getter = ctx.resolution.set_property_getter(
                static_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { static @static_type () },
                    "get_StaticProperty",
                    Some(body::Method::new(asm! {
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
                    Some(body::Method::new(asm! {
                        LoadArgument 0;
                        store_static_field static_field;
                        Return;
                    })),
                ),
            );

            let instance_type: MethodType = ctx.resolution[instance_field].return_type.clone().into();
            let instance_prop = ctx.resolution.push_property(
                ctx.class,
                Property::new(false, "InstanceProperty", Parameter::value(instance_type.clone())),
            );
            let instance_getter = ctx.resolution.set_property_getter(
                instance_prop,
                Method::new(
                    Accessibility::Public,
                    msig! { @instance_type () },
                    "get_InstanceProperty",
                    Some(body::Method::new(asm! {
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
                    Some(body::Method::new(asm! {
                        LoadArgument 0;
                        LoadArgument 1;
                        store_field instance_field;
                        Return;
                    })),
                ),
            );

            (
                vec![],
                vec![LocalVariable::new(BaseType::class(ctx.class).into())],
                asm! {
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
