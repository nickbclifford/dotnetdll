use dotnetdll::prelude::*;

mod common;

#[allow(clippy::approx_constant)]
#[test]
pub fn write() {
    common::write_fixture(
        "attributes",
        |ctx| {
            let mscorlib = ctx.mscorlib;
            let attribute = ctx
                .resolution
                .push_type_reference(type_ref! { System.Attribute in #mscorlib });
            let attr_t: MethodType = BaseType::class(attribute).into();
            let attr_ctor = ctx
                .resolution
                .push_method_reference(method_ref! { void #attr_t::.ctor() });

            let test_attr = ctx
                .resolution
                .push_type_definition(TypeDefinition::new(None, "TestAttribute"));
            ctx.resolution[test_attr].extends = Some(attribute.into());

            let required = ctx.resolution.push_field(
                test_attr,
                Field::new(false, Accessibility::Public, "Required", ctype! { string }),
            );

            let optional_field = ctx.resolution.push_field(
                test_attr,
                Field::new(false, Accessibility::Public, "OptionalField", ctype! { int }),
            );

            let optional_prop_backing = ctx.resolution.push_field(
                test_attr,
                Field::new(false, Accessibility::Private, "optionalProp", ctype! { float[] }),
            );
            let optional_property = ctx.resolution.push_property(
                test_attr,
                Property {
                    setter: Some(Method::new(
                        Accessibility::Public,
                        msig! { void (float[]) },
                        "set_OptionalProperty",
                        Some(body::Method::new(asm! {
                            LoadArgument 0;
                            LoadArgument 1;
                            store_field optional_prop_backing;
                            Return;
                        })),
                    )),
                    ..Property::new(false, "OptionalProperty", Parameter::value(ctype! { float[] }))
                },
            );
            let get_optional_property = ctx.resolution.set_property_getter(
                optional_property,
                Method::new(
                    Accessibility::Public,
                    msig! { float[] () },
                    "get_OptionalProperty",
                    Some(body::Method::new(asm! {
                        LoadArgument 0;
                        load_field optional_prop_backing;
                        Return;
                    })),
                ),
            );

            let test_ctor = ctx.resolution.push_method(
                test_attr,
                Method::constructor(
                    Accessibility::Public,
                    msig! { void (string) },
                    Some(body::Method::new(asm! {
                        LoadArgument 0;
                        call attr_ctor;
                        LoadArgument 0;
                        LoadArgument 1;
                        store_field required;
                        Return;
                    })),
                ),
            );

            ctx.resolution[ctx.class].attributes.extend([
                Attribute::new(
                    test_ctor.into(),
                    CustomAttributeData {
                        constructor_args: vec![FixedArg::String(Some("a"))],
                        named_args: vec![],
                    },
                ),
                Attribute::new(
                    test_ctor.into(),
                    CustomAttributeData {
                        constructor_args: vec![FixedArg::String(Some("b"))],
                        named_args: vec![NamedArg::Field(
                            "OptionalField",
                            FixedArg::Integral(IntegralParam::Int32(1)),
                        )],
                    },
                ),
                Attribute::new(
                    test_ctor.into(),
                    CustomAttributeData {
                        constructor_args: vec![FixedArg::String(Some("c"))],
                        named_args: vec![NamedArg::Property(
                            "OptionalProperty",
                            FixedArg::Array(Some(vec![FixedArg::Float32(3.14), FixedArg::Float32(6.28)])),
                        )],
                    },
                ),
            ]);

            let type_t: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Type in #mscorlib }),
            )
            .into();
            let type_handle = BaseType::valuetype(
                ctx.resolution
                    .push_type_reference(type_ref! { System.RuntimeTypeHandle in #mscorlib }),
            )
            .into();
            let get_type = ctx
                .resolution
                .push_method_reference(method_ref! { static @type_t @type_t::GetTypeFromHandle(#type_handle) });

            let member_info = BaseType::class(ctx.resolution
                .push_type_reference(type_ref! { System.Reflection.MemberInfo in #mscorlib })).into();

            let console = BaseType::class(ctx.console).into();
            let test_attr_t: MethodType = BaseType::class(test_attr).into();

            (
                vec![
                    LocalVariable::new(ctype! { object[] }),
                    LocalVariable::new(ctype! { int }),
                    LocalVariable::new(test_attr_t.clone()),
                    LocalVariable::new(ctype! { float[] }),
                    LocalVariable::new(ctype! { object[] }),
                    LocalVariable::new(ctype! { int }),
                ],
                asm! {
                    load_token_type BaseType::class(ctx.class);
                    call get_type;
                    LoadTokenType test_attr_t;
                    call get_type;
                    LoadConstantInt32 0;
                    call_virtual ctx
                        .resolution
                        .push_method_reference(method_ref! { object[] #member_info::GetCustomAttributes(@type_t, bool) });
                    StoreLocal 0;
                @condition
                    LoadLocal 1;
                    LoadLocal 0;
                    LoadLength;
                    BranchGreaterOrEqual NumberSign::Unsigned, ret;
                    // loop body
                    LoadLocal 0;
                    LoadLocal 1;
                    load_element BaseType::Object;
                    StoreLocal 2;
                    load_string "{0}|{1}|{2}";
                    LoadLocal 2;
                    load_field required;
                    LoadLocal 2;
                    load_field optional_field;
                    BoxValue ctype! { int };
                    LoadLocal 2;
                    call get_optional_property;
                    Duplicate;
                    BranchFalsy call;
                    StoreLocal 3;
                    LoadLocal 3;
                    LoadLength;
                    NewArray ctype! { object };
                    StoreLocal 4;
                @cast_cond
                    LoadLocal 5;
                    LoadLocal 3;
                    LoadLength;
                    BranchGreaterOrEqual NumberSign::Unsigned, cast_end;
                    // loop body
                    LoadLocal 4;
                    LoadLocal 5;
                    LoadLocal 3;
                    LoadLocal 5;
                    load_element BaseType::Float32;
                    BoxValue ctype! { float };
                    store_element BaseType::Object;
                    // increment counter
                    LoadLocal 5;
                    LoadConstantInt32 1;
                    Add;
                    StoreLocal 5;
                    Branch cast_cond;
                @cast_end
                    load_string ", ";
                    LoadLocal 4;
                    call ctx.resolution.push_method_reference(method_ref! { static string string::Join(string, object[]) });
                @call
                    call ctx.resolution.push_method_reference(method_ref! { static void #console::WriteLine(string, object, object, object) });
                    // increment
                    LoadLocal 1;
                    LoadConstantInt32 1;
                    Add;
                    StoreLocal 1;
                    Branch condition;
                @ret
                    Return;
                },
            )
        },
        b"a|0|\nb|1|\nc|0|3.14, 6.28\n",
    )
    .unwrap();
}
