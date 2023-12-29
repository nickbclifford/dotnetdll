use dotnetdll::prelude::*;

#[macro_use]
mod common;

#[test]
pub fn read() {
    common::read_fixture(
        "generics",
        r#"
        .class Container<T> {
            .field public !T Value
            .method public class Container<!!M> Restricted<+ class M, ([mscorlib]System.IDisposable) D>(!!M) {  }
        }
        "#,
        |res| {
            let container = &res.type_definitions[1];
            assert_eq!(container.generic_parameters[0].name, "T");
            assert_eq!(container.fields[0].return_type, ctype! { T0 });

            let method = &container.methods[0];
            assert_inner_eq!(method.generic_parameters[0], {
                variance => generic::Variance::Covariant,
                name: "M",
                special_constraint => generic::SpecialConstraint { reference_type: true, .. }
            });
            assert!(
                matches!(&method.generic_parameters[1].type_constraints[0].constraint_type,
                MethodType::Base(b) if matches!(&**b,
                    BaseType::Type { source: TypeSource::User(u), .. } if u.type_name(&res) == "System.IDisposable"))
            );

            let (inst_base, inst_params) = match &method.signature.return_type.1 {
                Some(ParameterType::Value(MethodType::Base(b))) => match &**b {
                    BaseType::Type {
                        source: TypeSource::Generic { base, parameters },
                        ..
                    } => (base, parameters),
                    rest => panic!("expected generic instantiation , got {:?}", rest),
                },
                rest => panic!("expected MethodType::Base return type, got {:?}", rest),
            };
            assert!(matches!(inst_base, UserType::Definition(i) if std::ptr::eq(&res[*i], container)));
            assert_eq!(inst_params[0], ctype! { M0 });
        },
    )
    .unwrap();
}

#[test]
pub fn write() {
    common::write_fixture(
        "generics",
        |ctx| {
            let count = ctx.resolution.push_field(
                ctx.class,
                Field::new(true, Accessibility::Private, "count", ctype! { int }),
            );
            let my_count = ctx.resolution.push_field(
                ctx.class,
                Field::new(false, Accessibility::Public, "MyCount", ctype! { int }),
            );

            let ctor_body = &mut ctx.resolution[ctx.default_ctor].body.as_mut().unwrap().instructions;
            ctor_body.pop(); // remove ret we automatically inserted
            ctor_body.extend(asm! {
                LoadArgument 0;
                load_static_field count;
                Duplicate;
                LoadConstantInt32 1;
                Add;
                store_static_field count;
                store_field my_count;
                Return;
            });

            let mscorlib = ctx.mscorlib;

            let list = ctx
                .resolution
                .push_type_reference(type_ref! { System.Collections.Generic.List<1> in #mscorlib });
            let list_t: MethodType = BaseType::class(TypeSource::generic(list, vec![ctype! { M0 }])).into();
            let list_ctor = ctx
                .resolution
                .push_method_reference(method_ref! { void @list_t::.ctor() });
            let list_add = ctx
                .resolution
                .push_method_reference(method_ref! { void @list_t::Add(T0) });

            let activator: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Activator in #mscorlib }),
            )
            .into();
            let ref_index = ctx
                .resolution
                .push_method_reference(method_ref! { static M0 #activator::CreateInstance<1>() });
            let create_instance = GenericMethodInstantiation::new(ref_index, vec![ctype! { M0 }]);

            let init = ctx.resolution.push_method(
                ctx.class,
                Method::new(
                    Accessibility::Public,
                    msig! { static @list_t (int) },
                    "Init",
                    Some(body::Method::with_locals(
                        vec![LocalVariable::new(list_t), LocalVariable::new(ctype! { int })],
                        asm! {
                            new_object list_ctor;
                            StoreLocal 0;
                            LoadConstantInt32 0;
                            StoreLocal 1;
                            Branch condition;
                        @loop_body
                            LoadLocal 0;
                            call create_instance;
                            call_virtual list_add;
                            LoadLocal 1;
                            LoadConstantInt32 1;
                            Add;
                            StoreLocal 1;
                        @condition
                            LoadLocal 1;
                            LoadArgument 0;
                            BranchLess NumberSign::Signed, loop_body;
                            LoadLocal 0;
                            Return;
                        },
                    )),
                ),
            );
            ctx.resolution[init].generic_parameters.push({
                let mut t = generic::Method::new("T");
                t.special_constraint.has_default_constructor = true;
                t
            });

            let init_class = GenericMethodInstantiation::new(init, vec![BaseType::class(ctx.class).into()]);

            let ienum = ctx
                .resolution
                .push_type_reference(type_ref! { System.Collections.Generic.IEnumerable<1> in #mscorlib });
            let ienum_class: MethodType =
                BaseType::class(TypeSource::generic(ienum, vec![BaseType::class(ctx.class).into()])).into();
            let generic_enumerator = ctx
                .resolution
                .push_type_reference(type_ref! { System.Collections.Generic.IEnumerator<1> in #mscorlib });
            let enum_t: MethodType =
                BaseType::class(TypeSource::generic(generic_enumerator, vec![ctype! { T0 }])).into();
            let get_enum = ctx.resolution.push_method_reference(method_ref! {
                #enum_t #ienum_class::GetEnumerator()
            });
            let enum_class: MethodType = BaseType::class(TypeSource::generic(
                generic_enumerator,
                vec![BaseType::class(ctx.class).into()],
            ))
            .into();
            let get_current = ctx
                .resolution
                .push_method_reference(method_ref! { T0 @enum_class::get_Current() });

            let enumerator: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Collections.IEnumerator in #mscorlib }),
            )
            .into();
            let move_next = ctx
                .resolution
                .push_method_reference(method_ref! { bool #enumerator::MoveNext() });

            let console_type: MethodType = BaseType::class(ctx.console).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console_type::WriteLine(string, object) });

            common::WriteTestResult::WithVariables {
                locals: vec![LocalVariable::new(enum_class)],
                main_body: asm! {
                    LoadConstantInt32 5;
                    call init_class;
                    call_virtual get_enum;
                    StoreLocal 0;
                    Branch condition;
                @loop_body
                    load_string "{0}";
                    LoadLocal 0;
                    call_virtual get_current;
                    load_field my_count;
                    BoxValue ctype! { int };
                    call write_line;
                @condition
                    LoadLocal 0;
                    call_virtual move_next;
                    BranchTruthy loop_body;
                    Return;
                },
            }
        },
        b"0\n1\n2\n3\n4\n",
    )
    .unwrap();
}

#[test]
pub fn write_generic_class() {
    common::write_fixture(
        "generics",
        |ctx| {
            let container = ctx
                .resolution
                .push_type_definition(TypeDefinition::new(None, "Container"));
            ctx.ctor_cache.define_default_ctor(&mut ctx.resolution, container);
            ctx.resolution[container]
                .generic_parameters
                .push(generic::Type::new("T"));
            ctx.resolution[container].flags.before_field_init = true;
            ctx.resolution[container].extends = Some(ctx.object.into());

            let arr_field = ctx.resolution.push_field(
                container,
                Field::new(false, Accessibility::Public, "inner", ctype! { T0[] }),
            );

            let mscorlib = ctx.mscorlib;
            let ienum = ctx
                .resolution
                .push_type_reference(type_ref! { System.Collections.Generic.IEnumerable<1> in #mscorlib });

            let ienum_inst: MethodType = BaseType::class(TypeSource::generic(ienum, vec![ctype! { M0 }])).into();
            let string_join = ctx
                .resolution
                .push_method_reference(method_ref! { static string string::Join<1>(string, #ienum_inst) });
            let string_join_inst = GenericMethodInstantiation::new(string_join, vec![ctype! { T0 }]);

            let to_string = ctx.resolution.push_method(
                container,
                Method::new(
                    Accessibility::Public,
                    msig! { string () },
                    "ToString",
                    Some(body::Method::new(asm! {
                        load_string ",";
                        LoadArgument 0;
                        load_field arr_field;
                        call string_join_inst;
                        Return;
                    })),
                ),
            );

            let console_type: MethodType = BaseType::class(ctx.console).into();
            let write_line = ctx
                .resolution
                .push_method_reference(method_ref! { static void #console_type::WriteLine(string) });

            let int_container: MethodType =
                BaseType::class(TypeSource::generic(container, vec![ctype! { int }])).into();
            let string_container: MethodType =
                BaseType::class(TypeSource::generic(container, vec![ctype! { string }])).into();

            common::WriteTestResult::WithVariables {
                locals: vec![
                    LocalVariable::new(int_container.clone()),
                    LocalVariable::new(string_container.clone()),
                ],
                main_body: asm! {
                    new_object ctx.resolution.push_method_reference(method_ref! { void @int_container::.ctor() });
                    StoreLocal 0;
                    new_object ctx.resolution.push_method_reference(method_ref! { void @string_container::.ctor() });
                    StoreLocal 1;
                    LoadLocal 0;
                    LoadConstantInt32 3;
                    new_array BaseType::Int32;
                    Duplicate;
                    LoadConstantInt32 0;
                    LoadConstantInt32 1;
                    store_element_primitive StoreType::Int32;
                    Duplicate;
                    LoadConstantInt32 1;
                    LoadConstantInt32 2;
                    store_element_primitive StoreType::Int32;
                    Duplicate;
                    LoadConstantInt32 2;
                    LoadConstantInt32 3;
                    store_element_primitive StoreType::Int32;
                    store_field arr_field;
                    LoadLocal 1;
                    LoadConstantInt32 3;
                    new_array BaseType::String;
                    Duplicate;
                    LoadConstantInt32 0;
                    load_string "foo";
                    store_element BaseType::String;
                    Duplicate;
                    LoadConstantInt32 1;
                    load_string "bar";
                    store_element BaseType::String;
                    Duplicate;
                    LoadConstantInt32 2;
                    load_string "baz";
                    store_element BaseType::String;
                    store_field arr_field;
                    LoadLocal 0;
                    call ctx.resolution.push_method_reference(method_ref! { string #int_container::ToString() });
                    call write_line;
                    LoadLocal 1;
                    call ctx.resolution.push_method_reference(method_ref! { string #string_container::ToString() });
                    call write_line;
                    Return;
                },
            }
        },
        b"1,2,3\nfoo,bar,baz\n",
    )
    .unwrap();
}
