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
            let list_t: MethodType = BaseType::class(TypeSource::Generic {
                base: list.into(),
                parameters: vec![ctype! { M0 }],
            })
            .into();
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
            let create_instance = GenericMethodInstantiation {
                base: ref_index.into(),
                parameters: vec![ctype! { M0 }],
            };

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

            let init_class = GenericMethodInstantiation {
                base: init.into(),
                parameters: vec![BaseType::class(ctx.class).into()],
            };

            let ienum = ctx
                .resolution
                .push_type_reference(type_ref! { System.Collections.Generic.IEnumerable<1> in #mscorlib });
            let ienum_class: MethodType = BaseType::class(TypeSource::Generic {
                base: ienum.into(),
                parameters: vec![BaseType::class(ctx.class).into()],
            })
            .into();
            let generic_enumerator = ctx
                .resolution
                .push_type_reference(type_ref! { System.Collections.Generic.IEnumerator<1> in #mscorlib });
            let enum_t: MethodType = BaseType::class(TypeSource::Generic {
                base: generic_enumerator.into(),
                parameters: vec![ctype! { T0 }],
            })
            .into();
            let get_enum = ctx.resolution.push_method_reference(method_ref! {
                #enum_t #ienum_class::GetEnumerator()
            });
            let enum_class: MethodType = BaseType::class(TypeSource::Generic {
                base: generic_enumerator.into(),
                parameters: vec![BaseType::class(ctx.class).into()],
            })
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

            (
                vec![],
                vec![LocalVariable::new(enum_class)],
                asm! {
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
            )
        },
        b"0\n1\n2\n3\n4\n",
    )
    .unwrap();
}
