use dotnetdll::prelude::*;

mod common;

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
            ctor_body.extend(common::asm! {
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
                        common::asm! {
                            new_object list_ctor;
                            StoreLocal 0;
                            LoadConstantInt32 0;
                            StoreLocal 1;
                            Branch 12;
                            LoadLocal 0;
                            call create_instance;
                            call_virtual list_add;
                            LoadLocal 1;
                            LoadConstantInt32 1;
                            Add;
                            StoreLocal 1;
                            LoadLocal 1;
                            LoadArgument 0;
                            BranchLess NumberSign::Signed, 5;
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
                vec![LocalVariable::new(enum_class)],
                common::asm! {
                    LoadConstantInt32 5;
                    call init_class;
                    call_virtual get_enum;
                    StoreLocal 0;
                    Branch 11;
                    load_string "{0}";
                    LoadLocal 0;
                    call_virtual get_current;
                    load_field my_count;
                    BoxValue ctype! { int };
                    call write_line;
                    LoadLocal 0;
                    call_virtual move_next;
                    BranchTruthy 5;
                    Return;
                },
            )
        },
        b"0\n1\n2\n3\n4\n",
    )
    .unwrap();
}
