use dotnetdll::prelude::*;

mod common;

#[test]
pub fn write() {
    common::write_fixture(
        "oop",
        |ctx| {
            let ivehicle = ctx
                .resolution
                .push_type_definition(TypeDefinition::new(None, "IVehicle"));
            ctx.resolution[ivehicle].flags.kind = Kind::Interface;
            ctx.resolution[ivehicle].flags.abstract_type = true;
            let max_distance = ctx.resolution.push_method(
                ivehicle,
                Method {
                    virtual_member: true,
                    abstract_member: true,
                    ..Method::new(Accessibility::Public, msig! { int () }, "MaxDistance", None)
                },
            );

            let bike = ctx.resolution.push_type_definition(TypeDefinition::new(None, "Bike"));
            let bike_ctor = ctx.resolution.add_default_ctor(bike);
            ctx.resolution[bike].extends = Some(ctx.object.into());
            ctx.resolution[bike].add_implementation(ivehicle);
            ctx.resolution.push_method(
                bike,
                Method {
                    virtual_member: true,
                    ..Method::new(
                        Accessibility::Public,
                        msig! { int () },
                        "MaxDistance",
                        Some(body::Method::new(asm! {
                            LoadConstantInt32 20;
                            Return;
                        })),
                    )
                },
            );

            let motor_vehicle = ctx
                .resolution
                .push_type_definition(TypeDefinition::new(None, "MotorVehicle"));
            ctx.resolution[motor_vehicle].flags.abstract_type = true;
            ctx.resolution[motor_vehicle].add_implementation(ivehicle);
            ctx.resolution[motor_vehicle].extends = Some(ctx.object.into());
            let tank_size = ctx.resolution.push_method(
                motor_vehicle,
                Method {
                    virtual_member: true,
                    abstract_member: true,
                    ..Method::new(access! { protected }, msig! { float () }, "TankSize", None)
                },
            );
            let gas_mileage = ctx.resolution.push_method(
                motor_vehicle,
                Method::new(
                    Accessibility::Public,
                    msig! { int () },
                    "GasMileage",
                    Some(body::Method::new(asm! {
                        LoadArgument 0;
                        call_virtual tank_size;
                        LoadConstantFloat32 25.0;
                        Multiply;
                        Convert ConversionType::Int32;
                        Return;
                    })),
                ),
            );
            ctx.resolution[gas_mileage].virtual_member = true;
            ctx.resolution[motor_vehicle].overrides.push(MethodOverride {
                implementation: gas_mileage.into(),
                declaration: max_distance.into(),
            });

            let car = ctx.resolution.push_type_definition(TypeDefinition::new(None, "Car"));
            ctx.resolution[car].extends = Some(motor_vehicle.into());
            ctx.resolution.push_method(
                car,
                Method {
                    virtual_member: true,
                    ..Method::new(
                        access! { protected },
                        msig! { float () },
                        "TankSize",
                        Some(body::Method::new(asm! {
                            LoadConstantFloat32 20.0;
                            Return;
                        })),
                    )
                },
            );
            let car_ctor = ctx.resolution.add_default_ctor(car);

            let mscorlib = ctx.mscorlib;
            let ilist: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Collections.IList in #mscorlib }),
            )
            .into();
            let array_list: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Collections.ArrayList in #mscorlib }),
            )
            .into();
            let add = ctx
                .resolution
                .push_method_reference(method_ref! { int #ilist::Add(object) });
            let enumerator: MethodType = BaseType::class(
                ctx.resolution
                    .push_type_reference(type_ref! { System.Collections.IEnumerator in #mscorlib }),
            )
            .into();

            let console: MethodType = BaseType::class(ctx.console).into();

            (
                vec![],
                vec![LocalVariable::new(array_list.clone()), LocalVariable::new(enumerator.clone())],
                asm! {
                    new_object ctx.resolution.push_method_reference(method_ref! { void @array_list::.ctor() });
                    StoreLocal 0;
                    LoadLocal 0;
                    new_object bike_ctor;
                    cast_class BaseType::Object;
                    call_virtual add;
                    Pop;
                    LoadLocal 0;
                    new_object car_ctor;
                    cast_class BaseType::Object;
                    call_virtual add;
                    Pop;
                    LoadLocal 0;
                    call_virtual ctx.resolution.push_method_reference(method_ref! { @enumerator #array_list::GetEnumerator() });
                    StoreLocal 1;
                    Branch condition;
                @loop_body
                    LoadLocal 1;
                    call_virtual ctx.resolution.push_method_reference(method_ref! { object @enumerator::get_Current() });
                    cast_class BaseType::class(ivehicle);
                    call_virtual max_distance;
                    BoxValue ctype! { int };
                    call ctx.resolution.push_method_reference(method_ref! { static void #console::WriteLine(object) });
                @condition
                    LoadLocal 1;
                    call_virtual ctx.resolution.push_method_reference(method_ref! { bool @enumerator::MoveNext() });
                    BranchTruthy loop_body;
                    Return;
                },
            )
        },
        b"20\n500\n",
    )
    .unwrap();
}
