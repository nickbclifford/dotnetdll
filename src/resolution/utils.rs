use crate::prelude::*;

#[derive(Debug, Default, Copy, Clone)]
pub struct ConstructorCache {
    pub object_ctor_ref: Option<MethodRefIndex>,
}

impl ConstructorCache {
    pub fn new() -> Self {
        ConstructorCache::default()
    }

    pub fn get_object_ctor(&mut self, res: &mut Resolution) -> MethodRefIndex {
        *self
            .object_ctor_ref
            .get_or_insert_with(|| res.push_method_reference(method_ref! { void object::.ctor() }))
    }

    pub fn define_default_ctor(&mut self, res: &mut Resolution, class: TypeIndex) -> MethodIndex {
        let object_ctor = self.get_object_ctor(res);
        res.push_method(
            class,
            Method::constructor(
                Accessibility::Public,
                vec![],
                Some(body::Method::new(asm! {
                    LoadArgument 0;
                    call object_ctor;
                    Return;
                })),
            ),
        )
    }
}
