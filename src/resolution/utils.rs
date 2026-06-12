use crate::prelude::*;

/// Cache for constructor references commonly needed while building a [`Resolution`].
///
/// This helper currently caches `System.Object::.ctor`, which is reused by
/// [`ConstructorCache::define_default_ctor`]. Caching avoids emitting duplicate
/// method-reference rows when multiple generated constructors call the same base constructor.
#[derive(Debug, Default, Copy, Clone)]
pub struct ConstructorCache {
    /// Cached method reference for `void object::.ctor()`.
    pub object_ctor_ref: Option<MethodRefIndex>,
}

impl ConstructorCache {
    /// Creates an empty constructor cache.
    pub fn new() -> Self {
        ConstructorCache::default()
    }

    /// Returns a cached method reference to `System.Object::.ctor`, creating it if needed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotnetdll::prelude::*;
    ///
    /// let mut res = Resolution::new(Module::new("Example.dll"));
    /// let mut cache = ConstructorCache::new();
    ///
    /// let first = cache.get_object_ctor(&mut res);
    /// let second = cache.get_object_ctor(&mut res);
    ///
    /// assert_eq!(first, second);
    /// assert_eq!(res.method_references.len(), 1);
    /// assert_eq!(res[first].name, ".ctor");
    /// ```
    pub fn get_object_ctor(&mut self, res: &mut Resolution) -> MethodRefIndex {
        *self
            .object_ctor_ref
            .get_or_insert_with(|| res.push_method_reference(method_ref! { void object::.ctor() }))
    }

    /// Defines a public parameterless instance constructor on `class`.
    ///
    /// The generated method body loads `this`, calls `System.Object::.ctor`, and returns.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotnetdll::prelude::*;
    ///
    /// let mut res = Resolution::new(Module::new("Example.dll"));
    /// let class = res.push_type_definition(TypeDefinition::new(Some("Demo".into()), "Widget"));
    ///
    /// let mut cache = ConstructorCache::new();
    /// let ctor = cache.define_default_ctor(&mut res, class);
    ///
    /// assert_eq!(res[class].methods.len(), 1);
    /// assert_eq!(res[ctor].name, ".ctor");
    /// assert!(res[ctor].body.is_some());
    /// assert!(cache.object_ctor_ref.is_some());
    /// ```
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
