use super::members;

#[derive(Debug)]
pub enum TypeKind {
    Class,
    Interface,
    ValueType,
}

#[derive(Debug)]
pub struct TypeDefinition<'a> {
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub kind: TypeKind,
    pub fields: Vec<members::Field<'a>>,
    pub properties: Vec<members::Property<'a>>,
    pub methods: Vec<members::Method<'a>>, // TODO: flags, extends, generic params
}

#[derive(Debug)]
pub struct ExternalTypeReference<'a> {
    pub name: &'a str,
    pub namespace: Option<&'a str>, // TODO: resolution scope
}

// I believe TypeSpec can *probably* be specialized for each usage
//   TypeDef cannot extend primitives
//   Field cannot use method generics
//   etc
// so I'm hesitant to wrap it in a single type for everything
// because that would force consumers to handle illegal states
