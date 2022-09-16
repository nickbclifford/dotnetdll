pub type Ident = String;

#[derive(Debug, Clone)]
pub struct Dotted(pub Vec<Ident>);

#[derive(Debug, Clone)]
pub struct Version(pub Vec<u32>);
#[derive(Debug, Clone)]
pub struct AssemblySpec {
    pub assembly: Dotted,
    pub version: Option<Version>,
}

#[derive(Debug, Clone)]
pub enum IntType {
    Bool,
    Char,
    SByte,
    Byte,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    NInt,
    NUInt,
}
#[derive(Debug, Clone)]
pub struct TypeReference {
    pub parent: Option<Dotted>,
    pub target: Dotted,
}
#[derive(Debug, Clone)]
pub enum Type {
    Integer(IntType),
    String,
    Object,
    Float,
    Double,
    RefType(TypeReference),
    ValueType(TypeReference),
    Vector(Box<Type>),
    Pointer(Option<Box<Type>>),
}

#[derive(Debug, Clone)]
pub struct Enum {
    pub base: Option<IntType>,
    pub name: Dotted,
    pub members: Vec<Ident>,
}

#[derive(Debug, Clone)]
pub enum Access {
    Public,
    Private,
    PrivateProtected,
    Protected,
    ProtectedInternal,
    Internal,
}

#[derive(Debug, Clone)]
pub struct Locals {
    pub init: bool,
    pub variables: Vec<(Type, Ident)>,
}
#[derive(Debug, Clone)]
pub struct MethodRef {
    pub r#static: bool,
    pub return_type: Option<ParamType>,
    pub parent: Type,
    pub method: Ident,
    pub parameters: Vec<ParamType>,
}
#[derive(Debug, Clone)]
pub enum Instruction {
    New(Type, Vec<ParamType>),
    Call(MethodRef),
    Return,
    LoadString(String)
}
pub type Label = Ident;
#[derive(Debug, Clone)]
pub struct MethodBody {
    pub max_stack: Option<u32>,
    pub locals: Option<Locals>,
    pub instructions: Vec<(Vec<Label>, Instruction)>,
}

#[derive(Debug, Clone)]
pub struct ParamType {
    pub r#ref: bool,
    pub r#type: Type,
}
#[derive(Debug, Clone)]
pub struct Method {
    pub name: Ident,
    pub parameters: Vec<(ParamType, Ident)>,
    pub return_type: Option<ParamType>,
    pub body: Option<MethodBody>,
}

#[derive(Debug, Clone)]
pub struct Field(pub Type, pub Ident);

#[derive(Debug, Clone)]
pub struct SemanticMethod(pub Ident, pub MethodBody);
#[derive(Debug, Clone)]
pub struct Property {
    pub r#type: Type,
    pub name: Ident,
    pub methods: Vec<SemanticMethod>,
}
#[derive(Debug, Clone)]
pub struct Event {
    pub r#type: Type,
    pub name: Ident,
    pub methods: Vec<SemanticMethod>,
}

#[derive(Debug, Clone)]
pub enum TypeItemKind {
    Field(Field),
    Method(Method),
    Property(Property),
    Event(Event)
}
#[derive(Debug, Clone)]
pub struct TypeItem {
    pub access: Access,
    pub r#static: bool,
    pub kind: TypeItemKind,
}
#[derive(Debug, Clone)]
pub enum TypeKind {
    Class { r#abstract: bool },
    Struct,
    Interface,
}
#[derive(Debug, Clone)]
pub struct TypeDeclaration {
    pub kind: TypeKind,
    pub name: Dotted,
    pub extends: Option<TypeReference>,
    pub implements: Option<Vec<TypeReference>>,
    pub items: Vec<TypeItem>,
}

#[derive(Debug, Clone)]
pub enum TopLevelKind {
    Enum(Enum),
    Type(TypeDeclaration),
}
#[derive(Debug, Clone)]
pub struct TopLevel {
    pub public: bool,
    pub kind: TopLevelKind,
}

#[derive(Debug, Clone)]
pub struct Assembly {
    pub assembly_decl: AssemblySpec,
    pub extern_decls: Vec<AssemblySpec>,
    pub top_level_decls: Vec<TopLevel>,
}