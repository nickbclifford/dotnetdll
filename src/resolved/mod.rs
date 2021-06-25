pub mod assembly;
pub mod attribute;
pub mod body;
pub mod generic;
pub mod il;
pub mod members;
pub mod module;
pub mod resource;
pub mod signature;
pub mod types;

#[derive(Debug)]
pub enum Accessibility {
    Private,
    PrivateProtected,  // FamANDAssem
    Internal,          // Assem
    Protected,         // Family
    ProtectedInternal, // FamORAssem
    Public,
}
