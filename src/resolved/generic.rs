use super::{attribute::Attribute, types};

#[derive(Debug)]
pub enum Variance {
    Invariant,
    Covariant,
    Contravariant,
}

#[derive(Debug)]
pub enum SpecialConstraint {
    ReferenceType,
    ValueType,
    HasDefaultConstructor,
}

#[derive(Debug)]
pub struct Generic<'a, ConstraintType> {
    pub attributes: Vec<Attribute<'a>>,
    pub name: &'a str,
    pub variance: Variance,
    pub special_constraint: (Vec<Attribute<'a>>, SpecialConstraint),
    pub type_constraint: (Vec<Attribute<'a>>, ConstraintType),
}

pub type TypeGeneric<'a> = Generic<'a, types::MemberType<'a>>;
pub type MethodGeneric<'a> = Generic<'a, types::MethodType<'a>>;
