use super::{attribute::Attribute, types};

#[derive(Debug)]
pub enum Variance {
    Invariant,
    Covariant,
    Contravariant,
}

#[derive(Debug)]
pub struct SpecialConstraint {
    pub reference_type: bool,
    pub value_type: bool,
    pub has_default_constructor: bool,
}

#[derive(Debug)]
pub struct Generic<'a, ConstraintType> {
    pub attributes: Vec<Attribute<'a>>,
    pub sequence: usize,
    pub name: &'a str,
    pub variance: Variance,
    pub special_constraint: SpecialConstraint,
    pub type_constraints: (Vec<Attribute<'a>>, Vec<ConstraintType>),
}

pub type TypeGeneric<'a> = Generic<'a, types::MemberType>;
pub type MethodGeneric<'a> = Generic<'a, types::MethodType>;
