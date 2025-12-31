use super::{attribute::Attribute, types, ResolvedDebug};
use crate::resolution::Resolution;
use std::borrow::Cow;

/// Specifies the variance of a generic parameter.
///
/// See ECMA-335, II.9.3 (page 139) for more information.
#[derive(Debug, Copy, Clone)]
pub enum Variance {
    /// The parameter is invariant.
    Invariant,
    /// The parameter is covariant (marked with `+` in ILAsm, `out` in C#).
    Covariant,
    /// The parameter is contravariant (marked with `-` in ILAsm, `in` in C#).
    Contravariant,
}

/// Represents special constraints on a generic parameter.
///
/// See ECMA-335, II.22.20 (page 229) for more information.
#[derive(Debug, Copy, Clone, Default)]
pub struct SpecialConstraint {
    /// If true, the parameter must be a reference type (`class` constraint in C#).
    pub reference_type: bool,
    /// If true, the parameter must be a value type (`struct` constraint in C#).
    pub value_type: bool,
    /// If true, the parameter must have a public parameterless constructor (`new()` constraint in C#).
    pub has_default_constructor: bool,
}
impl SpecialConstraint {
    /// Returns true if no special constraints are set.
    pub fn is_empty(&self) -> bool {
        !(self.reference_type || self.value_type || self.has_default_constructor)
    }
}

/// A type constraint on a generic parameter.
///
/// See ECMA-335, II.22.21 (page 230) for more information.
#[derive(Debug, Clone)]
pub struct Constraint<'a, ConstraintType> {
    /// All attributes present on the generic parameter's constraint.
    pub attributes: Vec<Attribute<'a>>,
    /// Custom type modifiers associated with the constraint type.
    pub custom_modifiers: Vec<types::CustomTypeModifier>,
    /// The type that the generic parameter must derive from or implement.
    pub constraint_type: ConstraintType,
}

/// A generic parameter for a type or method.
///
/// See ECMA-335, II.22.20 (page 229) for more information.
#[derive(Debug, Clone)]
pub struct Generic<'a, ConstraintType> {
    /// All attributes present on the generic parameter's declaration.
    pub attributes: Vec<Attribute<'a>>,
    /// Name of the generic parameter.
    pub name: Cow<'a, str>,
    /// Variance of the generic parameter.
    pub variance: Variance,
    /// Special constraints (reference, value, or default constructor) on the parameter.
    pub special_constraint: SpecialConstraint,
    /// Type constraints (base classes or interfaces) on the parameter.
    pub type_constraints: Vec<Constraint<'a, ConstraintType>>,
}

impl<'a, T> Generic<'a, T> {
    pub fn new(name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            attributes: vec![],
            name: name.into(),
            variance: Variance::Invariant,
            special_constraint: SpecialConstraint::default(),
            type_constraints: vec![],
        }
    }
}

pub type Type<'a> = Generic<'a, types::MemberType>;
pub type Method<'a> = Generic<'a, types::MethodType>;

impl<T: ResolvedDebug> ResolvedDebug for Vec<Generic<'_, T>> {
    fn show(&self, _: &Resolution) -> String {
        use std::fmt::Write;

        let mut buf = String::new();

        if !self.is_empty() {
            write!(
                buf,
                "<{}>",
                self.iter().map(|p| p.name.as_ref()).collect::<Vec<&str>>().join(", ")
            )
            .unwrap();
        }

        buf
    }
}

pub fn show_constraints<T: ResolvedDebug>(v: &[Generic<'_, T>], res: &Resolution) -> Option<String> {
    if v.iter()
        .any(|g| !(g.special_constraint.is_empty() && g.type_constraints.is_empty()))
    {
        Some(
            v.iter()
                .map(|g| {
                    let mut constraints = Vec::new();
                    if g.special_constraint.reference_type {
                        constraints.push("class".to_string());
                    }
                    if g.special_constraint.value_type {
                        constraints.push("struct".to_string());
                    }
                    if g.special_constraint.has_default_constructor {
                        constraints.push("new()".to_string());
                    }
                    constraints.extend(g.type_constraints.iter().map(|t| t.constraint_type.show(res)));

                    if constraints.is_empty() {
                        String::new()
                    } else {
                        format!("where {} : {}", g.name, constraints.join(", "))
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        )
    } else {
        None
    }
}
