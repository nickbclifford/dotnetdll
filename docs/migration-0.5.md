# Migrating to dotnetdll 0.5

Update the dependency requirement:

```toml
[dependencies]
dotnetdll = "0.5"
```

## Combined `constrained.` and `tail.` virtual calls

The resolved IL instruction enum now includes
`Instruction::CallVirtualConstrainedTail(MethodType, MethodSource)`. The first
operand is the constraint type and the second is the method to call. Use it when
both prefixes apply to a `callvirt`. `CallVirtualConstrained` and
`CallVirtualTail` continue to represent each prefix alone.

Reading accepts either prefix order. Writing emits `constrained.` followed by
`tail.`; the original prefix order is not retained. The instruction occupies a
single resolved instruction index, including when it is a branch target.

Exhaustive matches on `resolved::il::Instruction` must handle the new variant.
Exhaustive matches on `binary::il::Instruction` must handle
`ConstrainedTailCallvirt` and `TailConstrainedCallvirt`, whose operands are the
constraint token and method token. Each binary variant preserves its prefix order.

Rust 1.85.1 remains the minimum supported compiler. The `dotnetdll-macros`
dependency remains at 0.2.1.
