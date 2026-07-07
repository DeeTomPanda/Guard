# Call Graph Design

This note explains the current call graph / resolution data structures in the Guard repo and how they flow together.

## Key concepts

### `Symbol`
- Declares program entities: functions, methods, variables, parameters, imports, classes, structs.
- Represents "what exists" in the code.
- Example: `main`, `foo`, `x`, `y`, `z`.

### `CallSite`
- Represents a call expression in source code.
- Contains:
  - `caller`: the function that performs the call
  - `callee`: the function being called
  - `arguments`: the raw argument values
  - `file`, `line`, `column`: source location
- Example: inside `main`, the expression `foo(y)` becomes a `CallSite`.

### `ResolvedCall` / `ResolutionTable`
- `ResolutionTable` holds `Vec<ResolvedCall>`.
- `ResolvedCall` wraps a `CallSite` plus resolved argument data.
- `ResolvedArgument` records:
  - raw argument text
  - optional resolved symbol
  - optional `assigned_from` provenance
- This is the semantic layer: it answers questions like "what symbol does this argument refer to?" and "where did this variable value come from?"

## Graph view

A classic call graph is usually modeled as:
- nodes = functions / methods (symbols)
- edges = callsites

For example:

```rust
fn main() {
    let x = 1;
    let y = x;
    foo(y);
}

fn foo(z: i32) { }
```

Graph structure:
- node: `main`
- node: `foo`
- edge from `main` to `foo` labeled with callsite `foo(y)`

### Why `main -> foo`?
- `main` is the caller
- `foo` is the callee
- the direction means "main calls foo"

Reversing the arrow would mean "foo calls main", which is not the code behavior.


## Practical meaning

- `Symbol` = declaration / definition
- `CallSite` = invocation event
- `ResolvedCall` = invocation plus semantic argument resolution
- `CallGraph` = structural representation of caller/callee relationships
