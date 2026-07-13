use crate::server::models::{
    calls::{CallSite, CallTable},
    resolution::{ResolutionTable, ResolvedArgument, ResolvedCall, ResolvedVariable},
    symbols::{AssignedFrom, Symbol, SymbolKind, SymbolTable},
};

pub struct Resolver;

impl Resolver {
    // resolve calls and variables
    pub fn resolve(symbol_table: &SymbolTable, call_table: &CallTable) -> ResolutionTable {
        let mut resolution_table = ResolutionTable::new();

        for calls in call_table.calls.values() {
            for call in calls {
                resolution_table
                    .calls
                    .push(Self::resolve_call(call, symbol_table));
            }
        }

        Self::resolve_variables(&mut resolution_table, symbol_table);

        resolution_table
    }

    fn resolve_call(call: &CallSite, symbol_table: &SymbolTable) -> ResolvedCall {
        // resolve any arguments in the call if any
        let arguments = call
            .arguments
            .iter()
            .map(|arg| Self::resolve_argument(arg, &call.caller, &call.file, symbol_table))
            .collect();

        // resolve where the callee is actually defined
        let resolved_callee = Self::resolve_callee(call, symbol_table);

        ResolvedCall {
            call: call.clone(),
            arguments,
            resolved_callee
        }
    }

    fn resolve_callee(call: &CallSite, st: &SymbolTable) -> Option<Symbol> {
        match &call.object {
            // method call: models.Model()
            // object = "models" (import alias), callee = "Model"
            Some(object) => {
                // get source files for this import alias
                let source_files = st.import_index.get(&call.file)?.get(object)?;

                // find the callee symbol in those source files
                source_files.iter().find_map(|source_file| {
                    st.fn_index
                        .get(source_file)?
                        .get(&call.callee)?
                        .first()
                        .cloned()
                })
            }

            // plain call: Model() — look locally first, then imports
            None => {
                // check local fn_index first
                let local = st
                    .fn_index
                    .get(&call.file)?
                    .get(&call.callee)?
                    .first()
                    .cloned();

                local.or_else(|| Self::resolve_import(&call.callee, &call.file, st))
            }
        }
    }

    fn resolve_argument(
        raw: &str,
        caller_scope: &str,
        file: &str,
        symbol_table: &SymbolTable,
    ) -> ResolvedArgument {
        // chase the full assignment chain from this arg back to its origin
        let chain = Self::resolve_chain(raw, caller_scope, file, symbol_table, 0);
        ResolvedArgument {
            raw: raw.to_string(),
            chain,
        }
    }

    // ── variables

    // walk every variable and import in the SymbolTable independently of call sites.
    // this captures data flow that never appears as a function argument
    // intermediate assignments, imports, etc.
    fn resolve_variables(res_table: &mut ResolutionTable, symbol_table: &SymbolTable) {
        for (file, symbols) in &symbol_table.symbols {
            for symbol in symbols {
                // Functions, parameters, etc are not data flow variables
                if symbol.kind == SymbolKind::Variable {
                    let chain =
                        Self::resolve_chain(&symbol.name, &symbol.scope, file, symbol_table, 0);

                    if !chain.is_empty() {
                        res_table.variables.push(ResolvedVariable {
                            name: symbol.name.to_string(),
                            chain,
                        });
                    }
                }
            }
        }
    }

    // walk assignment chains iteratively.
    //
    // given: X = 5, Y = X, foo(Y)
    // resolve_chain("Y") to [Symbol(Y), Symbol(X)]
    //
    // stops at Parameters (came from caller,  origin found),
    // or when assigned_from is None (literal or unresolvable).
    // depth guard prevents cycles.
    fn resolve_chain(
        name: &str,
        scope: &str,
        file: &str,
        symbol_table: &SymbolTable,
        depth: usize,
    ) -> Vec<Symbol> {
        if depth > 10 {
            return vec![];
        }

        // O(1) lookup, indexed hash map
        let key = format!("{}::{}", name, scope);
        let sym = symbol_table
            .index
            .get(file)
            .and_then(|idx| idx.get(&key))
            .and_then(|v| v.first())
            .cloned();

        dbg!(&sym);

        let Some(s) = sym else {
            // not found locally, check imports before giving up
            return Self::resolve_via_import(name, file, symbol_table, depth);
        };

        let mut chain = vec![s.clone()];

        match s.kind {
            // is Parameter, this is the origin, stop here
            SymbolKind::Parameter => {}

            // is Variable, chase what it was assigned from
            SymbolKind::Variable => {
                match s.assigned_from {
                    Some(AssignedFrom::Identifier(ref rhs)) => {
                        // chase: x = y,  follow y
                        let mut rest =
                            Self::resolve_chain(rhs, scope, file, symbol_table, depth + 1);
                        chain.append(&mut rest);
                    }
                    Some(AssignedFrom::Call { .. })
                    | Some(AssignedFrom::Member { .. })
                    | Some(AssignedFrom::Expression(_)) => {
                        // origin node — taint engine reads assigned_from directly,
                        // no further symbol to look up
                    }
                    Some(AssignedFrom::Literal(_)) | None => {
                        // safe / unresolvable, stop
                    }
                    Some(AssignedFrom::Import(_)) => {
                        // shouldn't happen on a Variable, but handle cleanly
                    }
                }
            }

            // ia Import, try cross-file resolution (Pending)
            SymbolKind::Import => {
                if let Some(sym) = Self::resolve_import(&s.name, file, symbol_table) {
                    chain.push(sym);
                }
            }

            // Functions, Methods, Classes etc are not a data-flow variable, stop
            _ => {}
        }

        chain
    }

    // called when a name isn't found in the local index.
    // checks if it resolves via an import before giving up.
    fn resolve_via_import(name: &str, file: &str, st: &SymbolTable, depth: usize) -> Vec<Symbol> {
        match Self::resolve_import(name, file, st) {
            Some(resolved) => Self::resolve_chain(
                &resolved.name,
                &resolved.scope,
                &resolved.file,
                st,
                depth + 1,
            ),
            None => vec![],
        }
    }

    // translate import name to a real Symbol in source file using import_index.
    // O(1) index lookup + O(candidates) verification against SymbolTable.
    // No path logic here, parsers stored stems, build_index matched them to real files.
    fn resolve_import(name: &str, file: &str, st: &SymbolTable) -> Option<Symbol> {
        let source_files = st.import_index.get(file)?.get(name)?;

        dbg!(name, file);
        // check each candidate — the one that actually declares the symbol wins
        source_files.iter().find_map(|source_file| {
            st.index
                .get(source_file)?
                .get(name)
                .and_then(|syms| {
                    syms.iter().find(|s| {
                        // TODO: add tiebreaker here
                        s.name == name
                            && matches!(
                                s.kind,
                                SymbolKind::Function | SymbolKind::Variable | SymbolKind::Method
                            )
                    })
                })
                .cloned()
        })
    }
}
