use crate::server::models::{
    calls::{CallSite, CallTable},
    resolution::{ResolutionTable, ResolvedArgument, ResolvedCall, ResolvedVariable},
    symbols::{Symbol, SymbolKind, SymbolTable},
};

pub struct Resolver;

impl Resolver {
    // for now only resolves calls
    // TODO add vars, imports etc
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

        ResolvedCall {
            call: call.clone(),
            arguments,
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

    // ── variables ─────────────────────────────────────────────────────────────

    // walk every variable and import in the SymbolTable independently of call sites.
    // this captures data flow that never appears as a function argument
    // intermediate assignments, imports, etc.
    fn resolve_variables(res_table: &mut ResolutionTable, symbol_table: &SymbolTable) {
        for (file, symbols) in &symbol_table.symbols {
            for symbol in symbols {
                match symbol.kind {
                    SymbolKind::Variable => {
                        let chain =
                            Self::resolve_chain(&symbol.name, &symbol.scope, file, symbol_table, 0);

                        if !chain.is_empty() {
                            res_table.variables.push(ResolvedVariable {
                                name: symbol.name.to_string(),
                                chain,
                            });
                        }
                    }
                    // TODO add imports
                    // Functions, parameters, etc are not data flow variables
                    _ => {}
                };
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

        let Some(s) = sym else { return vec![] };

        let mut chain = vec![s.clone()];

        match s.kind {
            // is Parameter, this is the origin, stop here
            SymbolKind::Parameter => {}

            // is Variable, chase what it was assigned from
            SymbolKind::Variable => {
                if let Some(ref rhs) = s.assigned_from {
                    let mut rest = Self::resolve_chain(rhs, scope, file, symbol_table, depth + 1);
                    chain.append(&mut rest);
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

    // Cross-file resolution via import symbols.
    // Requires parsers to store the resolved source path in assigned_from
    // Currently a stub (to hanlde path normalization)
    fn resolve_import(name: &str, file: &str, st: &SymbolTable) -> Option<Symbol> {
        let imports = st.symbols.get(file)?;

        let import_sym = imports
            .iter()
            .find(|s| s.kind == SymbolKind::Import && s.name == name)?;

        // assigned_from holds resolved source path e.g. "/project/src/utils.js"
        let source_file = import_sym.assigned_from.as_ref()?;

        st.symbols
            .get(source_file)?
            .iter()
            .find(|s| {
                s.name == name && matches!(s.kind, SymbolKind::Function | SymbolKind::Variable)
            })
            .cloned()
    }
}
