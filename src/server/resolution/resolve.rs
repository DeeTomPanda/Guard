use crate::server::models::{
    calls::{CallSite, CallTable},
    resolution::{ResolutionTable, ResolvedArgument, ResolvedCall},
    symbols::{Symbol, SymbolKind, SymbolTable},
};

pub struct Resolver;

impl Resolver {
    pub fn resolve(symbol_table: &SymbolTable, call_table: &CallTable) -> ResolutionTable {
        let mut resolution = ResolutionTable::new();

        for calls in call_table.calls.values() {
            for call in calls {
                let resolved = Self::resolve_call(call, symbol_table);
                resolution.calls.push(resolved);
            }
        }

        resolution
    }

    fn resolve_call(call: &CallSite, symbol_table: &SymbolTable) -> ResolvedCall {
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
        // O(1) lookup
        let key = format!("{}::{}", raw, caller_scope);
        let symbol = symbol_table
            .index
            .get(file)
            .and_then(|file_index| file_index.get(&key))
            .and_then(|symbols| symbols.first()) // take first, O(1)
            .cloned();

        // if found, try to resolve what it was assigned from
        let assigned_from = symbol
            .as_ref()
            .and_then(|s| Self::resolve_assignment(s, file, symbol_table));

        ResolvedArgument {
            raw: raw.to_string(),
            symbol,
            assigned_from,
        }
    }

    fn resolve_assignment(
        symbol: &Symbol,
        file: &str,
        symbol_table: &SymbolTable,
    ) -> Option<String> {
        match symbol.kind {
            // parameter — came from caller
            SymbolKind::Parameter => Some(format!("parameter::{}", symbol.name)),
            // variable — return what it was assigned from
            SymbolKind::Variable => {
                symbol.assigned_from.clone() // ← just return it directly
            }
            // everything else — not resolvable
            _ => None,
        }
    }
}
