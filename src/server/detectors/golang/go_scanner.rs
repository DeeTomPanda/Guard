use crate::server::models::findings::{Severity, VulnerabilityType};
use crate::server::{
    detectors::Scanner,
    models::{
        calls::CallSite,
        findings::Findings,
        results::ScanResult,
        symbols::{Symbol, SymbolKind},
    },
};

pub struct GolangScanner;

pub(super) struct GolangTreeSitter<'a> {
    findings: Vec<Findings>,
    symbols: Vec<Symbol>,
    file_path: &'a str,
    scope_stack: Vec<String>,
    calls: Vec<CallSite>,
}

impl Scanner for GolangScanner {
    fn scan(&self, code: &str, file_path: &str) -> ScanResult {
        let mut tree_sitter = GolangTreeSitter::new(file_path);
        tree_sitter.analyze(code);
        tree_sitter.into_result()
    }
}

impl<'a> GolangTreeSitter<'a> {
    pub fn new(file_path: &'a str) -> Self {
        Self {
            findings: Vec::new(),
            file_path,
            symbols: Vec::new(),
            scope_stack: Vec::new(),
            calls: Vec::new(),
        }
    }

    fn current_scope(&self) -> String {
        if self.scope_stack.is_empty() {
            "global".to_string()
        } else {
            self.scope_stack.join("::")
        }
    }

    fn extract_symbols(&mut self, root: tree_sitter::Node, code_bytes: &[u8]) {
        self.walk_node(root, code_bytes);
    }

    fn walk_node(&mut self, node: tree_sitter::Node, code_bytes: &[u8]) {
        match node.kind() {
            // standalone function
            "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(code_bytes).unwrap_or("").to_string();
                    let line = name_node.start_position().row + 1;

                    self.symbols.push(Symbol {
                        name: name.clone(),
                        kind: SymbolKind::Function,
                        file: self.file_path.to_string(),
                        line,
                        column: name_node.start_position().column,
                        scope: self.current_scope(),
                    });

                    self.scope_stack.push(name);
                    // extract parameters
                    if let Some(params) = node.child_by_field_name("parameters") {
                        self.extract_go_params(params, code_bytes);
                    }

                    self.walk_children(node, code_bytes);
                    self.scope_stack.pop();
                }
            }

            // method on a type
            "method_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(code_bytes).unwrap_or("").to_string();
                    let line = name_node.start_position().row + 1;

                    // get receiver type for scope
                    let receiver_type = node
                        .child_by_field_name("receiver")
                        .and_then(|r| {
                            // bind to variable so cursor lifetime is valid
                            let mut cursor = r.walk();
                            let param = r
                                .children(&mut cursor)
                                .find(|c| c.kind() == "parameter_declaration");

                            param
                                .and_then(|p| p.child_by_field_name("type"))
                                .and_then(|t| {
                                    if t.kind() == "pointer_type" {
                                        t.child(1)
                                            .and_then(|inner| inner.utf8_text(code_bytes).ok())
                                    } else {
                                        t.utf8_text(code_bytes).ok()
                                    }
                                })
                                .map(|s| s.trim_start_matches('*').to_string())
                        })
                        .unwrap_or("unknown".to_string());

                    self.symbols.push(Symbol {
                        name: name.clone(),
                        kind: SymbolKind::Method,
                        file: self.file_path.to_string(),
                        line,
                        column: name_node.start_position().column,
                        scope: receiver_type.clone(),
                    });

                    self.scope_stack.push(receiver_type);
                    self.scope_stack.push(name);

                    // extract parameters
                    if let Some(params) = node.child_by_field_name("parameters") {
                        self.extract_go_params(params, code_bytes);
                    }

                    self.walk_children(node, code_bytes);
                    self.scope_stack.pop();
                    self.scope_stack.pop();
                }
            }

            // short variable declaration: x := something
            "short_var_declaration" => {
                if let Some(left) = node.child_by_field_name("left") {
                    let mut cursor = left.walk();
                    for child in left.children(&mut cursor) {
                        if child.kind() == "identifier" {
                            let name = child.utf8_text(code_bytes).unwrap_or("").to_string();
                            self.symbols.push(Symbol {
                                name,
                                kind: SymbolKind::Variable,
                                file: self.file_path.to_string(),
                                line: child.start_position().row + 1,
                                column: child.start_position().column,
                                scope: self.current_scope(),
                            });
                        }
                    }
                }
                self.walk_children(node, code_bytes);
            }

            // var declaration: var x int = something
            "var_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "var_spec" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let name = name_node.utf8_text(code_bytes).unwrap_or("").to_string();
                            self.symbols.push(Symbol {
                                name,
                                kind: SymbolKind::Variable,
                                file: self.file_path.to_string(),
                                line: name_node.start_position().row + 1,
                                column: name_node.start_position().column,
                                scope: self.current_scope(),
                            });
                        }
                    }
                }
                self.walk_children(node, code_bytes);
            }

            "import_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    match child.kind() {
                        // single import
                        // import import_1
                        "import_spec" => {
                            self.collect_import_spec(child, code_bytes);
                        }
                        // grouped imports
                        /*
                        import(
                            import_1
                            import_2
                        ) */
                        "import_spec_list" => {
                            let mut list_cursor = child.walk();
                            for spec in child.children(&mut list_cursor) {
                                if spec.kind() == "import_spec" {
                                    self.collect_import_spec(spec, code_bytes);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // struct types
            "type_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "type_spec" {
                        let has_struct = child
                            .child_by_field_name("type")
                            .map(|t| t.kind() == "struct_type")
                            .unwrap_or(false);

                        if has_struct {
                            if let Some(name_node) = child.child_by_field_name("name") {
                                let name =
                                    name_node.utf8_text(code_bytes).unwrap_or("").to_string();
                                self.symbols.push(Symbol {
                                    name,
                                    kind: SymbolKind::Struct,
                                    file: self.file_path.to_string(),
                                    line: name_node.start_position().row + 1,
                                    column: name_node.start_position().column,
                                    scope: "global".to_string(),
                                });
                            }
                        }
                    }
                }
            }

            "call_expression" => {
                let function_node = node.child_by_field_name("function");
                let args_node = node.child_by_field_name("arguments");

                // extract arguments
                let arguments: Vec<String> = args_node
                    .map(|args| {
                        let mut cursor = args.walk();
                        args.children(&mut cursor)
                        // strip away ',' and parantheses!
                            .filter(|c| c.kind() != "," && c.kind() != "(" && c.kind() != ")")
                            .map(|c| c.utf8_text(code_bytes).unwrap_or("").to_string())
                            .collect()
                    })
                    .unwrap_or_default();

                if let Some(func) = function_node {
                    match func.kind() {
                        // plain call: save(x)
                        "identifier" => {
                            let callee = func.utf8_text(code_bytes).unwrap_or("").to_string();
                            self.calls.push(CallSite {
                                callee,
                                object: None,
                                arguments,
                                caller: self.current_scope(),
                                file: self.file_path.to_string(),
                                line: func.start_position().row + 1,
                                column: func.start_position().column,
                            });
                        }

                        // method call: db.Query(x)
                        "selector_expression" => {
                            let callee = func
                                .child_by_field_name("field")
                                .and_then(|f| f.utf8_text(code_bytes).ok())
                                .unwrap_or("")
                                .to_string();

                            let object = func.child_by_field_name("operand").map(|o| {
                                // if operand is itself a selector (r.db), take the field
                                // if operand is plain identifier (db), take it directly
                                if o.kind() == "selector_expression" {
                                    o.child_by_field_name("field")
                                        .and_then(|f| f.utf8_text(code_bytes).ok())
                                        .unwrap_or("")
                                        .to_string()
                                } else {
                                    o.utf8_text(code_bytes).unwrap_or("").to_string()
                                }
                            });

                            self.calls.push(CallSite {
                                callee,
                                object,
                                arguments,
                                caller: self.current_scope(),
                                file: self.file_path.to_string(),
                                line: func.start_position().row + 1,
                                column: func.start_position().column,
                            });
                        }

                        _ => {}
                    }
                }
            }

            // everything else — just walk children
            _ => {
                self.walk_children(node, code_bytes);
            }
        }
    }

    fn walk_children(&mut self, node: tree_sitter::Node, code_bytes: &[u8]) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_node(child, code_bytes);
        }
    }

    fn extract_go_params(&mut self, params_node: tree_sitter::Node, code_bytes: &[u8]) {
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "parameter_declaration" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = name_node.utf8_text(code_bytes).unwrap_or("").to_string();
                    self.symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Parameter,
                        file: self.file_path.to_string(),
                        line: name_node.start_position().row + 1,
                        column: name_node.start_position().column,
                        scope: self.current_scope(),
                    });
                }
            }
        }
    }

    fn collect_import_spec(&mut self, node: tree_sitter::Node, code: &[u8]) {
        if let Some(path_node) = node.child_by_field_name("path") {
            let raw = path_node.utf8_text(code).unwrap_or("\"\"");
            let name = raw.trim_matches('"').to_string();
            self.symbols.push(Symbol {
                name,
                kind: SymbolKind::Import,
                file: self.file_path.to_string(),
                line: path_node.start_position().row + 1,
                column: path_node.start_position().column,
                scope: "global".to_string(),
            });
        }
    }

    fn analyze(&mut self, code: &str) {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_go::LANGUAGE;
        if let Err(err) = parser.set_language(&language.into()) {
            eprintln!(
                "go parser could not be initialized err: {} \nCheck that tree-sitter and tree-sitter-go versions match.",
                 err
            );
            return;
        }

        let tree = match parser.parse(code, None) {
            Some(tree) => tree,
            None => {
                eprintln!("go parser failed to analyze");
                return;
            }
        };
        let root = tree.root_node();
        let code_bytes = code.as_bytes();
        self.extract_symbols(root, code_bytes);
        // check for hardcoded secrets
        self.check_secrets(root, code_bytes);
        // check for SQL injection vulnerabilities
        self.check_sql_sprintf(root, code_bytes);
        self.check_sql_db(root, code_bytes);
        self.check_gorm(root, code_bytes);
        // check for command injection vulnerabilities
        self.check_exec(root, code_bytes);
        self.check_syscall(root, code_bytes);
        // check for unsafe file operations
        self.check_file_ops(root, code_bytes);
    }

    pub(super) fn report(
        &mut self,
        snippet: &str,
        node: tree_sitter::Node,
        vuln_type: VulnerabilityType,
        severity: Severity,
    ) {
        let line = (node.start_position().row + 1).to_string();
        let col = node.start_position().column.to_string();

        // avoid duplicate findings for the same vuln type, line,column and snippet
        let exists = self.findings.iter().any(|f| {
            f.vuln_type == vuln_type && f.line_no == line && f.col_no == col && f.snippet == snippet
        });

        if exists {
            return;
        }

        self.findings.push(Findings {
            vuln_type,
            line_no: line.to_string(),
            col_no: col.to_string(),
            file_path: self.file_path.to_string(),
            snippet: snippet.to_string(),
            severity,
        });
    }

    pub fn into_result(self) -> ScanResult {
        ScanResult {
            findings: self.findings,
            symbols: self.symbols,
            calls: self.calls,
        }
    }

    pub fn list_possible_threats(self) -> Vec<Findings> {
        self.findings
    }
}
