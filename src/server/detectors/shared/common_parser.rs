use super::js_and_ts::utils::*;
use crate::server::models::{
    calls::CallSite,
    findings::{Severity, VulnerabilityType},
    results::ScanResult,
    symbols::{AssignedFrom, Symbol, SymbolKind},
};
use crate::Findings;
use oxc::ast_visit::Visit;
use oxc::span::{GetSpan, Span};
use oxc::{allocator::Allocator, parser::Parser, span::SourceType};
use oxc_ast::ast::{BindingPattern, CallExpression, Expression, NewExpression, VariableDeclarator};
use oxc_ast::ast::{TSAsExpression, TSType};

pub struct CodeVisitor<'a> {
    pub findings: Vec<Findings>,
    pub file_path: &'a str,
    pub source_text: &'a str,
    pub symbols: Vec<Symbol>,
    pub calls: Vec<CallSite>,
    scope_stack: Vec<String>,
    line_starts: Vec<usize>,
}

impl<'a> CodeVisitor<'a> {
    pub fn new(file_path: &'a str, source_text: &'a str) -> Self {
        // default start for all files
        let mut line_starts = vec![0];

        // loop through entire file bytes for start

        for (i, c) in source_text.char_indices() {
            if c == '\n' {
                line_starts.push(i + 1);
            }
        }

        Self {
            file_path,
            source_text,
            findings: vec![],
            symbols: vec![],
            scope_stack: vec![],
            calls: vec![],
            line_starts,
        }
    }

    // convert code to AST using oxc parser
    pub fn parse_to_ast(
        code: &'a str,
        allocator: &'a Allocator,
        file_path: &str,
    ) -> Result<oxc::ast::ast::Program<'a>, String> {
        let source_type = SourceType::from_path(file_path).unwrap_or_default();

        let ret = Parser::new(allocator, code, source_type).parse();

        if ret.errors.is_empty() {
            return Ok(ret.program);
        }
        // .js files can legally contain JSX (common in React projects)
        // if we see JSX errors, retry with JSX enabled before giving up
        let has_jsx_error = ret.errors.iter().any(|e| {
            let msg = e.to_string();
            msg.contains("JSX")
                || msg.contains("Unexpected JSX")
                || msg.contains("Unexpected token `<`")
        });

        if has_jsx_error {
            let jsx_source_type = source_type.with_jsx(true);
            let jsx_ret = Parser::new(allocator, code, jsx_source_type).parse();

            if jsx_ret.errors.is_empty() {
                return Ok(jsx_ret.program);
            }

            // JSX retry also failed — report the original errors, not the retry
            return Err(ret
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n"));
        }

        // second retry: TS syntax in a .js file
        let ts_source_type = source_type.with_typescript(true).with_jsx(true); // enable both since they often co-occur

        let ts_ret = Parser::new(allocator, code, ts_source_type).parse();
        if ts_ret.errors.is_empty() {
            return Ok(ts_ret.program);
        }

        // non-JSX parse error
        Err(ret
            .errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n"))
    }

    // only returns the stem, extension resolving is at 'Resolver'
    pub fn resolve_import_path(&self, import_path: &str) -> Option<String> {
        if import_path.starts_with('.') || import_path.starts_with('/') {
            let base_dir = std::path::Path::new(&self.file_path)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));

            // just normalize to absolute stem, no extension probing
            Some(
                base_dir
                    .join(import_path)
                    .to_string_lossy()
                    .replace("/./", "/")
                    .to_string(),
            )
        } else {
            Some(import_path.to_string()) // node_modules, leave as-is
        }
    }

    // get scope of element, i.e. wher they were declared
    fn current_scope(&self) -> String {
        if self.scope_stack.is_empty() {
            "global".to_string()
        } else {
            self.scope_stack.join("::")
        }
    }

    fn offset_to_line_col(&self, pos: usize) -> (usize, usize) {
        let idx = self.line_starts.partition_point(|&x| x <= pos) - 1;

        let line = idx + 1;
        let col = pos - self.line_starts[idx];

        (line, col)
    }

    // add to findings
    fn report(
        &mut self,
        snippet: &str,
        span: Span,
        vuln_type: VulnerabilityType,
        severity: Severity,
    ) {
        let (line, col) = self.offset_to_line_col(span.start as usize);

        self.findings.push(Findings {
            vuln_type,
            line_no: line.to_string(),
            col_no: col.to_string(),
            file_path: self.file_path.to_string(),
            snippet: snippet.to_string(),
            severity,
        });
    }

    pub fn into_scan_result(self) -> ScanResult {
        ScanResult {
            findings: self.findings,
            symbols: self.symbols,
            calls: self.calls,
        }
    }
}

// visitor implementation for AST traversal
impl<'a> Visit<'a> for CodeVisitor<'a> {
    fn visit_variable_declarator(&mut self, node: &VariableDeclarator<'a>) {
        // unwrap `satisfies` or `as` or `!` assertions before checking the shape
        let node_init = node.init.as_ref().map(unwrap_ts_expression);
        let (line, column) = self.offset_to_line_col(node.span.start as usize);

        let assigned_from = get_assigned_from(node_init, self.source_text);
        // check if the var declaration has a function call
        if let Some(Expression::CallExpression(call)) = node_init {
            if let Expression::Identifier(callee) = &call.callee {
                // imports
                if callee.name == "require" {
                    if let Some(arg) = call.arguments.first() {
                        if let Some(Expression::StringLiteral(lit)) = arg.as_expression() {
                            // shadow assigned_from here — require() is always an import
                            let assigned_from = self
                                .resolve_import_path(&lit.value)
                                .map(AssignedFrom::Import);
                            // CommonJS imports via require()
                            // e.g. module.exports = require('./lib/express');
                            // var debug = require('debug');
                            // const db = require("./db")
                            match &node.id {
                                // const db = require("./db");
                                BindingPattern::BindingIdentifier(ident) => {
                                    self.symbols.push(Symbol {
                                        name: ident.name.to_string(),
                                        kind: SymbolKind::Import,
                                        file: self.file_path.to_string(),
                                        line,
                                        column,
                                        scope: self.current_scope(),
                                        assigned_from,
                                    });
                                    return;
                                }
                                // const { buildQuery } = require("./utils");
                                BindingPattern::ObjectPattern(obj) => {
                                    // loop because 'name' is no provided directly
                                    for property in &obj.properties {
                                        let local_name = match &property.value {
                                            BindingPattern::BindingIdentifier(ident) => {
                                                ident.name.to_string()
                                            }
                                            _ => continue,
                                        };

                                        self.symbols.push(Symbol {
                                            name: local_name,
                                            kind: SymbolKind::Import,
                                            file: self.file_path.to_string(),
                                            line,
                                            column,
                                            scope: self.current_scope(),
                                            assigned_from: assigned_from.clone(),
                                        });
                                    }
                                    return;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // get variable name from AST if not a call expression
        let var_names = collect_binding_names(&node.id);

        for var in &var_names {
            self.symbols.push(Symbol {
                name: var.to_string(),
                kind: SymbolKind::Variable,
                file: self.file_path.to_string(),
                line,
                column,
                scope: self.current_scope(),
                assigned_from: assigned_from.clone(),
            });
        }

        // check object literals like:
        // const config = { password: "secret" };
        if let Some(Expression::ObjectExpression(obj_lit)) = node_init {
            // iterate through properties of object
            for prop in &obj_lit.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) = prop {
                    if let oxc_ast::ast::PropertyKey::StaticIdentifier(ident) = &prop.key {
                        let key_name = ident.name.to_lowercase();
                        if is_secret_name(&key_name) {
                            // check if the value is a string literal or template literal without expressions
                            let value = &prop.value;
                            if let Some(_value) = is_hardcoded_secret(value) {
                                // self.report(
                                //     &value,
                                //     prop.span(),
                                //     VulnerabilityType::HardcodedSecret,
                                //     Severity::Critical,
                                // );
                            }
                        }
                    }
                }
            }
        }

        for var in &var_names {
            let var_name = var.to_lowercase();
            // check if variable name contains keywords commonly associated with secrets
            if is_secret_name(&var_name) {
                // determine what type of expression is associated, must be string literal or template literal without expressions
                if let Some(init) = &node.init {
                    if let Some(_value) = is_hardcoded_secret(init) {
                        // self.report(
                        //     &value,
                        //     init.span(),
                        //     VulnerabilityType::HardcodedSecret,
                        //     Severity::Critical,
                        // );
                    }
                }
            }
        }

        // recurse into child, i.e deep traversal
        oxc::ast_visit::walk::walk_variable_declarator(self, node);
    }

    // e.g. new Function(...)
    fn visit_new_expression(&mut self, node: &NewExpression<'a>) {
        if let Expression::Identifier(ident) = &node.callee {
            if ident.name.as_str() == "Function" {
                let _name = ident.name.as_str();
                // self.report(name, node.span(), VulnerabilityType::Eval, Severity::High);
            }
        }
        // walk into children and recurse
        oxc::ast_visit::walk::walk_new_expression(self, node); // visits callee + all arguments
    }

    // for functions
    // eg: save(x)
    // db.query()
    // require()
    fn visit_call_expression(&mut self, node: &CallExpression<'a>) {
        // for TS
        // unwrap (eval as any)(...) to eval(...) do this FIRST, unconditionally
        let callee = unwrap_ts_expression(&node.callee);

        let arguments: Vec<String> = node
            .arguments
            .iter()
            .filter_map(|arg| arg.as_expression())
            .map(|expr| {
                let start = expr.span().start as usize;
                let end = expr.span().end as usize;
                self.source_text[start..end].to_string()
            })
            .collect();

        let (line, col) = self.offset_to_line_col(node.span().start as usize);

        match callee {
            /*
               save(y)
               call(a)
            */
            Expression::Identifier(ident) => {
                let name = ident.name.as_str();

                if is_dangerous_call(name) {
                    // self.report(name, node.span(), VulnerabilityType::Eval, Severity::High);
                }

                self.calls.push(CallSite {
                    callee: name.to_string(),
                    object: None,
                    arguments,
                    caller: self.current_scope(),
                    file: self.file_path.to_string(),
                    line,
                    column: col,
                });
            }

            // method call: db.query(x), fs.readFile(x)
            Expression::StaticMemberExpression(member) => {
                let callee_name = member.property.name.to_string();
                let object_name = match &member.object {
                    Expression::Identifier(id) => Some(id.name.to_string()),
                    _ => None,
                };

                self.calls.push(CallSite {
                    callee: callee_name,
                    object: object_name,
                    arguments,
                    caller: self.current_scope(),
                    file: self.file_path.to_string(),
                    line,
                    column: col,
                });
            }
            _ => {}
        }

        // sql injection check
        if let Some(first_arg) = node.arguments.first() {
            // allow queries with non empty params to not be flagged
            // db.query("SELECT * FROM users WHERE id = ?", [id]);

            if let Some(expr) = first_arg.as_expression() {
                match expr {
                    // template literal with expressions: `SELECT * FROM ${table}`
                    Expression::TemplateLiteral(_) => {
                        if contains_sql_keyword(expr) && contains_dynamic_value(expr) {
                            let start = expr.span().start as usize;
                            let end = expr.span().end as usize;
                            let _snippet = &self.source_text[start..end];
                            // self.report(
                            //     snippet,
                            //     node.span(),
                            //     VulnerabilityType::SQLInjection,
                            //     Severity::Critical,
                            // );
                        }
                    }
                    // flag if concatenated SQL with no params
                    Expression::BinaryExpression(_) => {
                        let has_params = node.arguments.len() > 1;
                        if !has_params {
                            let start = expr.span().start as usize;
                            let end = expr.span().end as usize;
                            let _snippet = &self.source_text[start..end];
                            // self.report(
                            //     snippet,
                            //     node.span(),
                            //     VulnerabilityType::SQLInjection,
                            //     Severity::Critical,
                            // );
                        }
                    }

                    _ => {}
                }
            }
        }
        // walk into chldren and recurse
        oxc::ast_visit::walk::walk_call_expression(self, node);
    }

    // let a as int
    fn visit_ts_as_expression(&mut self, node: &TSAsExpression<'a>) {
        if let TSType::TSAnyKeyword(_) = &node.type_annotation {
            // self.report(
            //     "as any",
            //     node.span(),
            //     VulnerabilityType::UnsafeTypeAssertion,
            //     Severity::Low,
            // );
        }
        // manual call to delve deeper !
        // because we manully need to walk over transparent wrappers!
        // continue traversal into the inner expression
        oxc::ast_visit::walk::walk_ts_as_expression(self, node);
    }

    // visit every function
    fn visit_function(
        &mut self,
        node: &oxc_ast::ast::Function<'a>,
        flags: oxc::syntax::scope::ScopeFlags,
    ) {
        if let Some(id) = &node.id {
            let name = id.name.to_string();
            let scope = self.current_scope();
            let (line, column) = self.offset_to_line_col(node.span.start as usize);

            let kind = match scope.as_str() {
                "global" => SymbolKind::Function,
                _ => SymbolKind::Method,
            };

            self.symbols.push(Symbol {
                name: name.clone(),
                kind,
                file: self.file_path.to_string(),
                line,
                column,
                scope,
                assigned_from: None,
            });

            // push scope before walking children
            self.scope_stack.push(name);

            // collect parameters
            for param in &node.params.items {
                if let BindingPattern::BindingIdentifier(ident) = &param.pattern {
                    self.symbols.push(Symbol {
                        name: ident.name.to_string(),
                        kind: SymbolKind::Parameter,
                        file: self.file_path.to_string(),
                        line,
                        column,
                        scope: self.current_scope(),
                        assigned_from: None,
                    });
                }
            }

            oxc::ast_visit::walk::walk_function(self, node, flags);
            self.scope_stack.pop(); // restore after
        } else {
            // anonymous function, still walk
            oxc::ast_visit::walk::walk_function(self, node, flags);
        }
    }

    // visit classes
    fn visit_class(&mut self, node: &oxc_ast::ast::Class<'a>) {
        if let Some(id) = &node.id {
            let name = id.name.to_string();
            let (line, column) = self.offset_to_line_col(node.span.start as usize);

            self.symbols.push(Symbol {
                name: name.clone(),
                kind: SymbolKind::Class,
                file: self.file_path.to_string(),
                line,
                column,
                scope: self.current_scope(),
                assigned_from: None,
            });

            self.scope_stack.push(name);
            oxc::ast_visit::walk::walk_class(self, node);
            self.scope_stack.pop();
        } else {
            oxc::ast_visit::walk::walk_class(self, node);
        }
    }

    // methods are class functions
    // e.g.
    /* class App{
        method(ab){}
        }
    */
    fn visit_method_definition(&mut self, node: &oxc_ast::ast::MethodDefinition<'a>) {
        if let oxc_ast::ast::PropertyKey::StaticIdentifier(ident) = &node.key {
            let name = ident.name.to_string();
            let (line, column) = self.offset_to_line_col(node.span.start as usize);

            self.symbols.push(Symbol {
                name: name.clone(),
                kind: SymbolKind::Method,
                file: self.file_path.to_string(),
                line,
                column,
                scope: self.current_scope(),
                assigned_from: None,
            });

            // push method name onto scope
            self.scope_stack.push(name);

            // collect parameters
            for param in &node.value.params.items {
                if let BindingPattern::BindingIdentifier(ident) = &param.pattern {
                    self.symbols.push(Symbol {
                        name: ident.name.to_string(),
                        kind: SymbolKind::Parameter,
                        file: self.file_path.to_string(),
                        line,
                        column,
                        scope: self.current_scope(), // now inside method scope
                        assigned_from: None,
                    });
                }
            }

            oxc::ast_visit::walk::walk_method_definition(self, node);
            self.scope_stack.pop();
        } else {
            oxc::ast_visit::walk::walk_method_definition(self, node);
        }
    }

    // e.g. import 'express' from express
    fn visit_import_declaration(&mut self, node: &oxc_ast::ast::ImportDeclaration<'a>) {
        if let Some(specifiers) = &node.specifiers {
            let import_source = node.source.value.as_str();
            let resolved_path = self.resolve_import_path(import_source);
            let (line, column) = self.offset_to_line_col(node.span.start as usize);

            for specifier in specifiers {
                let name = match specifier {
                    // handles import { query } from "./db"; (or) import { query as runQuery } from "./db";
                    oxc_ast::ast::ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        s.local.name.to_string()
                    }
                    // handles import express from "express";
                    oxc_ast::ast::ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        s.local.name.to_string()
                    }
                    // handles import * as fs from "fs";
                    oxc_ast::ast::ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        s.local.name.to_string()
                    }
                };

                self.symbols.push(Symbol {
                    name,
                    kind: SymbolKind::Import,
                    file: self.file_path.to_string(),
                    line,
                    column,
                    scope: "global".to_string(), // imports are always global
                    assigned_from: resolved_path.clone().map(AssignedFrom::Import),
                });
            }
        }
        oxc::ast_visit::walk::walk_import_declaration(self, node);
    }
}

// function to collect vars of differnt types
fn collect_binding_names<'a>(pattern: &BindingPattern<'a>) -> Vec<String> {
    match pattern {
        // const password = "secret!";
        BindingPattern::BindingIdentifier(ident) => {
            vec![ident.name.to_string()]
        }

        // const { key,secret } = object;
        BindingPattern::ObjectPattern(obj) => {
            let mut names = Vec::new();

            for property in &obj.properties {
                let name = match &property.value {
                    BindingPattern::BindingIdentifier(ident) => Some(ident.name.to_string()),

                    _ => None,
                };

                if let Some(name) = name {
                    names.push(name);
                }
            }

            names
        }

        // const [a,b] = array;
        BindingPattern::ArrayPattern(arr) => {
            let mut names = Vec::new();

            for element in &arr.elements {
                if let Some(BindingPattern::BindingIdentifier(ident)) = element {
                    names.push(ident.name.to_string());
                }
            }

            names
        }

        _ => {
            vec![]
        }
    }
}

fn get_assigned_from<'a>(
    node_init: Option<&Expression<'a>>,
    source_text: &str,
) -> Option<AssignedFrom> {
    node_init.map(|expr| match expr {
        // const x = y;
        // tracks identifier so resolver can chase the chain: x to y to ...
        Expression::Identifier(id) => AssignedFrom::Identifier(id.name.to_string()),

        // const x = "hello";
        // const x = 42;
        // literal origin — chain stops here, nothing to resolve further
        Expression::StringLiteral(lit) => AssignedFrom::Literal(lit.value.to_string()),
        Expression::NumericLiteral(num) => AssignedFrom::Literal(num.value.to_string()),

        // const id = req.body.id;
        // const db = config.database;
        // split into object + property so taint engine can check
        // if the object (e.g. "req.body") is a known taint source
        Expression::StaticMemberExpression(member) => {
            let property = member.property.name.to_string();
            // use span to capture the full object text, e.g. "req.body" not just "req"
            let object = {
                let start = member.object.span().start as usize;
                let end = member.object.span().end as usize;
                source_text[start..end].to_string()
            };
            AssignedFrom::Member { object, property }
        }

        // const result = buildQuery("users", id);
        // const conn = db.connect();
        // records callee + raw argument text so resolver can:
        //   1. look up where callee is defined (cross-file via import_index)
        //   2. check if any argument is tainted
        Expression::CallExpression(call) => {
            let callee = match unwrap_ts_expression(&call.callee) {
                // plain call: foo(...)
                Expression::Identifier(id) => id.name.to_string(),

                // method call: db.query(...) to "db.query"
                // object captured via span to handle chained members e.g. "req.db"
                Expression::StaticMemberExpression(m) => {
                    format!(
                        "{}.{}",
                        {
                            let s = m.object.span().start as usize;
                            let e = m.object.span().end as usize;
                            &source_text[s..e]
                        },
                        m.property.name
                    )
                }

                // fallback: computed or wrapped callee — just grab the raw text
                other => {
                    let s = other.span().start as usize;
                    let e = other.span().end as usize;
                    source_text[s..e].to_string()
                }
            };

            // capture each argument as raw source text so the taint engine
            // can later resolve them individually (e.g. is `id` tainted?)
            let arguments: Vec<String> = call
                .arguments
                .iter()
                .filter_map(|a| a.as_expression())
                .map(|e| source_text[e.span().start as usize..e.span().end as usize].to_string())
                .collect();

            AssignedFrom::Call { callee, arguments }
        }

        // const x = a + b;
        // const y = arr[i];
        // const z = condition ? a : b;
        // doesn't fit a specific category — store raw text for the taint
        // engine to inspect directly, chain resolution stops here
        other => {
            let s = other.span().start as usize;
            let e = other.span().end as usize;
            AssignedFrom::Expression(source_text[s..e].to_string())
        }
    })
}
