use super::js_and_ts::utils::*;
use crate::server::models::{
    findings::{Severity, VulnerabilityType},
    results::ScanResult,
    symbols::{Symbol, SymbolKind},
};
use crate::Findings;
use oxc::ast_visit::Visit;
use oxc::span::GetSpan;
use oxc::{allocator::Allocator, parser::Parser, span::SourceType};
use oxc_ast::ast::{BindingPattern, CallExpression, Expression, NewExpression, VariableDeclarator};
use oxc_ast::ast::{TSAsExpression, TSType};

pub struct CodeVisitor<'a> {
    pub findings: Vec<Findings>,
    pub file_path: &'a str,
    pub source_text: &'a str,
    pub symbols: Vec<Symbol>,
    scope_stack: Vec<String>,
}

impl<'a> CodeVisitor<'a> {
    pub fn new(file_path: &'a str, source_text: &'a str) -> Self {
        Self {
            file_path,
            source_text,
            findings: vec![],
            symbols: vec![],
            scope_stack: vec![],
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

    fn span_to_line(&self, span_start: usize) -> usize {
        let safe = span_start.min(self.source_text.len());
        self.source_text[..safe].lines().count() + 1
    }

    // add to findings
    fn report(
        &mut self,
        snippet: &str,
        span_start: usize,
        vuln_type: VulnerabilityType,
        severity: Severity,
    ) {
        let safe = span_start.min(self.source_text.len());
        let line = self.source_text[..safe].lines().count() + 1;

        self.findings.push(Findings {
            vuln_type,
            line_no: line.to_string(),
            file_path: self.file_path.to_string(),
            snippet: snippet.to_string(),
            severity,
        });
    }

    pub fn list_possible_threats(self) -> Vec<Findings> {
        self.findings
    }

    pub fn into_scan_result(self) -> ScanResult {
        ScanResult {
            findings: self.findings,
            symbols: self.symbols,
        }
    }
}

// visitor implementation for AST traversal
impl<'a> Visit<'a> for CodeVisitor<'a> {
    // let var a=1;
    fn visit_variable_declarator(&mut self, node: &VariableDeclarator<'a>) {
        // Get variable name from AST first
        if let BindingPattern::BindingIdentifier(ident) = &node.id {
            self.symbols.push(Symbol {
                name: ident.name.to_string(),
                kind: SymbolKind::Variable,
                file: self.file_path.to_string(),
                line: self.span_to_line(node.span.start as usize),
                column: node.span.start as usize,
                scope: self.current_scope(),
            });

            // unwrap `satisfies` or `as` or `!` assertions before checking the shape
            let init = node.init.as_ref().map(unwrap_ts_expression);
            // check for Object Pattern like const { password }= config;
            if let Some(Expression::ObjectExpression(obj_lit)) = init {
                // iterate through properties of object
                for prop in &obj_lit.properties {
                    if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(prop) = prop {
                        if let oxc_ast::ast::PropertyKey::StaticIdentifier(ident) = &prop.key {
                            let key_name = ident.name.to_lowercase();
                            if is_secret_name(&key_name) {
                                // check if the value is a string literal or template literal without expressions
                                let value = &prop.value;
                                if let Some(value) = is_hardcoded_secret(value) {
                                    self.report(
                                        &value,
                                        prop.span().start as usize,
                                        VulnerabilityType::HardcodedSecret,
                                        Severity::Critical,
                                    );
                                }
                            }
                        }
                    }
                }
            } else {
                // then check for normal variable declaration like const password
                let var_name = ident.name.to_lowercase();

                // check if variable name contains keywords commonly associated with secrets
                if is_secret_name(&var_name) {
                    // determine what type of expression is associated, must be string literal or template literal without expressions
                    if let Some(init) = &node.init {
                        if let Some(value) = is_hardcoded_secret(init) {
                            self.report(
                                &value,
                                init.span().start as usize,
                                VulnerabilityType::HardcodedSecret,
                                Severity::Critical,
                            );
                        }
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
                let name = ident.name.as_str();
                self.report(
                    name,
                    node.span().start as usize,
                    VulnerabilityType::Eval,
                    Severity::High,
                );
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

        if let Expression::Identifier(ident) = callee {
            let name = ident.name.as_str();

            if is_dangerous_call(name) {
                self.report(
                    name,
                    node.span().start as usize,
                    VulnerabilityType::Eval,
                    Severity::High,
                );
            }

            // CommonJS imports via require()
            // e.g. module.exports = require('./lib/express');
            // var debug = require('debug');
            if name == "require" {
                if let Some(first_arg) = node.arguments.first() {
                    if let Some(expr) = first_arg.as_expression() {
                        if let Expression::StringLiteral(lit) = expr {
                            self.symbols.push(Symbol {
                                name: lit.value.to_string(),
                                kind: SymbolKind::Import,
                                file: self.file_path.to_string(),
                                line: self.span_to_line(node.span.start as usize),
                                column: node.span.start as usize,
                                scope: self.current_scope(),
                            });
                        }
                    }
                }
            }
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
                            let snippet = &self.source_text[start..end];
                            self.report(
                                snippet,
                                node.span().start as usize,
                                VulnerabilityType::SQLInjection,
                                Severity::Critical,
                            );
                        }
                    }
                    // flag if concatenated SQl with no params
                    Expression::BinaryExpression(_) => {
                        let has_params = node.arguments.len() > 1;
                        if !has_params {
                            let start = expr.span().start as usize;
                            let end = expr.span().end as usize;
                            let snippet = &self.source_text[start..end];
                            self.report(
                                snippet,
                                node.span().start as usize,
                                VulnerabilityType::SQLInjection,
                                Severity::Critical,
                            );
                        }
                    }

                    _ => {}
                }
            }
        }
        // walk into chldren and recurse
        oxc::ast_visit::walk::walk_call_expression(self, node);
    }

    // let a as int?
    fn visit_ts_as_expression(&mut self, node: &TSAsExpression<'a>) {
        if let TSType::TSAnyKeyword(_) = &node.type_annotation {
            self.report(
                "as any",
                node.span().start as usize,
                VulnerabilityType::UnsafeTypeAssertion,
                Severity::Low,
            );
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

            let kind = match scope.as_str() {
                "global" => SymbolKind::Function,
                _ => SymbolKind::Method,
            };

            self.symbols.push(Symbol {
                name: name.clone(),
                kind,
                file: self.file_path.to_string(),
                line: self.span_to_line(node.span.start as usize),
                column: node.span.start as usize,
                scope,
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
                        line: self.span_to_line(param.span.start as usize),
                        column: param.span.start as usize,
                        scope: self.current_scope(),
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

            self.symbols.push(Symbol {
                name: name.clone(),
                kind: SymbolKind::Class,
                file: self.file_path.to_string(),
                line: self.span_to_line(node.span.start as usize),
                column: node.span.start as usize,
                scope: self.current_scope(),
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
    } */
    fn visit_method_definition(&mut self, node: &oxc_ast::ast::MethodDefinition<'a>) {
        if let oxc_ast::ast::PropertyKey::StaticIdentifier(ident) = &node.key {
            let name = ident.name.to_string();

            self.symbols.push(Symbol {
                name: name.clone(),
                kind: SymbolKind::Method,
                file: self.file_path.to_string(),
                line: self.span_to_line(node.span.start as usize),
                column: node.span.start as usize,
                scope: self.current_scope(),
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
                        line: self.span_to_line(param.span.start as usize),
                        column: param.span.start as usize,
                        scope: self.current_scope(), // now inside method scope
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
            for specifier in specifiers {
                let name = match specifier {
                    oxc_ast::ast::ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        s.local.name.to_string()
                    }
                    oxc_ast::ast::ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        s.local.name.to_string()
                    }
                    oxc_ast::ast::ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        s.local.name.to_string()
                    }
                };

                self.symbols.push(Symbol {
                    name,
                    kind: SymbolKind::Import,
                    file: self.file_path.to_string(),
                    line: self.span_to_line(node.span.start as usize),
                    column: node.span.start as usize,
                    scope: "global".to_string(), // imports are always global
                });
            }
        }
        oxc::ast_visit::walk::walk_import_declaration(self, node);
    }
}

// convert code to AST using oxc parser
pub fn parse_to_ast<'a>(
    code: &'a str,
    allocator: &'a Allocator,
    file_path: &str,
) -> Result<oxc::ast::ast::Program<'a>, String> {
    let source_type = SourceType::from_path(file_path).unwrap_or_default();

    let ret = Parser::new(allocator, code, source_type).parse();

    if ret.errors.is_empty() {
        Ok(ret.program)
    } else {
        Err(ret
            .errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n"))
    }
}
