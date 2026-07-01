use super::js_and_ts::utils::*;
use crate::server::models::findings::{Severity, VulnerabilityType};
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
}

// visitor implementation for AST traversal
impl<'a> Visit<'a> for CodeVisitor<'a> {
    fn visit_variable_declarator(&mut self, node: &VariableDeclarator<'a>) {
        // Get variable name from AST first
        if let BindingPattern::BindingIdentifier(ident) = &node.id {
            // unwrap `satisfies` / `as` / `!` before checking the shape
            let init = node.init.as_ref().map(unwrap_ts_expression);
            // check for Object Pattern like const config = {password: "secret"}
            if let Some(Expression::ObjectExpression(obj_lit)) = init {
                // iterate through the objects
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
                                        Severity::Critical
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
                                Severity::Critical
                            );
                        }
                    }
                }
            }
        }
        // recurse into child
        oxc::ast_visit::walk::walk_variable_declarator(self, node);
    }

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

    // for fucntions
    fn visit_call_expression(&mut self, node: &CallExpression<'a>) {
        // for TS
        // unwrap (eval as any)(...) → eval(...) — do this FIRST, unconditionally
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
                    // flag if any part is dynamic OR if it's all static strings forming SQL
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

    fn visit_ts_as_expression(&mut self, node: &TSAsExpression<'a>) {
        if let TSType::TSAnyKeyword(_) = &node.type_annotation {
            self.report(
                "as any",
                node.span().start as usize,
                VulnerabilityType::UnsafeTypeAssertion,
                Severity::Low,
            );
        }
        // manual call to dleev deeper !
        // because we manully need o walk over transparent wrappers!
        // continue traversal into the inner expression
        oxc::ast_visit::walk::walk_ts_as_expression(self, node);
    }
}

impl CodeVisitor<'_> {
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
