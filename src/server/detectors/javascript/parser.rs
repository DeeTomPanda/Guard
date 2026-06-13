use super::utils::*;
use crate::server::model::{Severity, VulnerabilityType};
use crate::Findings;
use oxc::ast_visit::Visit;
use oxc::span::GetSpan;
use oxc::{allocator::Allocator, parser::Parser, span::SourceType};
use oxc_ast::ast::{BindingPattern, CallExpression, Expression, NewExpression, VariableDeclarator};

pub struct CodeVisitor<'a> {
    pub findings: Vec<Findings>,
    pub file_path: &'a str,
    pub source_text: &'a str,
}

impl<'a> CodeVisitor<'a> {
    pub fn initialize() -> Self {
        CodeVisitor {
            findings: Vec::new(),
            file_path: "",
            source_text: "",
        }
    }
}

// visitor implementation for AST traversal
impl<'a> Visit<'a> for CodeVisitor<'a> {
    fn visit_variable_declarator(&mut self, node: &VariableDeclarator<'a>) {
        // Get variable name from AST first
        if let BindingPattern::BindingIdentifier(ident) = &node.id {
            // check for Object Pattern like const config = {password: "secret"}
            if let Some(Expression::ObjectExpression(obj_lit)) = &node.init {
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
                if !is_secret_name(&var_name) {
                    return;
                }

                // determine what type of expression is associated, must be string literal or template literal without expressions
                if let Some(init) = &node.init {
                    if let Some(value) = is_hardcoded_secret(init) {
                        self.report(
                            &value,
                            init.span().start as usize,
                            VulnerabilityType::HardcodedSecret,
                        );
                    }
                }
            }
        }
    }

    fn visit_new_expression(&mut self, node: &NewExpression<'a>) {
        if let Expression::Identifier(ident) = &node.callee {
            if ident.name.as_str() == "Function" {
                let name = ident.name.as_str();
                self.report(name, node.span().start as usize, VulnerabilityType::Eval);
            }
        }
    }

    // for fucntions
    fn visit_call_expression(&mut self, node: &CallExpression<'a>) {
        if let Expression::Identifier(ident) = &node.callee {
            let name = ident.name.as_str();

            // check if calling function match different names
            if is_dangerous_call(name) {
                self.report(&name, node.span().start as usize, VulnerabilityType::Eval);
            }
        }

        // sql injection check
        if let Some(first_arg) = node.arguments.first() {
            // allow queries with non empty params to not be flagged
            // db.query("SELECT * FROM users WHERE id = ?", [id]);

            if let Some(expr) = first_arg.as_expression() {
                match expr {
                    // template literal with expressions: `SELECT * FROM ${table}`
                    Expression::StringLiteral(s) => {
                        // let has_params = node.arguments.len() > 1;
                        // // flag only
                        // // db.query("SELECT * FROM users WHERE id = 1")
                        // // not db.query("SELECT * FROM users WHERE id = $1",[id])
                        // // or db.query("SELECT * FROM users WHERE id = ?",[id])
                        // if contains_sql_keyword(expr) && !has_params {
                        //     self.report(
                        //         s.value.as_str(),
                        //         node.span().start as usize,
                        //         VulnerabilityType::SQLInjection,
                        //     );
                        // }
                    }
                    Expression::TemplateLiteral(_) => {
                        if contains_sql_keyword(expr) && contains_dynamic_value(expr) {
                            let start = expr.span().start as usize;
                            let end = expr.span().end as usize;
                            let snippet = &self.source_text[start..end];
                            self.report(
                                snippet,
                                node.span().start as usize,
                                VulnerabilityType::SQLInjection,
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
                            );
                        }
                    }

                    _ => {}
                }
            }
        }
    }
}

impl<'a> CodeVisitor<'a> {
    pub fn new(file_path: &'a str, source_text: &'a str) -> Self {
        Self {
            findings: Vec::new(),
            file_path,
            source_text,
        }
    }

    // add to findings
    fn report(&mut self, snippet: &str, span_start: usize, vuln_type: VulnerabilityType) {
        let safe = span_start.min(self.source_text.len());
        let line = self.source_text[..safe].lines().count() + 1;

        self.findings.push(Findings {
            vuln_type,
            line_no: line.to_string(),
            file_path: self.file_path.to_string(),
            snippet: snippet.to_string(),
            severity: Severity::High,
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
