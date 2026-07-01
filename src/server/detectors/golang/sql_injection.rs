use super::{go_scanner::GolangTreeSitter, utils::match_pattern};
use crate::server::models::findings::{Severity, VulnerabilityType};
use tree_sitter::Node;

const QUERY_SQL_SPRINTF: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @receiver
    field: (field_identifier) @method)
  arguments: (argument_list
    .
    (call_expression
      function: (selector_expression
        operand: (identifier) @pkg
        field: (field_identifier) @fmt_method)
      arguments: (argument_list
        (interpreted_string_literal) @query
        (_)*)) @sprintf_call
    (_)*)
  (#match? @method "^(Query|QueryRow|Exec)$")
  (#eq? @pkg "fmt")
  (#eq? @fmt_method "Sprintf")) @snippet
"#;

const QUERY_SQL_SPRINTF_CONTEXT: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @receiver
    field: (field_identifier) @method)
  arguments: (argument_list
    .
    (_)
    .
    (call_expression
      function: (selector_expression
        operand: (identifier) @pkg
        field: (field_identifier) @fmt_method)
      arguments: (argument_list
        (interpreted_string_literal) @query
        (_)*)) @sprintf_call
    (_)*)
  (#match? @method "^(QueryContext|QueryRowContext|ExecContext)$")
  (#eq? @pkg "fmt")
  (#eq? @fmt_method "Sprintf")) @snippet
"#;

const QUERY_SQL_DB: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @receiver
    field: (field_identifier) @method)
  arguments: (argument_list
    .
    [
      (identifier)
      (binary_expression)
      (call_expression)
      (selector_expression)
    ] @query_arg
    (_)*)
  (#match? @method "^(Query|QueryRow|Exec)$")) @snippet
"#;

const QUERY_SQL_DB_CONTEXT: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @receiver
    field: (field_identifier) @method)
  arguments: (argument_list
    .
    (_)
    .
    [
      (identifier)
      (binary_expression)
      (call_expression)
      (selector_expression)
    ] @query_arg
    (_)*)
  (#match? @method "^(QueryContext|QueryRowContext|ExecContext)$")) @snippet
"#;

const QUERY_GORM_CONCAT: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @receiver
    field: (field_identifier) @method)
  arguments: (argument_list
    (_)*
    (binary_expression) @expr
    (_)* )
  (#match? @method "^(Where|Not|Or|Having|Joins|Raw|Exec)$")) @snippet
"#;

const QUERY_GORM_SPRINTF: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @receiver
    field: (field_identifier) @method)
  arguments: (argument_list
    (_)*
    (call_expression
      function: (selector_expression
        operand: (identifier) @pkg
        field: (field_identifier) @inner)) @sprintf_call
    (_)*)
  (#match? @method "^(Where|Not|Or|Having|Joins|Raw|Exec)$")
  (#eq? @pkg "fmt")
  (#eq? @inner "Sprintf")) @snippet
"#;

const QUERY_GORM_RAW_VAR: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @receiver
    field: (field_identifier) @method)
  arguments: (argument_list
    .
    (identifier) @arg
    (_)*)
  (#match? @method "^(Raw|Exec)$")) @snippet
"#;

impl GolangTreeSitter<'_> {
    pub (super) fn check_sql_sprintf(&mut self, root: Node, src: &[u8]) {
        for m in match_pattern(QUERY_SQL_SPRINTF, root, src) {
            let query = m
                .iter()
                .find(|(n, ..)| n == "query")
                .map(|(_, text, _, _)| text);

            let snippet = m
                .iter()
                .find(|(n, ..)| n == "snippet")
                .map(|(_, text, line, col)| (text, line, col));

            if let (Some(q), Some((snippet, line, col))) = (query, snippet) {
                let q = q.to_uppercase();

                if q.contains("SELECT")
                    || q.contains("INSERT")
                    || q.contains("UPDATE")
                    || q.contains("DELETE")
                {
                    self.report(
                        snippet,
                        &(line.to_string()),
                        VulnerabilityType::SQLInjection,
                        Severity::Critical,
                    );
                }
            }
        }

         for m in match_pattern(QUERY_SQL_SPRINTF_CONTEXT, root, src) {
            let query = m
                .iter()
                .find(|(n, ..)| n == "query")
                .map(|(_, text, _, _)| text);

            let snippet = m
                .iter()
                .find(|(n, ..)| n == "snippet")
                .map(|(_, text, line, col)| (text, line, col));

            if let (Some(q), Some((snippet, line, col))) = (query, snippet) {
                let q = q.to_uppercase();

                if q.contains("SELECT")
                    || q.contains("INSERT")
                    || q.contains("UPDATE")
                    || q.contains("DELETE")
                {
                    self.report(
                        snippet,
                        &(line.to_string()),
                        VulnerabilityType::SQLInjection,
                        Severity::Critical,
                    );
                }
            }
        }
    }

    pub(super)fn check_sql_db(&mut self, root: Node, src: &[u8]) {
        for m in match_pattern(QUERY_SQL_DB, root, src) {
            let method = m
                .iter()
                .find(|(n, ..)| n == "method")
                .map(|(_, text, _, _)| text);

            let snippet = m
                .iter()
                .find(|(n, ..)| n == "snippet")
                .map(|(_, text, line, col)| (text, line, col));

            if let (Some(method), Some((snippet, line, col))) = (method, snippet) {
                self.report(
                    snippet,
                    &(line.to_string()),
                    VulnerabilityType::SQLInjection,
                    Severity::Critical,
                );
            }
        }

        for m in match_pattern(QUERY_SQL_DB_CONTEXT, root, src) {
            let method = m
                .iter()
                .find(|(n, ..)| n == "method")
                .map(|(_, text, _, _)| text);

            let snippet = m
                .iter()
                .find(|(n, ..)| n == "snippet")
                .map(|(_, text, line, col)| (text, line, col));

            if let (Some(method), Some((snippet, line, col))) = (method, snippet) {
                self.report(
                    snippet,
                    &(line.to_string()),
                    VulnerabilityType::SQLInjection,
                    Severity::Critical,
                );
            }
        }
    }

    // ── GORM ───

    pub(super)fn check_gorm(&mut self, root: Node, src: &[u8]) {
        // string concat: db.Where("id = " + val)
        for m in match_pattern(QUERY_GORM_CONCAT, root, src) {
            if let Some((_, snippet, line, _)) = m.iter().find(|(n, ..)| n == "snippet") {
                self.report(
                    snippet,
                    &(line.to_string()),
                    VulnerabilityType::SQLInjection,
                    Severity::Critical,
                );
            }
        }

        // Sprintf inside Where: db.Where(fmt.Sprintf(...))
        for m in match_pattern(QUERY_GORM_SPRINTF, root, src) {
            if let Some((_, snippet, line, _)) = m.iter().find(|(n, ..)| n == "snippet") {
                self.report(
                    snippet,
                    &(line.to_string()),
                    VulnerabilityType::SQLInjection,
                    Severity::Critical,
                );
            }
        }

        // raw variable: db.Raw(query)
        for m in match_pattern(QUERY_GORM_RAW_VAR, root, src) {
            if let Some((_, snippet, line, _)) = m.iter().find(|(n, ..)| n == "snippet") {
                self.report(
                    snippet,
                    &(line.to_string()),
                    VulnerabilityType::SQLInjection,
                    Severity::Critical,
                );
            }
        }
    }
}
