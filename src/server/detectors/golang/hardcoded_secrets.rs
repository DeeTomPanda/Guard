use crate::server::models::findings::{Severity, VulnerabilityType};
use tree_sitter::Node;
use super::{go_scanner::GolangTreeSitter, utils::match_pattern};

const QUERY_SECRET_VAR: &str = r#"
(var_declaration
  (var_spec
    name: (identifier) @varname
    value: (expression_list (_) @value))
  (#match? @varname "(?i)(password|secret|api_key|token|private_key|passwd|pwd|auth)")) @snippet
"#;

const QUERY_SECRET_CONST: &str = r#"
(const_declaration
  (const_spec
    name: (identifier) @varname
    value: (expression_list (_) @value))
  (#match? @varname "(?i)(password|secret|api_key|token|private_key|passwd|pwd|auth)")) @snippet
"#;

const QUERY_SECRET_STRUCT: &str = r#"
(keyed_element
  (literal_element (identifier) @key)
  (literal_element (interpreted_string_literal) @value)
  (#match? @key "(?i)(password|secret|token|api_key)")) @snippet
"#;

impl GolangTreeSitter<'_> {
    pub(super)fn check_secrets(&mut self, root: Node, src: &[u8]) {
        for query_src in [QUERY_SECRET_VAR, QUERY_SECRET_CONST, QUERY_SECRET_STRUCT] {
            for m in match_pattern(query_src, root, src) {
                if let Some((_, snippet, line, _)) = m.iter().find(|(n, ..)| n == "snippet") {
                    self.report(
                        snippet,
                        &line.to_string(),
                        VulnerabilityType::HardcodedSecret,
                        Severity::Critical,
                    );
                }
            }
        }
    }
}
