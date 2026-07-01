use super::{go_scanner::GolangTreeSitter, utils::match_pattern};
use crate::server::models::findings::{Severity, VulnerabilityType};
use tree_sitter::Node;

const QUERY_FILE_OS: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  arguments: (argument_list
    (_) @path)
  (#eq? @pkg "os")
  (#match? @method "^(Open|Create|Remove|Stat)$")) @snippet
"#;

// TODO: filepath.Join is safe-by-default. We should only flag it if any argument
// is tainted (user-controlled). Accurate detection requires taint analysis:
//  - mark vars from `r.URL.Query().Get`, `r.FormValue`, `json.Unmarshal`, `os.Getenv`, etc.
//  - propagate taint across simple assignments/returns
// For now we keep filepath.Join unreported to avoid false positives.

impl GolangTreeSitter<'_> {
    pub(super) fn check_file_ops(&mut self, root: Node, src: &[u8]) {
        for m in match_pattern(QUERY_FILE_OS, root, src) {
            if let (Some((_, snippet, line, _)), Some((_, method, _, _))) = (
                m.iter().find(|(n, ..)| n == "snippet"),
                m.iter().find(|(n, ..)| n == "method"),
            ) {
                self.report(
                    snippet,
                    &line.to_string(),
                    VulnerabilityType::UnsafeFileOperation,
                    Severity::High,
                );
            }
        }
    }
}
