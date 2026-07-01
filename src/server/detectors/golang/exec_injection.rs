use super::{go_scanner::GolangTreeSitter, utils::match_pattern};
use crate::server::models::findings::{Severity, VulnerabilityType};
use tree_sitter::Node;

const QUERY_EXEC_COMMAND_DYNAMIC: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  arguments: (argument_list
    [
      (identifier)
      (call_expression)
    ] @cmdarg
    (_)* )
  (#eq? @pkg "exec")
  (#match? @method "^(Command|CommandContext)$")) @snippet
"#;

const QUERY_EXEC_COMMAND_SHELL: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  arguments: (argument_list
    (interpreted_string_literal) @shell
    (interpreted_string_literal) @flag
    (_)* )
  (#eq? @pkg "exec")
  (#match? @method "^(Command|CommandContext)$")
  (#match? @shell "^(\"?sh\"?|\"?bash\"?)$")
  (#match? @flag "^\"?-c\"?$") ) @snippet
"#;

const QUERY_SYSCALL_EXEC: &str = r#"
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @method)
  arguments: (argument_list
    (_) @path
    (_) @argv
    (_) @envv)
  (#eq? @pkg "syscall")
  (#eq? @method "Exec")) @snippet
"#;

impl GolangTreeSitter<'_> {
    pub(super) fn check_exec(&mut self, root: Node, src: &[u8]) {
        for m in match_pattern(QUERY_EXEC_COMMAND_DYNAMIC, root, src) {
            if let Some((_, snippet, line, _)) = m.iter().find(|(n, ..)| n == "snippet") {
                self.report(
                    snippet,
                    &line.to_string(),
                    VulnerabilityType::UnsafeCodeExecution,
                    Severity::High,
                );
            }
        }

        for m in match_pattern(QUERY_EXEC_COMMAND_SHELL, root, src) {
            if let Some((_, snippet, line, _)) = m.iter().find(|(n, ..)| n == "snippet") {
                self.report(
                    snippet,
                    &line.to_string(),
                    VulnerabilityType::UnsafeCodeExecution,
                    Severity::High,
                );
            }
        }
    }

    pub(super) fn check_syscall(&mut self, root: Node, src: &[u8]) {
        for m in match_pattern(QUERY_SYSCALL_EXEC, root, src) {
            if let (Some((_, snippet, line, _)), Some((_, method, _, _))) = (
                m.iter().find(|(n, ..)| n == "snippet"),
                m.iter().find(|(n, ..)| n == "method"),
            ) {
                self.report(
                    snippet,
                    &line.to_string(),
                    VulnerabilityType::UnsafeCodeExecution,
                    Severity::High,
                );
            }
        }
    }
}
