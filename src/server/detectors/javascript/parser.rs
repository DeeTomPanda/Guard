use oxc::{allocator::Allocator, parser::Parser, span::SourceType};

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
