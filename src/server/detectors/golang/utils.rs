use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Node, Query, QueryCursor};

fn node_text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn pos(node: Node) -> (usize, usize) {
    let p = node.start_position();
    (p.row + 1, p.column + 1) // 1-based line/col
}

// Returns a list of matches; each match is a list of (capture_name, text, line, col)
pub fn match_pattern(
    pattern: &str,
    root: Node,
    src: &[u8],
) -> Vec<Vec<(String, String, usize, usize)>> {
   
    let language = tree_sitter_go::LANGUAGE.into();
    let query = Query::new(&language, pattern).expect("invalid query");
    let mut cursor = QueryCursor::new();
    let mut results = vec![];
    let mut matches = cursor.matches(&query, root, src);

    while let Some(m) = matches.next() {
        let captures: Vec<_> = m
            .captures
            .iter()
            .map(|c| {
                let name = query.capture_names()[c.index as usize].to_string();
                let text = node_text(c.node, src).to_string();
                let (line, col) = pos(c.node);
                (name, text, line, col)
            })
            .collect();
        results.push(captures);
    }
    results
}
