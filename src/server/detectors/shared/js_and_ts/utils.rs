use oxc_ast::ast::{Expression};

pub fn is_secret_name(name: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "passwd",
        "pwd",
        "client_secret",
        "auth_token",
        "bearer_token",
        "jwt",
        "db_password",
        "database_password",
        "aws_secret",
        "aws_access_key",
        "ssh_key",
        "credential",
        "credentials",
        "password",
        "secret",
        "token",
    ];

    let name = name.to_lowercase();

    KEYWORDS.iter().any(|k| name.contains(k))
}

pub fn is_hardcoded_secret(init: &Expression<'_>) -> Option<String> {
    match init {
        // enclosed within "" ?
        Expression::StringLiteral(str_lit) => Some(str_lit.value.to_string()),
        // enclosed within ``
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            template.quasis.first().map(|q| q.value.raw.to_string())
        }
        _ => return None,
    }
}

pub fn is_dangerous_call(name: &str) -> bool {
    matches!(
        name,
        "eval" | "Function" | "setTimeout" | "setInterval" | "exec" | "query" | "queryRaw"
    )
}


pub fn contains_sql_keyword(expr: &Expression) -> bool {
    match expr {
        Expression::TemplateLiteral(t) => {
            // hanlde outer and inner quasis
            // eg `${"SELECT * FROM " + table}`
            t.quasis.iter().any(|q| has_sql_keyword(&q.value.raw))
                || t.expressions.iter().any(|e| contains_sql_keyword(e))
        }
        // check for sql strings with + eg "SELECT FROM TABLE WHERE id = " + value
        Expression::BinaryExpression(bin) => {
            contains_sql_keyword(&bin.left) || contains_sql_keyword(&bin.right)
        }
        Expression::StringLiteral(s) => {
            has_sql_keyword(&s.value)
        }
        _ => false,
    }
}

fn has_sql_keyword(s: &str) -> bool {
    let upper = s.to_uppercase();
    let trimmed = upper.trim_start();
    trimmed.starts_with("SELECT")
        || trimmed.starts_with("INSERT")
        || trimmed.starts_with("UPDATE")
        || trimmed.starts_with("DELETE")
        || trimmed.starts_with("DROP")
        || trimmed.starts_with("CREATE")
        || trimmed.contains(" WHERE ")
        || trimmed.contains(" FROM ")
}


pub fn contains_dynamic_value(expr: &Expression) -> bool {
    match expr {
        // literals are safe as they're hardcoded
        Expression::StringLiteral(_) | Expression::NumericLiteral(_) => false,
        // an identifier means a variable is being concatenated in
        Expression::Identifier(_) => true,
        // a function call result being concatenated in
        Expression::CallExpression(_) => true,
        // recurse into both sides of +(for multiline sql queries )
        Expression::BinaryExpression(bin) => {
            contains_dynamic_value(&bin.left) || contains_dynamic_value(&bin.right)
        }
        _ => true, // assume dynamic if unknown
    }
}

// unwrap as any assertions
// eg:  (eval as any)(...) → eval(...)
pub fn unwrap_ts_expression<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::ParenthesizedExpression(e) => unwrap_ts_expression(&e.expression),
        Expression::TSAsExpression(e) => unwrap_ts_expression(&e.expression),
        Expression::TSSatisfiesExpression(e) => unwrap_ts_expression(&e.expression),
        Expression::TSNonNullExpression(e) => unwrap_ts_expression(&e.expression),
        _ => expr,
    }
}