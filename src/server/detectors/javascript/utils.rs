use oxc_ast::ast::{BindingPattern, Expression, VariableDeclarator};

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

pub fn is_hardcoded_secret(init: &Expression<'_>) -> Option<String>{
    match init {
        Expression::StringLiteral(str_lit) => {           
            return Some(str_lit.value.to_string());
        }
        Expression::TemplateLiteral(template) => {
            if template.expressions.is_empty() {
                // only flag if it's explict string in the template
                if let Some(quasi) = template.quasis.first() {
                    return Some(quasi.value.raw.to_string());
                }else{
                    return None;
                }
            }else{
                return None;
            }
        }
        _=> return None,
    }
}

