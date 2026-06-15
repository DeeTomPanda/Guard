#[cfg(test)]
mod tests {
    use crate::server::detectors::{JavaScriptScanner,Scanner};
    use crate::server::models::findings::VulnerabilityType;

    // declare once, use everywhere
    static SCANNER: JavaScriptScanner = JavaScriptScanner{};

    // =========================================================
    // HARDCODED SECRETS
    // =========================================================

    #[test]
    fn detects_basic_hardcoded_secrets() {
        let code = r#"
            const password = "secret123";
            const apiKey = "abcd";
            const token = `xyz`;
            const obj = {
                password: "objsecret"
            }
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let secrets: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::HardcodedSecret)
            .collect();
        assert_eq!(secrets.len(), 3);
    }

    #[test]
    fn no_secret_when_value_is_function_call() {
        // values come from functions, not literals — should not flag
        let code = r#"
            const password = getPasswordFromEnv();
            const apiKey = fetchApiKey();
            const token = generateToken();
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let secrets: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::HardcodedSecret)
            .collect();
        assert_eq!(secrets.len(), 0);
    }

    #[test]
    fn no_secret_when_template_literal_has_expression() {
        // `${getPassword()}` is not hardcoded
        let code = r#"
            const passwd = `${getPassword()}`;
            const token = `Bearer ${fetchToken()}`;
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let secrets: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::HardcodedSecret)
            .collect();
        assert_eq!(secrets.len(), 0);
    }

    #[test]
    fn no_secret_for_unrelated_string_variables() {
        // variable names like myVar, config, username should not trigger
        let code = r#"
            let myVar = "abcde";
            const username = "admin";
            const greeting = "hello world";
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let secrets: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::HardcodedSecret)
            .collect();
        assert_eq!(secrets.len(), 0);
    }

    #[test]
    fn detects_secret_in_object() {
        let code = r#"
            const password="supersecret";
            const config = { password: "secret" } 
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let secrets: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::HardcodedSecret)
            .collect();
        assert_eq!(secrets.len(), 2);
    }

    // =========================================================
    // EVAL & DANGEROUS CALLS
    // =========================================================

    #[test]
    fn detects_direct_eval() {
        let code = r#"
            eval("alert(1)");
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let evals: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::Eval)
            .collect();
        assert_eq!(evals.len(), 1);
    }

    #[test]
    fn detects_function_constructor() {
        // new Function(...) is effectively eval
        let code = r#"
            const fn = new Function("return 1");
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let evals: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::Eval)
            .collect();
        assert_eq!(evals.len(), 1);
    }

    #[test]
    fn detects_settimeout_with_string() {
        // setTimeout with a string arg is eval in disguise
        let code = r#"
            setTimeout("doSomething()", 1000);
            setInterval("doSomethingElse()", 500);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let evals: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::Eval)
            .collect();
        assert_eq!(evals.len(), 2);
    }

    #[test]
    fn no_eval_for_normal_calls() {
        let code = r#"
            console.log("hello");
            Math.random();
            parseInt("42");
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let evals: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::Eval)
            .collect();
        assert_eq!(evals.len(), 0);
    }

    // =========================================================
    // SQL INJECTION
    // =========================================================

    #[test]
    fn detects_sql_in_template_literal() {
        let code = r#"
            db.query(`SELECT * FROM ${table}`);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let sql: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::SQLInjection)
            .collect();
        assert_eq!(sql.len(), 1);
    }

    #[test]
    fn detects_sql_in_binary_concat() {
        let code = r#"
            db.query("SELECT * FROM " + table + " WHERE id = " + id);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let sql: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::SQLInjection)
            .collect();
        assert_eq!(sql.len(), 1);
    }

    #[test]
    fn skip_sql_in_plain_string() {
        // hardcoded SQL string passed directly 
        let code = r#"
            db.query("SELECT * FROM users WHERE id = 1");
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let sql: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::SQLInjection)
            .collect();
        assert_eq!(sql.len(), 0);
    }

    #[test]
    fn detects_sql_in_template_with_binary_expression() {
        // `${"SELECT * FROM " + table}` — binary inside template expression
        let code = r#"
            db.query(`${"SELECT * FROM " + table}`);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let sql: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::SQLInjection)
            .collect();
        assert_eq!(sql.len(), 1);
    }

    #[test]
    fn no_sql_for_parameterized_query() {
        // parameterized queries with ? or $1 placeholders are safe
        let code = r#"
            db.query("SELECT * FROM users WHERE id = ?", [id]);
            db.query("SELECT * FROM users WHERE id = $1", [id]);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let sql: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::SQLInjection)
            .collect();
        assert_eq!(sql.len(), 0);
    }

    #[test]
    fn no_sql_for_unrelated_template_literal() {
        // template literal with no SQL keywords
        let code = r#"
            const msg = `Hello ${name}`;
            console.log(`User ${id} logged in`);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        let sql: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::SQLInjection)
            .collect();
        assert_eq!(sql.len(), 0);
    }

    // =========================================================
    // MIXED — multiple vulns in one file
    // =========================================================

    #[test]
    fn detects_multiple_vuln_types_in_one_file() {
        let code = r#"
            const password = "hunter2";
            eval(userInput);
            db.query(`SELECT * FROM ${table}`);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::HardcodedSecret));
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::Eval));
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::SQLInjection));
    }

    #[test]
    fn clean_file_has_no_findings() {
        let code = r#"
            const name = "guard";
            const version = getVersion();
            const result = db.query("SELECT * FROM users WHERE id = ?", [userId]);
        "#;
        let findings = SCANNER.scan(code, "test.js");
        assert_eq!(findings.len(), 0);
    }
}
