#[cfg(test)]
mod tests {
    use crate::server::detectors::{GolangScanner, Scanner};
    use crate::server::models::findings::{self, VulnerabilityType};

    static SCANNER: GolangScanner = GolangScanner;

    // TODO: filepath.Join is not detected as unsafe file operation
    // will require taint analysis to detect if any argument is user-controlled
    #[test]
    fn detects_unsafe_file_operations() {
        let code = r#"
            package main
            import (
                "os"
                "path/filepath"
            )

            func main() {
                f, _ := os.Open("secret.txt")
                _ = filepath.Join("/tmp", "data")
                _ = os.Create("log.txt")
            }
        "#;

        let findings = SCANNER.scan(code, "test.go");
        let ops: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::UnsafeFileOperation)
            .collect();

        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn detects_hardcoded_secrets() {
        let code = r#"
            package main

            var password = "secretpass"
            const api_key = "abcd1234"
            var token = "tokval"
        "#;

        let findings = SCANNER.scan(code, "test.go");
        let secrets: Vec<_> = findings
            .iter()
            .filter(|f| f.vuln_type == VulnerabilityType::HardcodedSecret)
            .collect();

        assert_eq!(secrets.len(), 3);
    }

    #[test]
    fn detects_sql_injection_with_sprintf() {
        let code = r#"
            package main
            import (
                "database/sql"
                "fmt"
            )

            func query(db *sql.DB, table string) {
                q := fmt.Sprintf("SELECT * FROM %s", table)
                db.Query(q)
            }
        "#;

        let findings = SCANNER.scan(code, "test.go");
  
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::SQLInjection));
    }

    #[test]
    fn detects_sql_injection_from_user_input() {
        let code = r#"
package main

import (
    "database/sql"
    "fmt"
    "net/http"
)

func users(db *sql.DB, r *http.Request) {
    id := r.URL.Query().Get("id")

    query := fmt.Sprintf(
        "SELECT * FROM users WHERE id = '%s'",
        id,
    )

    db.Query(query)
}
"#;

        let findings = SCANNER.scan(code, "test.go");

        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::SQLInjection));
    }

    #[test]
    fn detects_sql_injection_with_query_context() {
        let code = r#"
package main

import (
    "context"
    "database/sql"
    "fmt"
)

func query(ctx context.Context, db *sql.DB, table string) {
    q := fmt.Sprintf(
        "SELECT * FROM %s",
        table,
    )

    db.QueryContext(ctx, q)
}
"#;

        let findings = SCANNER.scan(code, "test.go");

        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::SQLInjection));
    }

    #[test]
    fn detects_command_execution() {
        let code = r#"
            package main
            import (
                "os/exec"
            )

            func run(cmd string) {
                exec.Command("sh", "-c", cmd)
            }
        "#;

        let findings = SCANNER.scan(code, "test.go");
        assert!(findings
            .iter()
            .any(|f| f.vuln_type == VulnerabilityType::UnsafeCodeExecution));
    }

    #[test]
    fn clean_go_file_has_no_findings() {
        let code = r#"
            package main
            import (
                "fmt"
            )

            func main() {
                fmt.Println("hello world")
            }
        "#;

        let findings = SCANNER.scan(code, "test.go");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn secure_go_code_has_no_findings() {
        let code = r#"
package main

import (
    "database/sql"
    "os"
    "os/exec"
    "path/filepath"
)

func main(db *sql.DB) {
    // environment secret
    password := os.Getenv("DB_PASSWORD")

    // parameterized query
    db.Query(
        "SELECT * FROM users WHERE id = ?",
        42,
    )

    // safe path construction
    path := filepath.Join("/var/app", "logs")

    // safe file read
    os.ReadFile(path)

    // fixed command invocation
    exec.Command("ls", "-la")

    _ = password
}
"#;

        let findings = SCANNER.scan(code, "test.go");
        assert!(findings.is_empty());
    }
}
