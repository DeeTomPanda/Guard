# Guard
```
 ███  █   █  ███  ████  ████  
█     █   █ █   █ █   █ █   █ 
█  ██ █   █ █████ ████  █   █ 
█   █ █   █ █   █ █  █  █   █ 
 ███   ███  █   █ █   █ ████                                  
                                
 ```

> ⚠️ Work in progress — APIs and output formats may change.

A static analysis security tool for JavaScript, built in Rust. Guard uses AST traversal (via [OXC](https://github.com/oxc-project/oxc)) to detect security vulnerabilities with higher accuracy than regex-based approaches. Results are viewable directly in the terminal or through a local Flutter dashboard.

---

## Features

- **SQL Injection** — detects raw SQL in template literals, string concatenations, and direct string args
- **Eval & Dangerous Calls** — flags `eval()`, `Function()`, and similar dangerous call expressions
- **Hardcoded Secrets** — catches API keys, tokens, and credentials embedded in source code
- AST-based — fewer false positives than regex scanners
- CI/CD friendly CLI with clean exit codes
- Local web dashboard for browsing findings

---



### How a Scan Works

This example shows the JavaScript scan flow. Other languages follow the same high-level path with a language-specific parser and analyzer.

```
CLI scan path
    └── parse JS with OXC
            └── walk AST with CodeVisitor
                    └── visit_call_expression / visit_variable_declaration
                            └── report() → push to findings Vec
                                    └── store in AppState
                                            └── serve via GET /api/results/{scan_id}
                                                    └── Flutter dashboard renders findings
```

For other languages, replace the JS parser/visitor with the appropriate language-specific analyzer.

### Server Layout

```
localhost:3000/
├── /api/results/{scan_id}   # JSON findings endpoint
├── /app                     # Flutter SPA (base-href: /app/)
└── /                        # redirects → /app
```

---

## Usage

### Scan a file and open the dashboard

```bash
guard scan path/to/file.js
```

This will:
1. Start a local server on `http://localhost:3000`
2. Run the scan against the provided file
3. Open the dashboard automatically at the results page
4. Keep running until `Ctrl+C`


## 🧾 SARIF Output (GitHub Code Scanning)

Guard can export scan results in **SARIF format**, which is compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF tools.

---

### Generate SARIF report

```bash
guard scan path/to/file.js --sarif
```

### Note

This will:
1. Run the scan as usual
2. Generate a SARIF report from the findings
3. Save it to a file automatically
4. Output file naming

If no output path is provided, Guard generates a default file like ` guard-20260615_142355-report.sarif `
checkout `examples` to see the sample SARIF output.

Guard SARIF output is compatible with:

- GitHub Code Scanning  
- VS Code SARIF Viewer  
- Other SARIF-compliant tools  

### Start the server only

```bash
guard serve
```

---

## Building

```bash
# build the rust CLI
cargo build --release

# build the flutter dashboard
cd dashboard
flutter build web --base-href /app/
```

---

## Vulnerability Types

| Type | Example |
|---|---|
| SQL Injection | `` `SELECT * FROM ${table}` `` |
| Eval | `eval(userInput)` |
| Hardcoded Secret | `const API_KEY = "sk-..."` |

---

## Planned

- [x] TypeScript support
- [ ] Taint Analysis
- [ ] Python support
- [x] Go support
- [x] SARIF output format (GitHub Code Scanning compatible)
