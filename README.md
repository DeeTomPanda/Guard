# Guard
```
 ███  █   █  ███  ████  ████  
█     █   █ █   █ █   █ █   █ 
█  ██ █   █ █████ ████  █   █ 
█   █ █   █ █   █ █  █  █   █ 
 ███   ███  █   █ █   █ ████                                  
                                
 ```
A static analysis tool that scans JavaScript codebases for common security vulnerabilities.

## What It Detects

| Vulnerability | Example |
|---------------|---------|
| SQL Injection | String concatenation inside database queries |
| Hardcoded Secrets | Passwords, API keys, tokens assigned to variables |
| Eval Usage | `eval()` called with variables or concatenation |

## Installation and Usage

```bash
# Clone
git clone https://github.com/DeeTomPanda/Guard/
cd guard
make
```

then, head over to the rust build directory and

```bash
# Scan a project
guard scan ./my-project

```

## Future updates

- Support for Python and Go 
- AST parsing support
- Taint Analysis
