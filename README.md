# Guard
 _____ _   _  ___  ____________ 
|  __ \ | | |/ _ \ | ___ \  _  \
| |  \/ | | / /_\ \| |_/ / | | |
| | __| | | |  _  ||    /| | | |
| |_\ \ |_| | | | || |\ \| |/ / 
 \____/\___/\_| |_/\_| \_|___/  
                                
                                
                                
                                
                                
                                
                                
                                
                                
                                
                                
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
git clone https://github.com/you/guard
cd guard
```

then

```bash
# Scan a project
guard scan ./my-project

```

## Future updates

- Support for Python and Go 
- AST parsing support
- Taint Analysis