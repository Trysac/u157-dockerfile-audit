# Architecture

`dockerfileaudit` provides a focused, single-purpose Dockerfile security auditor and parser.

## Processing Pipeline

1. **Parser Directives & Continuation**: Detects `# escape=\ ` or backtick directives before any instruction. Strips comments and joins line continuations while preserving starting line numbers.
2. **Heredoc Skipping**: BuildKit heredocs (`<<EOF` / `<<-EOF`) are bypassed so multi-line scripts are not scanned by simple token checks.
3. **Instruction Tokenization**: Splits commands, flags (e.g. `--checksum=...`), and checks for valid JSON exec form (`[...]`).
4. **Security Auditing**: Evaluates the instruction sequence against security rules DF001 through DF009.
5. **Suppression & Filtering**: Checks inline `# dockerfile-audit: ignore=...` comments and user options (`Disable`, `MinSeverity`).
6. **Ordering**: Deterministically sorts findings by `Line` ascending, then `Rule` ascending.
