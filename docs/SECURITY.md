# Security Policy and Threat Model

## Threat Model

`dockerfileaudit` is designed to parse Dockerfile content which may be sourced from untrusted user uploads or external repositories.

### Defended

- **Denial of Service**: The parser enforces a maximum input size of 1 MiB. Exceeding this limit returns `ErrInputTooLarge`, preventing excessive memory allocation.
- **Secret Exposure**: Rule DF005 inspects `ENV` and `ARG` for sensitive names (e.g., PASSWORD, API_KEY). The diagnostic output reveals only the variable name, ensuring the secret value itself is never logged or emitted in text/JSON reports.
- **Deterministic Execution**: Auditing and parsing are purely in-memory operations with no network or subprocess invocation.

### Not Defended

- **Complex Shell Obfuscation**: The parser identifies patterns for `curl` piped to shell but does not emulate shell execution; highly obfuscated scripts may evade detection.
- **Heredoc Content**: The current implementation skips heredoc bodies (`<<EOF`), meaning commands inside them are not analyzed.