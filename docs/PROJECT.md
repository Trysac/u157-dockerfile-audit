# Project Record

## Objective

Audit Dockerfiles for security mistakes with nine rules: unpinned bases, root user, remote ADD, secrets in ENV or ARG, curl piped to shell and more, with text and JSON output.

## Scope

- Parsing and linting of Dockerfile syntax.
- Identifying security patterns (DF001-DF009).
- Supporting Go library usage and CLI integration.
- Supporting inline suppression via comments.

## Out of Scope

- Building container images.
- Scanning image layers or binary contents.
- Complex shell parsing beyond standard patterns.
- Variable expansion.
- BuildKit secret mounts analysis.
- Docker Compose files.

## Effort Metrics

| Metric | Value |
|---|---|
| Tokens (input / output) | 261827 / 18143 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.0999 |

## Factory run u157 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4350 | 15971 | 0 | 0 | 0.0316 |
| fix-1 | gemini-3.8-flash | no | 26885 | 430 | 0 | 64071 | 0.0266 |
| fix-2 | gemini-3.8-flash | no | 31477 | 312 | 0 | 94930 | 0.0319 |
| audit | gemini-3.1-flash-lite | no | 25963 | 72 | 0 | 10200 | 0.0069 |
| docs | gemini-3.1-flash-lite | no | 3951 | 1358 | 0 | 0 | 0.0030 |

Total: $0.0999. Prices: Anthropic list prices.
