# Testing

## Coverage

- Tests are located in `*_test.go` files adjacent to the source.
- Test suite includes table-driven tests asserting correct detection of all DF001-DF009 rules.
- Assertions verify return values, `errors.Is` error types, and exact output format.
- All `Example` functions are verified by `go test` via `// Output:` comments.

## Execution

- `go test -cover .`: Runs the unit tests and asserts coverage requirements.
- The gate checks for race conditions using the Go race detector.