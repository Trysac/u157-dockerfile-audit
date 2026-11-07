// Package dockerfileaudit is a small, dependency-free Go library: Audit Dockerfiles for security mistakes with nine rules: unpinned bases, root user, remote ADD, secrets in ENV or ARG, curl piped to shell and more, with text and JSON output
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package dockerfileaudit
