# Use targeted standard library regex and line parser for Dockerfile auditing

Status: accepted (generated, pending human review)

## Context

We need a lightweight, embeddable Go library and CLI to audit Dockerfiles for security issues without external heavy dependencies or full shell abstract syntax tree parsers.

## Decision

Implement line-accurate instruction parsing directly with stdlib string manipulation and targeted regular expressions, supporting parser directives (escape char), heredocs skipping, inline ignore comments, and 9 focused security rules.

## Consequences

Zero external dependencies, fast in-memory execution, deterministic line mapping, and easy integration into CI/CD pipelines and Go services.
