# dockerfile-audit

Dockerfiles often ship images that run as root, pull unpinned latest bases, download scripts straight into a shell or bake passwords into ENV, and review rarely catches it. Hadolint is broad and style-heavy and ships as a separate binary. This Go package parses Dockerfile syntax faithfully enough for line-accurate findings and checks a short list of security rules, embeddable as a library or CLI.

## Installation

`go get github.com/Trysac/u157-dockerfile-audit`

## Usage

```go
package main

import (
	"fmt"
	dockerfileaudit "github.com/Trysac/u157-dockerfile-audit"
)

func main() {
	findings, err := dockerfileaudit.Audit([]byte("FROM ubuntu\n"), dockerfileaudit.Options{})
	if err == nil {
		fmt.Println(dockerfileaudit.FormatText("Dockerfile", findings))
	}
}
```

## API Summary

- `type Instruction`: Contains `Cmd`, `Flags`, `Args`, `Exec` slice, and `Line` number.
- `func Parse(src []byte) ([]Instruction, error)`: Parses the Dockerfile into structured instructions.
- `func Audit(src []byte, opts Options) ([]Finding, error)`: Analyzes instructions against security rules.
- `type Options`: Fields `Disable []string`, `MinSeverity string` (defaults to "low").
- `type Finding`: Fields `Rule`, `Severity`, `Line`, `Message`.
- `ErrInputTooLarge`: Returned when source exceeds 1 MiB limit.

## Rules

| Rule | Severity | Description |
|---|---|---|
| DF001 | medium | FROM without tag or digest or with tag latest |
| DF002 | high | Final stage has no USER or last USER is root / 0 |
| DF003 | medium | ADD with remote http(s) source and no --checksum flag |
| DF004 | low | ADD of local source not ending in tar archive extensions |
| DF005 | high | ENV or ARG with sensitive variable names and non-empty values |
| DF006 | high | RUN where curl or wget is piped to a shell |
| DF007 | low | RUN using sudo |
| DF008 | medium | RUN with chmod 777, 0777 or a+rwx |
| DF009 | low | EXPOSE 22 (SSH daemon) |

## Why not Hadolint?

An embeddable Go library with only security rules and stable rule IDs, rather than a broad, style-heavy external binary.

See full security policy in [docs/SECURITY.md](docs/SECURITY.md).