package main

import (
	"os"

	dockerfileaudit "github.com/Trysac/u157-dockerfile-audit"
)

func main() {
	code := dockerfileaudit.Run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}
