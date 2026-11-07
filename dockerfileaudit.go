package dockerfileaudit

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Maximum input size accepted by Parse and Audit (1 MiB).
const MaxInputSize = 1024 * 1024

// Sentinel errors.
var (
	ErrInputTooLarge  = errors.New("dockerfileaudit: input exceeds maximum allowed size (1 MiB)")
	ErrInvalidOptions = errors.New("dockerfileaudit: invalid audit options")
)

// Instruction represents a parsed Dockerfile instruction.
type Instruction struct {
	Cmd         string   // Uppercased instruction name (FROM, RUN, etc.)
	Flags       []string // Leading flags such as --checksum=...
	Args        string   // Raw arguments after flags (continuation lines joined by a single space)
	Exec        []string // Non-nil only when valid JSON exec form was parsed
	Line        int      // 1-based starting line number
	Suppression []string // Rule IDs suppressed by preceding comment
}

// Finding represents a detected security issue.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// Options configures the audit engine.
type Options struct {
	Disable     []string
	MinSeverity string // "low" (default), "medium", or "high"
}

// Severity ranks for comparisons.
const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

var severityRank = map[string]int{
	SeverityLow:    1,
	SeverityMedium: 2,
	SeverityHigh:   3,
}

var sensitiveEnvPattern = regexp.MustCompile(`(?i)(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)`)
var curlWgetPipedPattern = regexp.MustCompile(`(?i)(?:curl|wget)[^|;&]*\|\s*(?:sh|bash|zsh|ash)(?:\s|$)`)
var sudoPattern = regexp.MustCompile(`(?:^|[;&|\s])sudo(?:\s+|$)`)
var chmodPattern = regexp.MustCompile(`(?:^|[;&|\s])chmod(?:\s+[^;&|]*?\s+|\s+)(?:777|0777|a\+rwx)(?:\s|;|&&|\||$)`)
var ignorePattern = regexp.MustCompile(`^#\s*dockerfile-audit:\s*ignore=([A-Za-z0-9_,\s]+)`)

// Parse parses the provided Dockerfile source bytes into instructions.
func Parse(src []byte) ([]Instruction, error) {
	if len(src) > MaxInputSize {
		return nil, ErrInputTooLarge
	}

	text := string(src)
	lines := strings.Split(text, "\n")

	escapeChar := '\\'
	lineIdx := 0

	// Check parser directives before the first non-comment / non-directive line.
	for lineIdx < len(lines) {
		line := strings.TrimSpace(lines[lineIdx])
		if strings.HasPrefix(line, "#") {
			content := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if strings.HasPrefix(strings.ToLower(content), "escape=") {
				val := strings.TrimPrefix(strings.ToLower(content), "escape=")
				val = strings.TrimSpace(val)
				if len(val) > 0 {
					escapeChar = rune(val[0])
				}
				lineIdx++
				continue
			}
			// Normal comment or ignore comment before first instruction
			break
		} else if line == "" {
			lineIdx++
			continue
		} else {
			break
		}
	}

	var instructions []Instruction
	var pendingSuppression []string

	for lineIdx < len(lines) {
		rawLine := lines[lineIdx]
		trimmed := strings.TrimSpace(rawLine)

		if trimmed == "" {
			pendingSuppression = nil
			lineIdx++
			continue
		}

		if strings.HasPrefix(trimmed, "#") {
			match := ignorePattern.FindStringSubmatch(trimmed)
			if len(match) > 1 {
				rules := strings.Split(match[1], ",")
				for _, r := range rules {
					r = strings.TrimSpace(r)
					if r != "" {
						pendingSuppression = append(pendingSuppression, strings.ToUpper(r))
					}
				}
			} else {
				pendingSuppression = nil
			}
			lineIdx++
			continue
		}

		startLine := lineIdx + 1
		var fullSegments []string
		var heredocDelim string
		var heredocTrimTabs bool

		for lineIdx < len(lines) {
			current := lines[lineIdx]
			curTrimmed := strings.TrimSpace(current)

			// If we are currently inside a heredoc body, consume until terminator line.
			if heredocDelim != "" {
				checkLine := current
				if heredocTrimTabs {
					checkLine = strings.TrimLeft(checkLine, "\t")
				}
				if strings.TrimSpace(checkLine) == heredocDelim {
					heredocDelim = ""
				}
				lineIdx++
				continue
			}

			// Outside heredoc body:
			if len(fullSegments) > 0 {
				if curTrimmed == "" || strings.HasPrefix(curTrimmed, "#") {
					lineIdx++
					continue
				}
			}

			// Check if this line ends with escapeChar
			runes := []rune(strings.TrimRight(current, "\r\t "))
			hasContinuation := false
			var cleanLine string
			if len(runes) > 0 && runes[len(runes)-1] == escapeChar {
				hasContinuation = true
				cleanLine = strings.TrimSpace(string(runes[:len(runes)-1]))
			} else {
				cleanLine = strings.TrimSpace(string(runes))
			}

			if cleanLine != "" {
				fullSegments = append(fullSegments, cleanLine)
			}

			// Check if heredoc syntax was introduced (<<-?([A-Za-z0-9_]+|'[^']+'|"[^"]+"))
			hdDelim, hdTab := extractHeredocDelim(cleanLine)
			if hdDelim != "" {
				heredocDelim = hdDelim
				heredocTrimTabs = hdTab
			}

			lineIdx++
			if !hasContinuation && heredocDelim == "" {
				break
			}
		}

		if len(fullSegments) == 0 {
			pendingSuppression = nil
			continue
		}

		combined := strings.Join(fullSegments, " ")
		inst := parseInstructionContent(combined, startLine)
		inst.Suppression = pendingSuppression
		pendingSuppression = nil

		instructions = append(instructions, inst)
	}

	return instructions, nil
}

var heredocPattern = regexp.MustCompile(`<<(-)?(?:'([A-Za-z0-9_]+)'|"([A-Za-z0-9_]+)"|([A-Za-z0-9_]+))`)

func extractHeredocDelim(s string) (string, bool) {
	matches := heredocPattern.FindStringSubmatch(s)
	if len(matches) > 4 {
		tabs := matches[1] == "-"
		delim := matches[2]
		if delim == "" {
			delim = matches[3]
		}
		if delim == "" {
			delim = matches[4]
		}
		return delim, tabs
	}
	return "", false
}

func parseInstructionContent(line string, startLine int) Instruction {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])
	rest := ""
	if len(parts) > 1 {
		rest = strings.TrimSpace(parts[1])
	}

	var flags []string
	for strings.HasPrefix(rest, "--") {
		flagPart := ""
		if idx := strings.IndexAny(rest, " \t"); idx != -1 {
			flagPart = rest[:idx]
			rest = strings.TrimSpace(rest[idx:])
		} else {
			flagPart = rest
			rest = ""
		}
		flags = append(flags, flagPart)
	}

	var exec []string
	if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
		var parsed []string
		if err := json.Unmarshal([]byte(rest), &parsed); err == nil {
			exec = parsed
		}
	}

	return Instruction{
		Cmd:   cmd,
		Flags: flags,
		Args:  rest,
		Exec:  exec,
		Line:  startLine,
	}
}

// Audit inspects Dockerfile bytes and returns discovered findings.
func Audit(src []byte, opts Options) ([]Finding, error) {
	if len(src) > MaxInputSize {
		return nil, ErrInputTooLarge
	}

	minSev := strings.ToLower(opts.MinSeverity)
	if minSev == "" {
		minSev = SeverityLow
	}
	threshold, ok := severityRank[minSev]
	if !ok {
		return nil, fmt.Errorf("%w: unknown min severity '%s'", ErrInvalidOptions, opts.MinSeverity)
	}

	disabled := make(map[string]bool)
	for _, d := range opts.Disable {
		disabled[strings.ToUpper(strings.TrimSpace(d))] = true
	}

	instructions, err := Parse(src)
	if err != nil {
		return nil, err
	}

	var findings []Finding

	var hasFrom bool
	var stages []string
	var stageFromInst []Instruction
	var stageUsers [][]Instruction

	for _, inst := range instructions {
		suppressed := func(rule string) bool {
			if disabled[rule] {
				return true
			}
			for _, sup := range inst.Suppression {
				if sup == rule {
					return true
				}
			}
			return false
		}

		switch inst.Cmd {
		case "FROM":
			hasFrom = true
			image, stageName := parseFromArgs(inst.Args)
			stageFromInst = append(stageFromInst, inst)
			stageUsers = append(stageUsers, nil)

			// DF001 check
			if !suppressed("DF001") && isUnpinnedBase(image, stages) {
				findings = append(findings, Finding{
					Rule:     "DF001",
					Severity: SeverityMedium,
					Line:     inst.Line,
					Message:  fmt.Sprintf("base image '%s' is not pinned to a tag or digest", image),
				})
			}

			if stageName != "" {
				stages = append(stages, strings.ToLower(stageName))
			}

		case "USER":
			if len(stageUsers) > 0 {
				idx := len(stageUsers) - 1
				stageUsers[idx] = append(stageUsers[idx], inst)
			}

		case "ADD":
			auditAdd(inst, suppressed, &findings)

		case "ENV":
			auditEnv(inst, suppressed, &findings)

		case "ARG":
			auditArg(inst, suppressed, &findings)

		case "RUN":
			auditRun(inst, suppressed, &findings)

		case "EXPOSE":
			auditExpose(inst, suppressed, &findings)
		}
	}

	// DF002 check on final stage
	if hasFrom && len(stageFromInst) > 0 {
		lastStageIdx := len(stageFromInst) - 1
		lastFrom := stageFromInst[lastStageIdx]
		users := stageUsers[lastStageIdx]

		checkDF002 := func(rule string, inst Instruction) bool {
			if disabled[rule] {
				return true
			}
			for _, sup := range inst.Suppression {
				if sup == rule {
					return true
				}
			}
			return false
		}

		if len(users) == 0 {
			if !checkDF002("DF002", lastFrom) {
				findings = append(findings, Finding{
					Rule:     "DF002",
					Severity: SeverityHigh,
					Line:     lastFrom.Line,
					Message:  "final stage does not set a non-root USER",
				})
			}
		} else {
			lastUser := users[len(users)-1]
			uVal := strings.TrimSpace(lastUser.Args)
			if isRootUser(uVal) {
				if !checkDF002("DF002", lastUser) {
					findings = append(findings, Finding{
						Rule:     "DF002",
						Severity: SeverityHigh,
						Line:     lastUser.Line,
						Message:  "final stage USER is set to root",
					})
				}
			}
		}
	}

	// Filter by MinSeverity
	var filtered []Finding
	for _, f := range findings {
		if severityRank[f.Severity] >= threshold {
			filtered = append(filtered, f)
		}
	}

	// Sort findings by line then rule
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Line != filtered[j].Line {
			return filtered[i].Line < filtered[j].Line
		}
		return filtered[i].Rule < filtered[j].Rule
	})

	return filtered, nil
}

func parseFromArgs(args string) (image string, asStage string) {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return "", ""
	}
	image = fields[0]
	for i := 1; i < len(fields)-1; i++ {
		if strings.EqualFold(fields[i], "AS") {
			asStage = fields[i+1]
			break
		}
	}
	return image, asStage
}

func isUnpinnedBase(image string, prevStages []string) bool {
	if strings.EqualFold(image, "scratch") {
		return false
	}
	if strings.Contains(image, "$") {
		return false
	}
	lowerImg := strings.ToLower(image)
	for _, stage := range prevStages {
		if lowerImg == stage {
			return false
		}
	}

	if strings.Contains(image, "@sha256:") {
		return false
	}

	idx := strings.LastIndex(image, ":")
	if idx == -1 {
		return true
	}

	tag := image[idx+1:]
	if strings.Contains(tag, "/") {
		return true
	}
	if strings.EqualFold(tag, "latest") {
		return true
	}
	return false
}

func isRootUser(u string) bool {
	if idx := strings.Index(u, ":"); idx != -1 {
		u = u[:idx]
	}
	u = strings.TrimSpace(u)
	return u == "root" || u == "0"
}

func auditAdd(inst Instruction, suppressed func(string) bool, findings *[]Finding) {
	hasChecksum := false
	for _, f := range inst.Flags {
		if strings.HasPrefix(f, "--checksum=") {
			hasChecksum = true
			break
		}
	}

	var sources []string
	if len(inst.Exec) > 1 {
		sources = inst.Exec[:len(inst.Exec)-1]
	} else {
		f := strings.Fields(inst.Args)
		if len(f) > 1 {
			sources = f[:len(f)-1]
		}
	}

	for _, src := range sources {
		isURL := strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://")
		if isURL {
			if !hasChecksum && !suppressed("DF003") {
				*findings = append(*findings, Finding{
					Rule:     "DF003",
					Severity: SeverityMedium,
					Line:     inst.Line,
					Message:  fmt.Sprintf("ADD with remote URL source '%s' lacks --checksum", src),
				})
			}
		} else {
			if !isTarball(src) && !suppressed("DF004") {
				*findings = append(*findings, Finding{
					Rule:     "DF004",
					Severity: SeverityLow,
					Line:     inst.Line,
					Message:  fmt.Sprintf("ADD used instead of COPY for local source '%s'", src),
				})
			}
		}
	}
}

func isTarball(path string) bool {
	lower := strings.ToLower(path)
	extensions := []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"}
	for _, ext := range extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func auditEnv(inst Instruction, suppressed func(string) bool, findings *[]Finding) {
	if suppressed("DF005") {
		return
	}
	args := inst.Args
	if strings.Contains(args, "=") {
		// key=value pairs
		pairs := parseEnvKeyValuePairs(args)
		for _, pair := range pairs {
			if pair.val != "" && sensitiveEnvPattern.MatchString(pair.key) {
				*findings = append(*findings, Finding{
					Rule:     "DF005",
					Severity: SeverityHigh,
					Line:     inst.Line,
					Message:  fmt.Sprintf("sensitive variable '%s' defined with non-empty default value", pair.key),
				})
			}
		}
	} else {
		// Legacy: ENV key value
		f := strings.Fields(args)
		if len(f) >= 2 {
			key := f[0]
			val := strings.Join(f[1:], " ")
			if val != "" && sensitiveEnvPattern.MatchString(key) {
				*findings = append(*findings, Finding{
					Rule:     "DF005",
					Severity: SeverityHigh,
					Line:     inst.Line,
					Message:  fmt.Sprintf("sensitive variable '%s' defined with non-empty default value", key),
				})
			}
		}
	}
}

type envPair struct {
	key string
	val string
}

func parseEnvKeyValuePairs(s string) []envPair {
	var pairs []envPair
	fields := strings.Fields(s)
	for _, f := range fields {
		if idx := strings.Index(f, "="); idx != -1 {
			k := f[:idx]
			v := f[idx+1:]
			v = strings.Trim(v, `"' `)
			pairs = append(pairs, envPair{key: k, val: v})
		}
	}
	return pairs
}

func auditArg(inst Instruction, suppressed func(string) bool, findings *[]Finding) {
	if suppressed("DF005") {
		return
	}
	parts := strings.SplitN(inst.Args, "=", 2)
	key := strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"' `)
		if val != "" && sensitiveEnvPattern.MatchString(key) {
			*findings = append(*findings, Finding{
				Rule:     "DF005",
				Severity: SeverityHigh,
				Line:     inst.Line,
				Message:  fmt.Sprintf("sensitive variable '%s' defined with non-empty default value", key),
			})
		}
	}
}

func auditRun(inst Instruction, suppressed func(string) bool, findings *[]Finding) {
	cmdStr := inst.Args
	if len(inst.Exec) > 0 {
		cmdStr = strings.Join(inst.Exec, " ")
	}

	if !suppressed("DF006") && curlWgetPipedPattern.MatchString(cmdStr) {
		*findings = append(*findings, Finding{
			Rule:     "DF006",
			Severity: SeverityHigh,
			Line:     inst.Line,
			Message:  "remote script retrieved with curl or wget piped to shell",
		})
	}

	if !suppressed("DF007") && sudoPattern.MatchString(cmdStr) {
		*findings = append(*findings, Finding{
			Rule:     "DF007",
			Severity: SeverityLow,
			Line:     inst.Line,
			Message:  "avoid sudo in container RUN command",
		})
	}

	if !suppressed("DF008") && chmodPattern.MatchString(cmdStr) {
		*findings = append(*findings, Finding{
			Rule:     "DF008",
			Severity: SeverityMedium,
			Line:     inst.Line,
			Message:  "overly permissive permissions (chmod 777 or a+rwx)",
		})
	}
}

func auditExpose(inst Instruction, suppressed func(string) bool, findings *[]Finding) {
	if suppressed("DF009") {
		return
	}
	ports := strings.Fields(inst.Args)
	for _, p := range ports {
		clean := strings.ToLower(p)
		if clean == "22" || clean == "22/tcp" {
			*findings = append(*findings, Finding{
				Rule:     "DF009",
				Severity: SeverityLow,
				Line:     inst.Line,
				Message:  "EXPOSE 22 for SSH daemon should be avoided",
			})
			break
		}
	}
}

// FormatText formats findings as plain text lines.
func FormatText(path string, findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("%s:%d: %s %s: %s\n", path, f.Line, f.Rule, f.Severity, f.Message))
	}
	return b.String()
}

// FormatJSON formats findings as a JSON array.
func FormatJSON(findings []Finding) ([]byte, error) {
	if findings == nil {
		findings = []Finding{}
	}
	return json.MarshalIndent(findings, "", "  ")
}

// Run executes the CLI logic with args, writing results to stdout and errors to stderr.
// Returns status code (0 = success / clean, 1 = findings detected, 2 = usage / execution error).
func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dockerfile-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	format := fs.String("format", "text", "Output format: text|json")
	minSeverity := fs.String("min-severity", "low", "Minimum severity: low|medium|high")
	disableFlag := fs.String("disable", "", "Comma-separated rules to disable (e.g. DF004,DF007)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "dockerfile-audit: Dockerfile path required")
		return 2
	}

	filePath := rest[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(stderr, "dockerfile-audit: failed to read %s: %v\n", filePath, err)
		return 2
	}

	var disabled []string
	if *disableFlag != "" {
		for _, d := range strings.Split(*disableFlag, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				disabled = append(disabled, d)
			}
		}
	}

	opts := Options{
		Disable:     disabled,
		MinSeverity: *minSeverity,
	}

	findings, err := Audit(data, opts)
	if err != nil {
		fmt.Fprintf(stderr, "dockerfile-audit: %v\n", err)
		return 2
	}

	switch strings.ToLower(*format) {
	case "text":
		if len(findings) > 0 {
			fmt.Fprint(stdout, FormatText(filePath, findings))
		}
	case "json":
		jb, err := FormatJSON(findings)
		if err != nil {
			fmt.Fprintf(stderr, "dockerfile-audit: failed to encode JSON: %v\n", err)
			return 2
		}
		fmt.Fprintln(stdout, string(jb))
	default:
		fmt.Fprintf(stderr, "dockerfile-audit: unknown format %s\n", *format)
		return 2
	}

	if len(findings) > 0 {
		return 1
	}
	return 0
}
