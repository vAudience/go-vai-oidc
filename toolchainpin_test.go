package vaioidc

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// go-vai-oidc#9 — the govulncheck-clean toolchain pin, and the gate that must analyse it.
//
// ⛔ THE DEFECT, MEASURED TWICE. `go.mod`'s `toolchain` directive exists — by its own
// comment — to select a patched 1.25.x that is govulncheck-clean. The GitHub Actions job
// that verified it used `setup-go` with `go-version: '1.25'`, which resolves to whatever
// patch the runner has and **ignores the directive entirely**, so it scanned a NEWER
// stdlib than the pin selects and reported clean indefinitely while the pin aged.
//
// ⛔ AND THE LOCAL GATE THAT REPLACED IT REPRODUCED THE SAME DEFECT ONE BOX OVER.
// `GOTOOLCHAIN` defaults to `auto`, which takes the MAXIMUM of the module's requirement
// and whatever is installed — so `make vuln` on any developer machine with a newer Go
// analysed a stdlib the pin does not select. The failure is asymmetric and therefore
// quiet: the gate can only ever be MORE up to date than the artifact, so it fails open,
// forever, behind a green run.
//
// ⭐ The general shape, in the issue's own words: *the check and the thing being checked
// were never the same artifact.* These tests are what keep them the same one.

const (
	goModPath    = "go.mod"
	makefilePath = "Makefile"
	// toolchainDirective is the go.mod line that selects the build toolchain.
	toolchainDirective = "toolchain"
	// gotoolchainVar is the environment variable that steers which Go version
	// govulncheck ANALYSES against — proven with `GOTOOLCHAIN=x govulncheck -version`.
	gotoolchainVar = "GOTOOLCHAIN"
	// toolchainPinMakeVar is the Makefile variable that must carry the derived pin.
	toolchainPinMakeVar = "TOOLCHAIN_PIN"
)

// toolchainPin reads the pin from go.mod, which is the one authority for it.
func toolchainPin(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read %s: %v", goModPath, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == toolchainDirective {
			return fields[1]
		}
	}
	t.Fatalf("%s has no %q directive. If it was removed deliberately, this guard and the "+
		"vuln gate's use of it must go in the SAME change — an unpinned gate that reports "+
		"clean is worse than no gate, because it looks like coverage", goModPath, toolchainDirective)
	return ""
}

func makefile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("read %s: %v", makefilePath, err)
	}
	return string(raw)
}

// TestVulnGateUsesThePinnedToolchain is the assertion that closes go-vai-oidc#9's open
// half: the gate must analyse the stdlib the pin selects, not the one the developer
// happens to have installed.
func TestVulnGateUsesThePinnedToolchain(t *testing.T) {
	line := scanInvocation(t, makefile(t))
	if !strings.Contains(line, gotoolchainVar+"=$("+toolchainPinMakeVar+")") {
		t.Fatalf("the line that runs the scan does not set %s=$(%s):\n\t%s\n"+
			"Without it `go env GOTOOLCHAIN` is `auto`, which takes the MAXIMUM of the module "+
			"requirement and the installed toolchain — so the gate analyses a stdlib the pin does "+
			"not select, and can only ever be MORE up to date than the artifact. It fails OPEN, "+
			"forever, behind a green run",
			gotoolchainVar, toolchainPinMakeVar, strings.TrimSpace(line))
	}
}

// scanInvocation returns the ONE Makefile line that actually runs the scan.
//
// ⛔ The first version of this guard searched the WHOLE Makefile for
// `GOTOOLCHAIN=$(TOOLCHAIN_PIN)`, and a mutation that removed it from the scan line was NOT
// caught — because the neighbouring `govulncheck -version` line, which exists only to PRINT
// what was analysed, still carried the string. A guard satisfied by a line other than the
// one that matters is the failure mode this whole file is about, rebuilt inside the file.
// Found by the mutation battery, not by reading it.
//
// The `-version` line and every `echo` (help text, progress) are excluded by name, and a
// Makefile where the scan cannot be located at all — or where there is more than one — is a
// FAILURE rather than a skip: picking the wrong line is how this guard would report
// coverage it does not have.
func scanInvocation(t *testing.T, mk string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(mk, "\n") {
		code := line
		if i := strings.Index(code, "#"); i >= 0 {
			code = code[:i]
		}
		if !strings.Contains(code, "govulncheck") || !strings.Contains(code, "./...") {
			continue
		}
		if strings.Contains(code, "-version") {
			continue // prints what was analysed; does not analyse anything
		}
		if strings.Contains(code, "echo") {
			continue // help text and progress lines mention the command, never run it
		}
		found = append(found, code)
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly ONE line invoking `govulncheck ./...`, found %d:\n%s\n"+
			"This guard fails rather than guessing, because picking the wrong line is how it "+
			"would report coverage it does not have", len(found), strings.Join(found, "\n"))
	}
	return found[0]
}

// TestTheToolchainPinIsDerivedNotCopied: a literal version in the Makefile would be a
// second copy of the pin, in the one place whose job is to prove the pin is honoured.
//
// ⚠️ This is the guard that would have caught the shape of the ORIGINAL defect had it
// existed: two artifacts each holding a Go version, with nothing reconciling them.
func TestTheToolchainPinIsDerivedNotCopied(t *testing.T) {
	pin := toolchainPin(t)
	mk := makefile(t)

	if !regexp.MustCompile(`(?m)^` + toolchainPinMakeVar + `\s*:?=\s*\$\(shell`).MatchString(mk) {
		t.Errorf("%s must be DERIVED from %s with $(shell …); a static assignment is a second "+
			"copy of the pin", toolchainPinMakeVar, goModPath)
	}
	// The pin must appear in the Makefile only as prose (a comment), never as a value a
	// recipe would use. Strip comments, then look for it.
	var code []string
	for _, line := range strings.Split(mk, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		code = append(code, line)
	}
	if strings.Contains(strings.Join(code, "\n"), pin) {
		t.Errorf("the Makefile writes the toolchain version %q out literally. It must read it from "+
			"%s instead: a second copy that silently disagrees is exactly the failure the vuln "+
			"gate exists to catch, rebuilt inside the gate", pin, goModPath)
	}
}

// TestVulnIsInTheDefaultGate: a vulnerability check nobody runs is not a control. It has
// to be part of `ci-local`, which is this repository's whole CI authority since the
// GitHub Actions workflow was retired.
func TestVulnIsInTheDefaultGate(t *testing.T) {
	mk := makefile(t)
	m := regexp.MustCompile(`(?m)^ci-local:\s*(.*)$`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatal("the Makefile has no ci-local target; it is this repository's only CI authority")
	}
	if !strings.Contains(m[1], "vuln") {
		t.Fatalf("ci-local does not depend on the vuln target (deps: %q). A check that has to be "+
			"remembered is a maintenance promise, not a gate", m[1])
	}
}

// TestTheScannerVersionIsBinding: the target used to check only that `govulncheck` EXISTED
// on PATH, so the stated `GOVULNCHECK_VERSION` was documentation — whatever the developer
// installed last is what ran. forgebox paid for this exact shape with golangci-lint.
func TestTheScannerVersionIsBinding(t *testing.T) {
	mk := makefile(t)
	if regexp.MustCompile(`command -v \$\(GOVULNCHECK\)`).MatchString(mk) {
		t.Error("the vuln target resolves govulncheck from PATH. A PATH lookup proves the tool " +
			"EXISTS and says nothing about which version ran, so the stated pin is documentation")
	}
	if !strings.Contains(mk, "govulncheck@$(GOVULNCHECK_VERSION)") {
		t.Error("the vuln target must install the scanner at $(GOVULNCHECK_VERSION), so the " +
			"version that runs is the version this Makefile names")
	}
}
