package obolresolver

// client_version_test.go — v0.18.0: the module version obol is told about.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestClientVersionMatchesTheManifest keeps ClientVersion honest.
//
// ⚠️ A VERSION STRING THAT DRIFTS IS WORSE THAN NO VERSION STRING, and this one
// is consumed by a metric another service alerts from. obol counts which client
// contract each consumer runs on `obl_consumer_sdk_total{service_id,sdk_contract}`
// and bounds the value into a closed vocabulary by comparing it against the
// contract IT ships — so a stale value here does not read as "unknown", it reads
// as a DIFFERENT, OLDER consumer, and an operator would go looking for a
// deployment that does not exist. The whole reason the header was added was to
// remove a floor of exactly that kind of unattributable traffic.
//
// It reads versions.yaml directly rather than importing a version library,
// because the manifest is the authority and a second reader of it is a second
// thing to keep in step.
func TestClientVersionMatchesTheManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "versions.yaml"))
	if err != nil {
		t.Fatalf("read versions.yaml: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\s+version:\s*"?([0-9][^"\s]*)"?\s*$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("could not find project.version in versions.yaml. ⚠️ THIS ARM FAILS RATHER " +
			"THAN SKIPS: a guard that cannot read its own authority and passes anyway is the " +
			"shape that lets a version drift for a whole release with a green suite.")
	}
	want := "go-vai-oidc/" + string(m[1])
	if ClientVersion != want {
		t.Errorf("ClientVersion = %q but versions.yaml says the module is %q, so "+
			"the header should read %q. Bump BOTH in the same commit.",
			ClientVersion, string(m[1]), want)
	}
	if !strings.HasPrefix(ClientVersion, "go-vai-oidc/") {
		t.Errorf("ClientVersion %q must name THIS module. It is not obol's SDK version and "+
			"must never be set to one: this module cannot import pkg/oblclient (that package "+
			"lives in obol's nested module, and this module is a dependency of services frozen "+
			"on obol's pre-split root module), so the honest answer to \"which code composed "+
			"this request\" is a string this repository owns.", ClientVersion)
	}
}
