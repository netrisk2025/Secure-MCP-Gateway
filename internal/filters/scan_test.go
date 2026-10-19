package filters

import (
	"context"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestScanWorkbench(t *testing.T) {
	// FR-8.27 also needs the G-02 view; console/e2e covers that part.
	reqtest.Partial(t, "FR-8.27")
	ctx := context.Background()
	o := Options{RequestBodyBytes: 1 << 20, ResultBytes: 8 << 20}

	// A redaction profile on a response: matches, transformed output and
	// disposition, with per-filter timing.
	rep, err := Scan(ctx, o, ScanRequest{Stage: "response", Filters: []string{IDPIIDetect}, Input: "mail jane@example.com or call (555) 234-5678"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Disposition != "redact" || rep.Output == nil || strings.Contains(*rep.Output, "jane@example.com") {
		t.Fatalf("pii redaction: %+v", rep)
	}
	if len(rep.Filters) != 1 || rep.Filters[0].ID != IDPIIDetect || len(rep.Filters[0].Findings) == 0 || rep.Filters[0].Version == "" {
		t.Fatalf("filter runs: %+v", rep.Filters)
	}
	if rep.InputBytes == 0 || rep.DurationUs < 0 {
		t.Fatalf("sizes: %+v", rep)
	}

	// A known secret format in request arguments blocks.
	rep, err = Scan(ctx, o, ScanRequest{Stage: "request", Input: unsplit(`{"q": "key AKIA⟨⟩IOSFODNN7EXAMPLE"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Disposition != "block" || rep.ReasonCode != ReasonSecretInArguments {
		t.Fatalf("secret block: %+v", rep)
	}
	if len(rep.Filters) < 2 {
		t.Fatalf("all request filters should run without a selection: %+v", rep.Filters)
	}

	// Clean text is released unchanged and not echoed.
	rep, err = Scan(ctx, o, ScanRequest{Stage: "response", Filters: []string{IDPIIDetect, IDUnicodeControl}, Input: "version 4.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Disposition != "release" || rep.Output != nil {
		t.Fatalf("clean: %+v", rep)
	}

	for _, bad := range []ScanRequest{{Stage: "metadata"}, {Stage: "request", Filters: []string{IDDelimitUntrusted}}} {
		if _, err := Scan(ctx, o, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
