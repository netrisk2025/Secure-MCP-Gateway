package health

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestStorageQuotaLevels: a store filled to 80% and then 95% of its quota
// raises the non-critical storage_quota_<name> warning, and every health
// report carries each store's quota level (FR-9.15).
func TestStorageQuotaLevels(t *testing.T) {
	reqtest.Verifies(t, "FR-9.15")
	dir := t.TempDir()
	m := New(Options{})
	m.AddQuota(&Quota{Name: "journal", Dir: dir, Limit: 10000, Interval: time.Nanosecond})
	m.AddQuota(&Quota{Name: "observation_store", Dir: t.TempDir(), Limit: 10000, Interval: time.Nanosecond})
	fill := func(name string, n int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	level := func(r Report, name string) QuotaLevel {
		for _, l := range r.Quotas {
			if l.Name == name {
				return l
			}
		}
		t.Fatalf("no level for %s in %+v", name, r.Quotas)
		return QuotaLevel{}
	}
	warned := func(r Report) bool {
		for _, c := range r.Causes {
			if c.Name == CauseStorageQuota+"journal" {
				if c.Critical {
					t.Fatal("quota warning is critical")
				}
				return true
			}
		}
		return false
	}
	fill("a", 5000)
	m.Evaluate()
	r := m.Report()
	if l := level(r, "journal"); l.Percent != 50 || l.Warning || warned(r) {
		t.Fatalf("50%%: %+v", l)
	}
	if l := level(r, "observation_store"); l.Bytes != 0 || l.Limit != 10000 {
		t.Fatalf("other store: %+v", l)
	}
	fill("b", 3000) // 80%
	m.Evaluate()
	r = m.Report()
	if l := level(r, "journal"); l.Percent != 80 || !l.Warning || !warned(r) {
		t.Fatalf("80%%: %+v causes %+v", l, r.Causes)
	}
	fill("c", 1500) // 95%
	m.Evaluate()
	r = m.Report()
	l := level(r, "journal")
	if l.Percent != 95 || !warned(r) || m.State() == FailClosed {
		t.Fatalf("95%%: %+v state %s", l, m.State())
	}
	for _, c := range r.Causes {
		if c.Name == CauseStorageQuota+"journal" && !strings.Contains(c.Detail, "95%") {
			t.Fatalf("detail %q", c.Detail)
		}
	}
}
