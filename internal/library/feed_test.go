package library

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestStaleRevocationFeedBlocksImports: while the revocation feed can be
// read, imports proceed; once it has been unreadable for longer than
// CP-34 (24 h), imports are refused with REVOCATION_FEED_STALE and the
// alert is raised once (evidence event, FeedStale for health); when the
// feed is readable again, the block lifts (SR-3-4).
func TestStaleRevocationFeedBlocksImports(t *testing.T) {
	reqtest.Verifies(t, "SR-3-4")
	e := newEnv(t)
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "a-id", Revision: "1"}), ImportOptions{}); err != nil {
		t.Fatalf("import with a readable feed: %v", err)
	}
	feed := filepath.Join(e.lib.Dir(), packaging.RevocationsDir)
	if err := os.MkdirAll(feed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(feed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(feed, 0o700) })
	if _, err := os.ReadDir(feed); err == nil {
		t.Skip("running with privileges that read a mode-000 directory")
	}
	// Unreadable but within CP-34: imports still proceed.
	e.now = e.now.Add(23 * time.Hour)
	if stale, _ := e.lib.FeedStale(); stale {
		t.Fatal("stale within 24 h")
	}
	if _, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "b-id", Revision: "1"}), ImportOptions{}); err != nil {
		t.Fatalf("import within CP-34: %v", err)
	}
	// Past CP-34: blocked, with one alert.
	e.now = e.now.Add(2 * time.Hour)
	_, err := e.lib.Import(e.pkg(pkgtest.Spec{ID: "c-id", Revision: "1"}), ImportOptions{})
	if reason(err) != ReasonFeedStale {
		t.Fatalf("import with a stale feed: %v", err)
	}
	stale, why := e.lib.FeedStale()
	if !stale || !strings.Contains(why, "CP-34") {
		t.Fatalf("stale %v %q", stale, why)
	}
	alerts := 0
	for _, ev := range e.rec.Events() {
		if ev.ReasonCode == ReasonFeedStale && ev.Outcome == "alert" {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("%d stale-feed alerts", alerts)
	}
	if _, found := e.lib.Get("c-id", "1"); found {
		t.Fatal("a package was imported while the feed was stale")
	}
	// Readable again: the block lifts at the next check.
	if err := os.Chmod(feed, 0o700); err != nil {
		t.Fatal(err)
	}
	if stale, _ := e.lib.FeedStale(); stale {
		t.Fatal("still stale after a successful read")
	}
}
