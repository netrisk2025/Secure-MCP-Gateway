package library

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// MaxFeedStaleness is CP-34: the longest the revocation feed may go
// without a successful read before new imports are blocked (SR-3-4).
const MaxFeedStaleness = 24 * time.Hour

// ReasonFeedStale refuses an import while the revocation feed is stale.
const ReasonFeedStale = "REVOCATION_FEED_STALE"

// readFeed reads the revocation feed (the library's revocation directory
// and the trust anchors that verify its entries) and records the time of
// a successful read. An absent revocation directory is an empty feed. The
// caller holds l.mu.
func (l *Library) readFeed() ([]os.DirEntry, *packaging.Anchors, error) {
	entries, err := os.ReadDir(filepath.Join(l.dir, packaging.RevocationsDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("revocation feed unreadable: %w", err)
	}
	anchors, err := packaging.LoadAnchors(l.stateDir)
	if err != nil {
		return nil, nil, fmt.Errorf("trust anchors unreadable: %w", err)
	}
	l.feedReadAt = l.now()
	l.feedAlerted = false
	return entries, anchors, nil
}

// feedStaleLocked reports whether the feed has not been read successfully
// within CP-34, trying a read first. It records the stale-feed alert once
// per stale period. The caller holds l.mu.
func (l *Library) feedStaleLocked() (bool, string) {
	_, _, rerr := l.readFeed()
	age := l.now().Sub(l.feedReadAt)
	if age <= MaxFeedStaleness {
		return false, ""
	}
	why := fmt.Sprintf("the revocation feed was last read %s ago, at %s (CP-34 allows 24 h)", age.Round(time.Minute), l.feedReadAt.UTC().Format(time.RFC3339))
	if rerr != nil {
		why += ": " + rerr.Error()
	}
	if !l.feedAlerted {
		l.feedAlerted = true
		l.log.Error("revocation feed stale; new imports are blocked", "last_read", l.feedReadAt, "err", rerr)
		_ = l.evidence(audit.Event{Origin: "E-13", Outcome: "alert", ReasonCode: ReasonFeedStale, Detail: map[string]any{"last_read": l.feedReadAt.UTC(), "error": fmt.Sprint(rerr)}})
	}
	return true, why
}

// FeedStale reports whether the revocation feed is stale (SR-3-4): health
// shows the alert while it is.
func (l *Library) FeedStale() (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.feedStaleLocked()
}
