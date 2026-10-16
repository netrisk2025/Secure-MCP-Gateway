// Package audit is the Audit & Evidence Service (E-21) slice: the mandatory
// security-event floor (FR-7.1, FR-7.2, SR-6.1-1) written to a tamper-evident
// JSON Lines journal of signed, hash-chained segments (FR-7.4), and the
// verifier behind `smcpctl journal verify` (FR-7.5).
//
// The graph persistence of events (D-05) is not part of this slice; the
// journal is the only store.
package audit

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// Phase is a call phase of FR-7.2.
type Phase string

const (
	PhaseRequested     Phase = "requested"
	PhaseDenied        Phase = "denied"
	PhaseAuthorized    Phase = "authorized"
	PhaseDispatched    Phase = "dispatched"
	PhaseCompleted     Phase = "completed"
	PhaseFailed        Phase = "failed"
	PhaseIndeterminate Phase = "indeterminate"
	PhaseFiltered      Phase = "filtered"
	PhaseDelivered     Phase = "delivered"
	PhaseWithheld      Phase = "withheld"
)

// Event carries the FR-7.1 fields. Empty strings are omitted on the wire.
type Event struct {
	EventID        string `json:"event_id"`
	Time           string `json:"time"`
	Class          string `json:"class"`
	Phase          Phase  `json:"phase,omitempty"`
	Origin         string `json:"origin"` // element ID, e.g. E-08
	CorrelationID  string `json:"correlation_id,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	DecisionID     string `json:"decision_id,omitempty"`
	PolicyRevision string `json:"policy_revision,omitempty"`
	ServerRevision string `json:"server_revision,omitempty"`
	ToolRevision   string `json:"tool_revision,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
	ReasonCode     string `json:"reason_code,omitempty"`
	PolicyStatus   string `json:"policy_status"` // evaluated, not_evaluated, unavailable (SR-6.19-1)
	Detail         any    `json:"detail,omitempty"`
}

// Options bound a segment (FR-7.4 defaults: 1,000 events or 60 seconds).
type Options struct {
	MaxEvents int
	MaxAge    time.Duration
	Now       func() time.Time
}

// Journal writes events to hash-chained, signed segments in a directory.
type Journal struct {
	dir  string
	key  ed25519.PrivateKey
	opts Options

	mu       sync.Mutex
	seq      int // number of the open segment
	file     *os.File
	hash     [32]byte // running hash of the open segment's bytes so far
	hasher   hashWriter
	count    int
	opened   time.Time
	prevHash string // hex sha256 of the previous closed segment file
	closed   bool
	ticker   *time.Ticker
	stopTick chan struct{}
}

type hashWriter struct {
	h interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
}

const (
	lineHeader = "header"
	lineEvent  = "event"
	lineFooter = "footer"
)

type header struct {
	Type       string `json:"type"`
	Segment    int    `json:"segment"`
	PrevSHA256 string `json:"prev_sha256"`
	OpenedAt   string `json:"opened_at"`
}

type footer struct {
	Type       string `json:"type"`
	Segment    int    `json:"segment"`
	Events     int    `json:"events"`
	ClosedAt   string `json:"closed_at"`
	BodySHA256 string `json:"body_sha256"`
	Signature  string `json:"signature"` // base64 Ed25519 over body_sha256 bytes
}

// Open creates or continues the journal in dir. It finds the last closed
// segment to continue the chain; an unclosed segment left by a crash is
// renamed aside and reported, never silently extended.
func Open(dir string, key ed25519.PrivateKey, opts Options) (*Journal, error) {
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = 1000
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = 60 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	j := &Journal{dir: dir, key: key, opts: opts}
	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	for _, s := range segs {
		closed, err := isClosed(filepath.Join(dir, s.name))
		if err != nil {
			return nil, err
		}
		if !closed {
			aside := filepath.Join(dir, s.name+".unclosed-"+opts.Now().UTC().Format("20060102T150405Z"))
			if err := os.Rename(filepath.Join(dir, s.name), aside); err != nil {
				return nil, err
			}
			continue
		}
		sum, err := fileSHA256(filepath.Join(dir, s.name))
		if err != nil {
			return nil, err
		}
		j.prevHash = sum
		j.seq = s.seq
	}
	if err := j.openSegment(); err != nil {
		return nil, err
	}
	j.stopTick = make(chan struct{})
	j.ticker = time.NewTicker(opts.MaxAge / 4)
	go j.ageLoop()
	return j, nil
}

func (j *Journal) ageLoop() {
	for {
		select {
		case <-j.stopTick:
			return
		case <-j.ticker.C:
			j.mu.Lock()
			if !j.closed && j.count > 0 && j.opts.Now().Sub(j.opened) >= j.opts.MaxAge {
				_ = j.rotateLocked()
			}
			j.mu.Unlock()
		}
	}
}

func segmentName(seq int) string { return fmt.Sprintf("segment-%06d.jsonl", seq) }

func (j *Journal) openSegment() error {
	j.seq++
	path := filepath.Join(j.dir, segmentName(j.seq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	j.file = f
	j.hasher = hashWriter{h: sha256.New()}
	j.count = 0
	j.opened = j.opts.Now()
	h := header{Type: lineHeader, Segment: j.seq, PrevSHA256: j.prevHash, OpenedAt: j.opened.UTC().Format(time.RFC3339Nano)}
	return j.writeLine(h)
}

func (j *Journal) writeLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := j.file.Write(b); err != nil {
		return err
	}
	_, _ = j.hasher.h.Write(b)
	return nil
}

// Record signs nothing itself; it appends the event to the open segment and
// rotates when the segment reaches its bounds. The event ID and time are
// filled in when empty.
func (j *Journal) Record(ev Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return errors.New("journal closed")
	}
	if ev.EventID == "" {
		ev.EventID = ids.New()
	}
	if ev.Time == "" {
		ev.Time = j.opts.Now().UTC().Format(time.RFC3339Nano)
	}
	if ev.PolicyStatus == "" {
		ev.PolicyStatus = "not_evaluated"
	}
	line := struct {
		Type string `json:"type"`
		Event
	}{lineEvent, ev}
	if err := j.writeLine(line); err != nil {
		return err
	}
	j.count++
	if j.count >= j.opts.MaxEvents {
		return j.rotateLocked()
	}
	return nil
}

func (j *Journal) rotateLocked() error {
	if err := j.closeSegmentLocked(); err != nil {
		return err
	}
	return j.openSegment()
}

func (j *Journal) closeSegmentLocked() error {
	body := hex.EncodeToString(j.hasher.h.Sum(nil))
	sig := ed25519.Sign(j.key, []byte(body))
	ft := footer{Type: lineFooter, Segment: j.seq, Events: j.count, ClosedAt: j.opts.Now().UTC().Format(time.RFC3339Nano),
		BodySHA256: body, Signature: base64.StdEncoding.EncodeToString(sig)}
	if err := j.writeLine(ft); err != nil {
		return err
	}
	if err := j.file.Sync(); err != nil {
		return err
	}
	if err := j.file.Close(); err != nil {
		return err
	}
	sum, err := fileSHA256(filepath.Join(j.dir, segmentName(j.seq)))
	if err != nil {
		return err
	}
	j.prevHash = sum
	return nil
}

// Close seals the open segment. An empty open segment is still sealed so the
// chain has no gap.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	close(j.stopTick)
	j.ticker.Stop()
	return j.closeSegmentLocked()
}

// Segments returns the segment numbers present in the journal directory.
func (j *Journal) Dir() string { return j.dir }

type segInfo struct {
	name string
	seq  int
}

func listSegments(dir string) ([]segInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []segInfo
	for _, e := range entries {
		var seq int
		if n, _ := fmt.Sscanf(e.Name(), "segment-%06d.jsonl", &seq); n == 1 && strings.HasSuffix(e.Name(), ".jsonl") {
			out = append(out, segInfo{e.Name(), seq})
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].seq < out[k].seq })
	return out, nil
}

func isClosed(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	last := ""
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			last = t
		}
	}
	return strings.Contains(last, `"type":"footer"`), sc.Err()
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// Report is the outcome of Verify.
type Report struct {
	Segments int
	Events   int
	Open     string // name of a trailing unclosed segment, if any
}

// Verify checks every closed segment's body hash and signature and the hash
// chain between segments, returning the first failure (FR-7.5). A trailing
// unclosed segment is reported in Report.Open and is not a failure; any other
// unclosed segment is.
func Verify(dir string, pub ed25519.PublicKey) (Report, error) {
	var rep Report
	segs, err := listSegments(dir)
	if err != nil {
		return rep, err
	}
	if len(segs) == 0 {
		return rep, errors.New("no segments")
	}
	prev := ""
	for i, s := range segs {
		if i > 0 && s.seq != segs[i-1].seq+1 {
			return rep, fmt.Errorf("%s: gap in segment numbering after %d", s.name, segs[i-1].seq)
		}
		path := filepath.Join(dir, s.name)
		b, err := os.ReadFile(path)
		if err != nil {
			return rep, err
		}
		lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(lines) < 1 {
			return rep, fmt.Errorf("%s: empty", s.name)
		}
		var h header
		if err := json.Unmarshal([]byte(lines[0]), &h); err != nil || h.Type != lineHeader {
			return rep, fmt.Errorf("%s: missing header", s.name)
		}
		if h.Segment != s.seq {
			return rep, fmt.Errorf("%s: header names segment %d", s.name, h.Segment)
		}
		if h.PrevSHA256 != prev {
			return rep, fmt.Errorf("%s: chain broken (header prev_sha256 %q, previous segment %q)", s.name, h.PrevSHA256, prev)
		}
		var ft footer
		lastLine := lines[len(lines)-1]
		if err := json.Unmarshal([]byte(lastLine), &ft); err != nil || ft.Type != lineFooter {
			if i == len(segs)-1 {
				rep.Open = s.name
				rep.Segments++
				rep.Events += len(lines) - 1
				return rep, nil
			}
			return rep, fmt.Errorf("%s: not closed", s.name)
		}
		body := strings.Join(lines[:len(lines)-1], "\n") + "\n"
		sum := sha256.Sum256([]byte(body))
		if hex.EncodeToString(sum[:]) != ft.BodySHA256 {
			return rep, fmt.Errorf("%s: body hash mismatch", s.name)
		}
		sig, err := base64.StdEncoding.DecodeString(ft.Signature)
		if err != nil || !ed25519.Verify(pub, []byte(ft.BodySHA256), sig) {
			return rep, fmt.Errorf("%s: signature invalid", s.name)
		}
		if ft.Events != len(lines)-2 {
			return rep, fmt.Errorf("%s: footer counts %d events, file has %d", s.name, ft.Events, len(lines)-2)
		}
		rep.Segments++
		rep.Events += ft.Events
		full := sha256.Sum256(b)
		prev = hex.EncodeToString(full[:])
	}
	return rep, nil
}
