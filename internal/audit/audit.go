// Package audit is the Audit & Evidence Service (E-21) slice: the mandatory
// security-event floor (FR-7.1, FR-7.2, SR-6.1-1) written to a tamper-evident
// JSON Lines journal of signed, hash-chained segments (FR-7.4), and the
// verifier behind `smcpctl journal verify` (FR-7.5).
//
// The journal is the evidence authority. Durability: Record appends an event
// to the open segment; Commit appends and returns only after the segment file
// has been fsynced, and concurrent commits share one fsync (group commit).
// Callers commit before any externally visible effect that the event
// justifies: the decision intent before a launch capability is issued, and
// the terminal event before a response is released. A write or fsync failure
// is sticky: every later Record and Commit fails, so callers fail closed.
//
// Crash recovery: Open seals a trailing unclosed segment left by a crash,
// truncating an incomplete last line, marks the footer as recovered with the
// number of bytes dropped, and records a journal_recovered event in the next
// segment. Verify reports recovered segments and a truncated tail.
//
// External anchor: each time a segment closes, the journal writes a signed
// anchor file outside the journal directory naming the last closed segment,
// its file hash and the total event count. Verify compares the journal with
// the anchor, so deleting trailing segments is detected. Replacing the anchor
// with an older signed copy is not detected locally; copying the anchor off
// the machine (evidence export, FR-7.14, export.go) closes that gap.
//
// Evidence-key rotation (FR-17.7, FR-17.8): RotateKey closes the open
// segment with a footer, signed by the outgoing key, whose next_key names
// the incoming key; Verify starts from the trust root (the key of segment
// 1) and follows these records.
//
// Graph and analytics persistence of events (E-26, E-27, E-29) are mirrors
// fed through Fanout observers and never gate a call.
package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	// Remote origin (FR-16.8): Channel is "remote" on every event of a
	// request received on the Remote Access listener; ClientAddress is the
	// tunnel-supplied caller address and ClientAddressSource says it is
	// "server-asserted" (a claim of the tunnel provider, not verified).
	Channel             string `json:"channel,omitempty"`
	ClientID            string `json:"client_id,omitempty"`
	ClientAddress       string `json:"client_address,omitempty"`
	ClientAddressSource string `json:"client_address_source,omitempty"`
	Detail              any    `json:"detail,omitempty"`
}

// Recorder is the interface every element uses to write evidence. Record
// appends; Commit appends and makes the event (and every event before it)
// durable before returning. Both return an error when the evidence store
// cannot accept the event, and the caller must then fail closed.
type Recorder interface {
	Record(Event) error
	Commit(Event) error
}

// Options bound a segment (FR-7.4 defaults: 1,000 events or 60 seconds).
type Options struct {
	MaxEvents int
	MaxAge    time.Duration
	Now       func() time.Time
	// AnchorPath is the signed anchor file; default "<dir>.anchor" next to
	// the journal directory.
	AnchorPath string
	// OpenSegment creates a new segment file (O_CREATE|O_EXCL, mode 0600).
	// Nil uses the operating system; crash-consistency tests substitute a
	// fault-injecting file layer (SR-6.2-1).
	OpenSegment func(path string) (SegmentFile, error)
}

// SegmentFile is the open segment the journal appends to.
type SegmentFile interface {
	io.Writer
	Sync() error
	Close() error
}

func (o *Options) defaults(dir string) {
	if o.MaxEvents <= 0 {
		o.MaxEvents = 1000
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 60 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.AnchorPath == "" {
		o.AnchorPath = DefaultAnchorPath(dir)
	}
	if o.OpenSegment == nil {
		o.OpenSegment = func(path string) (SegmentFile, error) {
			return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // journal segment under the state directory
		}
	}
}

// DefaultAnchorPath is the anchor file used when Options.AnchorPath is empty.
func DefaultAnchorPath(dir string) string {
	clean := filepath.Clean(dir)
	return filepath.Join(filepath.Dir(clean), filepath.Base(clean)+".anchor")
}

// Recovery describes a segment sealed by crash recovery.
type Recovery struct {
	Segment        int
	Events         int
	TruncatedBytes int64
}

// Journal writes events to hash-chained, signed segments in a directory.
type Journal struct {
	dir  string
	key  ed25519.PrivateKey
	opts Options

	mu        sync.Mutex
	fileMu    sync.RWMutex // read-held during fsync; write-held to close a segment file
	syncMu    sync.Mutex   // serializes fsyncs so concurrent commits share one
	seq       int          // number of the open segment
	file      SegmentFile
	hasher    hash.Hash // running hash of the open segment's bytes so far
	count     int       // events in the open segment
	total     int64     // events in the whole journal
	opened    time.Time
	prevHash  string // hex SHA-256 of the previous closed segment file
	closed    bool
	err       error // sticky failure
	written   uint64
	synced    atomic.Uint64
	recovered []Recovery
	ticker    *time.Ticker
	stopTick  chan struct{}
	firstAt   time.Time // time of the first event in the open segment
	nextKey   string    // set by RotateKey for the footer being written
	flushObs  atomic.Pointer[func(time.Duration)]
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
	Type           string `json:"type"`
	Segment        int    `json:"segment"`
	Events         int    `json:"events"`
	ClosedAt       string `json:"closed_at"`
	BodySHA256     string `json:"body_sha256"`
	Recovered      bool   `json:"recovered,omitempty"`
	TruncatedBytes int64  `json:"truncated_bytes,omitempty"`
	// NextKey is set on the last segment signed by an outgoing evidence key:
	// the hex Ed25519 public key that signs the following segments
	// (key-transition record, FR-17.7). It is covered by the signature.
	NextKey   string `json:"next_key,omitempty"`
	Signature string `json:"signature"` // base64 Ed25519 over signingBytes
}

func (f footer) signingBytes() []byte {
	f.Signature = ""
	b, _ := json.Marshal(f)
	return append([]byte("smcp-journal-footer-v1\n"), b...)
}

type anchor struct {
	Type          string `json:"type"`
	Segment       int    `json:"segment"`
	SegmentSHA256 string `json:"segment_sha256"`
	EventsTotal   int64  `json:"events_total"`
	Time          string `json:"time"`
	// Key is the hex public key that signed the anchor. Anchors written
	// before evidence-key rotation existed omit it.
	Key       string `json:"key,omitempty"`
	Signature string `json:"signature"`
}

func (a anchor) signingBytes() []byte {
	a.Signature = ""
	b, _ := json.Marshal(a)
	return append([]byte("smcp-journal-anchor-v1\n"), b...)
}

// Open creates or continues the journal in dir. It continues the chain from
// the last closed segment and seals a trailing unclosed segment left by a
// crash (see the package comment). It refuses to open a journal whose
// anchor names a segment that no longer exists, or that has an unclosed
// segment before the last one, because continuing would hide the damage.
func Open(dir string, key ed25519.PrivateKey, opts Options) (*Journal, error) {
	opts.defaults(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	j := &Journal{dir: dir, key: key, opts: opts}
	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	var last *footer
	for i, s := range segs {
		path := filepath.Join(dir, s.name)
		ft, err := readFooter(path)
		if err != nil {
			return nil, err
		}
		if ft == nil {
			if i != len(segs)-1 {
				return nil, fmt.Errorf("%s is not closed and is not the last segment; run `smcpctl journal verify` and investigate before starting", s.name)
			}
			// Recovery signs the crashed segment, so the key must be right first.
			if err := checkTransition(last, key); err != nil {
				return nil, err
			}
			rec, err := j.recoverSegment(s.seq, path)
			if err != nil {
				return nil, fmt.Errorf("recover %s: %w", s.name, err)
			}
			j.recovered = append(j.recovered, rec)
			continue
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		j.prevHash, j.seq = sum, s.seq
		j.total += int64(ft.Events)
		last = ft
	}
	pub := key.Public().(ed25519.PublicKey)
	transition := last != nil && last.NextKey != ""
	if len(j.recovered) == 0 {
		if err := checkTransition(last, key); err != nil {
			return nil, err
		}
	}
	if a, err := readAnchor(opts.AnchorPath, pub, transition); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if err == nil && a.Segment > j.seq {
		return nil, fmt.Errorf("anchor %s names segment %d but the journal ends at segment %d: trailing segments are missing; move the anchor aside only after investigating", opts.AnchorPath, a.Segment, j.seq)
	}
	if err := j.openSegment(); err != nil {
		return nil, err
	}
	for _, r := range j.recovered {
		if _, err := j.Append(Event{Class: "journal", Origin: "E-21", Outcome: "recovered", ReasonCode: "JOURNAL_RECOVERED",
			Detail: map[string]any{"segment": r.Segment, "events": r.Events, "truncated_bytes": r.TruncatedBytes}}, true); err != nil {
			return nil, err
		}
	}
	j.stopTick = make(chan struct{})
	j.ticker = time.NewTicker(tickInterval(opts.MaxAge))
	go j.ageLoop()
	return j, nil
}

// checkTransition refuses a key other than the one the last key-transition
// record hands the chain to; any other key would break verification.
func checkTransition(last *footer, key ed25519.PrivateKey) error {
	if last == nil || last.NextKey == "" {
		return nil
	}
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if last.NextKey != pub {
		return fmt.Errorf("the journal's last key-transition record names evidence key %s, but the configured key is %s: finish or undo the key rotation before starting", last.NextKey, pub)
	}
	return nil
}

// tickInterval is how often the age loop checks the open segment.
func tickInterval(maxAge time.Duration) time.Duration {
	return min(maxAge/4, time.Second)
}

// ageDue reports whether the open segment must close because of its age.
// A segment closes MaxAge after it opened, and also slightly before its
// first event is MaxAge old, so that the oldest unsigned event never
// exceeds MaxAge (the CP-27 stop threshold) because of tick granularity.
func (j *Journal) ageDue(now time.Time) bool {
	if j.count == 0 {
		return false
	}
	margin := 2 * tickInterval(j.opts.MaxAge)
	return now.Sub(j.opened) >= j.opts.MaxAge || now.Sub(j.firstAt) >= j.opts.MaxAge-margin
}

// Recovered lists the segments sealed by crash recovery during Open.
func (j *Journal) Recovered() []Recovery { return append([]Recovery(nil), j.recovered...) }

// recoverSegment truncates a crashed segment to its last complete valid line
// and seals it as recovered.
func (j *Journal) recoverSegment(seq int, path string) (Recovery, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Recovery{}, err
	}
	valid, events, headerOK := 0, 0, false
	for pos := 0; pos < len(b); {
		nl := bytes.IndexByte(b[pos:], '\n')
		if nl < 0 {
			break
		}
		line := b[pos : pos+nl]
		var probe struct {
			Type    string `json:"type"`
			Segment int    `json:"segment"`
		}
		if json.Unmarshal(line, &probe) != nil {
			break
		}
		if pos == 0 {
			if probe.Type != lineHeader || probe.Segment != seq {
				break
			}
			headerOK = true
		} else if probe.Type != lineEvent {
			break
		} else {
			events++
		}
		pos += nl + 1
		valid = pos
	}
	rec := Recovery{Segment: seq, Events: events, TruncatedBytes: int64(len(b) - valid)}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return rec, err
	}
	if err := f.Truncate(int64(valid)); err != nil {
		f.Close()
		return rec, err
	}
	if _, err := f.Seek(int64(valid), io.SeekStart); err != nil {
		f.Close()
		return rec, err
	}
	j.seq, j.file, j.hasher, j.count = seq, f, sha256.New(), events
	j.hasher.Write(b[:valid])
	if !headerOK {
		j.count = 0
		h := header{Type: lineHeader, Segment: seq, PrevSHA256: j.prevHash, OpenedAt: j.opts.Now().UTC().Format(time.RFC3339Nano)}
		if err := j.writeLine(h); err != nil {
			f.Close()
			return rec, err
		}
	}
	j.total += int64(j.count)
	if err := j.closeSegmentLocked(&rec); err != nil {
		return rec, err
	}
	return rec, nil
}

func (j *Journal) ageLoop() {
	for {
		select {
		case <-j.stopTick:
			return
		case <-j.ticker.C:
			j.mu.Lock()
			if !j.closed && j.err == nil && j.ageDue(j.opts.Now()) {
				if err := j.rotateLocked(); err != nil {
					j.fail(err)
				}
			}
			j.mu.Unlock()
		}
	}
}

func segmentName(seq int) string { return fmt.Sprintf("segment-%06d.jsonl", seq) }

func (j *Journal) openSegment() error {
	j.seq++
	path := filepath.Join(j.dir, segmentName(j.seq))
	f, err := j.opts.OpenSegment(path)
	if err != nil {
		return err
	}
	j.file = f
	j.hasher = sha256.New()
	j.count = 0
	j.opened = j.opts.Now()
	h := header{Type: lineHeader, Segment: j.seq, PrevSHA256: j.prevHash, OpenedAt: j.opened.UTC().Format(time.RFC3339Nano)}
	if err := j.writeLine(h); err != nil {
		return err
	}
	return syncDir(j.dir)
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
	j.hasher.Write(b)
	return nil
}

func (j *Journal) fail(err error) {
	if j.err == nil {
		j.err = fmt.Errorf("evidence journal failed: %w", err)
	}
}

// Err returns the sticky failure, or nil while the journal is healthy.
func (j *Journal) Err() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.err
}

// Record appends an event without waiting for fsync.
func (j *Journal) Record(ev Event) error { _, err := j.Append(ev, false); return err }

// Commit appends an event and returns after it is on stable storage.
func (j *Journal) Commit(ev Event) error { _, err := j.Append(ev, true); return err }

// Append writes one event, filling the event ID, time and policy status when
// empty, and returns the event as written. With durable set it returns only
// after an fsync that covers the event.
func (j *Journal) Append(ev Event, durable bool) (Event, error) {
	j.mu.Lock()
	if j.err != nil {
		j.mu.Unlock()
		return ev, j.err
	}
	if j.closed {
		j.mu.Unlock()
		return ev, errors.New("journal closed")
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
	if j.count == 0 {
		j.firstAt = j.opts.Now()
	}
	if err := j.writeLine(line); err != nil {
		j.fail(err)
		err = j.err
		j.mu.Unlock()
		return ev, err
	}
	j.count++
	j.total++
	j.written++
	gen := j.written
	if j.count >= j.opts.MaxEvents {
		if err := j.rotateLocked(); err != nil {
			j.fail(err)
			err = j.err
			j.mu.Unlock()
			return ev, err
		}
	}
	j.mu.Unlock()
	if durable {
		if err := j.syncTo(gen); err != nil {
			return ev, err
		}
	}
	return ev, nil
}

// Sync makes every event appended so far durable.
func (j *Journal) Sync() error {
	j.mu.Lock()
	gen := j.written
	j.mu.Unlock()
	return j.syncTo(gen)
}

// syncTo returns once generation gen is on stable storage. Callers that
// arrive while an fsync is running wait and are usually covered by the next
// one, which is the group commit.
func (j *Journal) syncTo(gen uint64) error {
	j.syncMu.Lock()
	defer j.syncMu.Unlock()
	if j.synced.Load() >= gen {
		return nil
	}
	j.mu.Lock()
	if j.err != nil {
		err := j.err
		j.mu.Unlock()
		return err
	}
	target, f := j.written, j.file
	j.fileMu.RLock()
	j.mu.Unlock()
	start := time.Now()
	err := f.Sync()
	j.fileMu.RUnlock()
	if obs := j.flushObs.Load(); obs != nil && err == nil {
		(*obs)(time.Since(start))
	}
	if err != nil {
		j.mu.Lock()
		j.fail(err)
		err = j.err
		j.mu.Unlock()
		return err
	}
	j.advanceSynced(target)
	return nil
}

func (j *Journal) advanceSynced(to uint64) {
	for {
		cur := j.synced.Load()
		if cur >= to || j.synced.CompareAndSwap(cur, to) {
			return
		}
	}
}

func (j *Journal) rotateLocked() error {
	if err := j.closeSegmentLocked(nil); err != nil {
		return err
	}
	return j.openSegment()
}

// SetFlushObserver registers a function called with the duration of every
// successful journal fsync (metrics, FR-17.5). Nil removes it.
func (j *Journal) SetFlushObserver(f func(time.Duration)) {
	if f == nil {
		j.flushObs.Store(nil)
		return
	}
	j.flushObs.Store(&f)
}

// Unsigned reports the number of events in the open segment, which are not
// yet covered by a segment signature, and the time of the oldest of them
// (zero when there are none). The Health & Safety Monitor compares them
// with the CP-27 stop thresholds.
func (j *Journal) Unsigned() (int, time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.count == 0 {
		return 0, time.Time{}
	}
	return j.count, j.firstAt
}

// Seal closes the open segment, signing every event appended so far, and
// opens the next one. Backups seal before copying the journal (SR-7.7-1).
func (j *Journal) Seal() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usableLocked(); err != nil {
		return err
	}
	if err := j.rotateLocked(); err != nil {
		j.fail(err)
		return j.err
	}
	return nil
}

func (j *Journal) usableLocked() error {
	if j.err != nil {
		return j.err
	}
	if j.closed {
		return errors.New("journal closed")
	}
	return nil
}

// RotateKey replaces the evidence-signing key (FR-17.7). It appends a
// key_rotated event naming both public keys, closes the open segment with
// a footer signed by the outgoing key whose next_key field names the
// incoming key (the key-transition record), rewrites the anchor under the
// incoming key and opens the next segment, which the incoming key signs.
// The caller persists the new key; until it does, a restart refuses to
// open the journal with the old key.
func (j *Journal) RotateKey(next ed25519.PrivateKey) error {
	if len(next) != ed25519.PrivateKeySize {
		return errors.New("new evidence key is not an Ed25519 private key")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usableLocked(); err != nil {
		return err
	}
	oldPub := hex.EncodeToString(j.key.Public().(ed25519.PublicKey))
	newPub := hex.EncodeToString(next.Public().(ed25519.PublicKey))
	if oldPub == newPub {
		return errors.New("new evidence key equals the current key")
	}
	ev := Event{EventID: ids.New(), Time: j.opts.Now().UTC().Format(time.RFC3339Nano), Class: "journal", Origin: "E-22", Outcome: "key_rotated",
		ReasonCode: "EVIDENCE_KEY_ROTATED", PolicyStatus: "not_evaluated", Detail: map[string]any{"previous_key": oldPub, "next_key": newPub}}
	if j.count == 0 {
		j.firstAt = j.opts.Now()
	}
	if err := j.writeLine(struct {
		Type string `json:"type"`
		Event
	}{lineEvent, ev}); err != nil {
		j.fail(err)
		return j.err
	}
	j.count++
	j.total++
	j.written++
	j.nextKey = newPub
	if err := j.closeSegmentLocked(nil); err != nil {
		j.fail(err)
		return j.err
	}
	j.key = next
	if err := j.writeAnchor(j.prevHash); err != nil {
		j.fail(err)
		return j.err
	}
	if err := j.openSegment(); err != nil {
		j.fail(err)
		return j.err
	}
	return nil
}

// PublicKey returns the key that signs the open segment.
func (j *Journal) PublicKey() ed25519.PublicKey {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.key.Public().(ed25519.PublicKey)
}

// closeSegmentLocked writes the signed footer, fsyncs and closes the
// segment, then writes the anchor.
func (j *Journal) closeSegmentLocked(rec *Recovery) error {
	ft := footer{Type: lineFooter, Segment: j.seq, Events: j.count, ClosedAt: j.opts.Now().UTC().Format(time.RFC3339Nano),
		BodySHA256: hex.EncodeToString(j.hasher.Sum(nil)), NextKey: j.nextKey}
	j.nextKey = ""
	if rec != nil {
		ft.Recovered, ft.TruncatedBytes = true, rec.TruncatedBytes
	}
	ft.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(j.key, ft.signingBytes()))
	if err := j.writeLine(ft); err != nil {
		return err
	}
	j.fileMu.Lock()
	err := j.file.Sync()
	if cerr := j.file.Close(); err == nil {
		err = cerr
	}
	j.fileMu.Unlock()
	if err != nil {
		return err
	}
	j.advanceSynced(j.written)
	sum, err := fileSHA256(filepath.Join(j.dir, segmentName(j.seq)))
	if err != nil {
		return err
	}
	j.prevHash = sum
	return j.writeAnchor(sum)
}

func (j *Journal) writeAnchor(segSHA string) error {
	a := anchor{Type: "anchor", Segment: j.seq, SegmentSHA256: segSHA, EventsTotal: j.total, Time: j.opts.Now().UTC().Format(time.RFC3339Nano),
		Key: hex.EncodeToString(j.key.Public().(ed25519.PublicKey))}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(j.key, a.signingBytes()))
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return writeFileAtomic(j.opts.AnchorPath, append(b, '\n'), 0o600)
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
	if j.stopTick != nil {
		close(j.stopTick)
		j.ticker.Stop()
	}
	if j.err != nil {
		j.file.Close()
		return j.err
	}
	return j.closeSegmentLocked(nil)
}

// Dir returns the journal directory.
func (j *Journal) Dir() string { return j.dir }

// AnchorPath returns the anchor file path.
func (j *Journal) AnchorPath() string { return j.opts.AnchorPath }

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
		if n, _ := fmt.Sscanf(e.Name(), "segment-%06d.jsonl", &seq); n == 1 && e.Name() == segmentName(seq) {
			out = append(out, segInfo{e.Name(), seq})
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].seq < out[k].seq })
	return out, nil
}

// readFooter returns the footer of a closed segment, or nil when the last
// line is not a footer.
func readFooter(path string) (*footer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const tail = 4096
	off := st.Size() - tail
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, err
	}
	if !bytes.HasSuffix(buf, []byte("\n")) {
		return nil, nil
	}
	buf = bytes.TrimRight(buf, "\n")
	last := buf[bytes.LastIndexByte(buf, '\n')+1:]
	var ft footer
	if json.Unmarshal(last, &ft) != nil || ft.Type != lineFooter {
		return nil, nil
	}
	return &ft, nil
}

// readAnchor reads and verifies the anchor under pub. With anyKey set, an
// anchor signed by the key it names is also accepted: Open uses it right
// after a key transition, when a crash may have left the anchor signed by
// the outgoing key.
func readAnchor(path string, pub ed25519.PublicKey, anyKey bool) (*anchor, error) {
	a, err := parseAnchor(path)
	if err != nil {
		return nil, err
	}
	if a.verify(pub) {
		return a, nil
	}
	if anyKey && a.Key != "" {
		if k, err := hex.DecodeString(a.Key); err == nil && a.verify(k) {
			return a, nil
		}
	}
	return nil, fmt.Errorf("anchor %s: signature invalid", path)
}

func parseAnchor(path string) (*anchor, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a anchor
	if err := json.Unmarshal(b, &a); err != nil || a.Type != "anchor" {
		return nil, fmt.Errorf("anchor %s is not an anchor record", path)
	}
	return &a, nil
}

func (a *anchor) verify(pub ed25519.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	return err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, a.signingBytes(), sig)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir makes a directory entry change durable. Some platforms refuse to
// fsync a directory; that is not an error.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	_ = d.Sync()
	return nil
}

// Report is the outcome of Verify. Fields other than Segments and Events
// are findings that do not break the chain but need an operator's
// attention.
type Report struct {
	Segments int
	Events   int
	Open     string // name of a trailing unclosed segment, if any
	// OpenEvents counts the events in the trailing unclosed segment
	// (included in Events). They are not signed yet, so the verifier
	// cannot detect changes to them or their removal.
	OpenEvents    int
	TruncatedTail bool     // the trailing open segment ends in an incomplete or invalid line
	Recovered     []string // segments sealed by crash recovery; events after the truncation point are lost
	AnchorSegment int      // segment named by the anchor; 0 when no segment has closed yet
	// Keys lists the hex evidence public keys in the order they signed,
	// starting with the trust root; one entry per key transition follows.
	Keys []string
	// Transitions lists the segments whose footer is a key-transition
	// record.
	Transitions []int
}

// CurrentKey is the key that signs segments after the last transition.
func (r Report) CurrentKey() string {
	if len(r.Keys) == 0 {
		return ""
	}
	return r.Keys[len(r.Keys)-1]
}

// Findings returns the report's warnings as sentences.
func (r Report) Findings() []string {
	var out []string
	if r.TruncatedTail {
		out = append(out, fmt.Sprintf("%s ends in an incomplete line (crash or truncation)", r.Open))
	}
	for _, s := range r.Recovered {
		out = append(out, fmt.Sprintf("%s was sealed by crash recovery; events after the crash point are missing", s))
	}
	return out
}

// VerifyOptions configure Verify.
type VerifyOptions struct {
	AnchorPath string // default DefaultAnchorPath(dir)
}

// Verify checks the journal in dir with the default anchor path.
func Verify(dir string, pub ed25519.PublicKey) (Report, error) {
	return VerifyWith(dir, pub, VerifyOptions{})
}

// VerifyWith checks every closed segment's body hash and footer signature,
// the hash chain between segments, the trailing open segment's lines and
// the anchor, returning the first failure (FR-7.5). A trailing unclosed
// segment is reported in Report.Open and is not a failure; any other
// unclosed segment is. A missing anchor when segments have closed, an anchor
// that names a missing segment, and an anchor that disagrees with the
// journal are failures.
//
// pub is the trust root: the key that signed segment 1. Key-transition
// records are followed (FR-17.8): a footer whose next_key is set, and whose
// signature verifies under the key in force, hands the chain to next_key,
// which must then sign every later segment until the next transition. The
// segment holding a transition must also contain the key_rotated event
// naming the same key. The anchor must be signed by the key in force for
// the segment it names or by that segment's next key.
func VerifyWith(dir string, pub ed25519.PublicKey, vo VerifyOptions) (Report, error) {
	var rep Report
	if len(pub) != ed25519.PublicKeySize {
		return rep, fmt.Errorf("trust root is not an Ed25519 public key (%d bytes)", len(pub))
	}
	rep.Keys = []string{hex.EncodeToString(pub)}
	segKey := map[int][2]ed25519.PublicKey{} // segment -> {signing key, next key}
	if vo.AnchorPath == "" {
		vo.AnchorPath = DefaultAnchorPath(dir)
	}
	segs, err := listSegments(dir)
	if err != nil {
		return rep, err
	}
	if len(segs) == 0 {
		return rep, errors.New("no segments")
	}
	type closedSeg struct {
		sha    string
		events int64
	}
	closed := map[int]closedSeg{}
	lastClosed := 0
	var cumulative int64
	prev := ""
	for i, s := range segs {
		if i > 0 && s.seq != segs[i-1].seq+1 {
			return rep, fmt.Errorf("%s: gap in segment numbering after %d", s.name, segs[i-1].seq)
		}
		if i == 0 && s.seq != 1 {
			return rep, fmt.Errorf("%s: journal does not start at segment 1", s.name)
		}
		path := filepath.Join(dir, s.name)
		b, err := os.ReadFile(path)
		if err != nil {
			return rep, err
		}
		lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
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
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ft); err != nil || ft.Type != lineFooter || !strings.HasSuffix(string(b), "\n") {
			if i != len(segs)-1 {
				return rep, fmt.Errorf("%s: not closed", s.name)
			}
			rep.Open = s.name
			rep.Segments++
			if !strings.HasSuffix(string(b), "\n") {
				rep.TruncatedTail = true
			}
			for _, l := range lines[1:] {
				var probe struct {
					Type string `json:"type"`
				}
				if json.Unmarshal([]byte(l), &probe) != nil || probe.Type != lineEvent {
					rep.TruncatedTail = true
					break
				}
				rep.Events++
				rep.OpenEvents++
			}
			break
		}
		body := strings.Join(lines[:len(lines)-1], "\n") + "\n"
		sum := sha256.Sum256([]byte(body))
		if hex.EncodeToString(sum[:]) != ft.BodySHA256 {
			return rep, fmt.Errorf("%s: body hash mismatch", s.name)
		}
		sig, err := base64.StdEncoding.DecodeString(ft.Signature)
		if err != nil || !ed25519.Verify(pub, ft.signingBytes(), sig) {
			return rep, fmt.Errorf("%s: signature invalid", s.name)
		}
		keys := [2]ed25519.PublicKey{pub, nil}
		if ft.NextKey != "" {
			next, err := hex.DecodeString(ft.NextKey)
			if err != nil || len(next) != ed25519.PublicKeySize {
				return rep, fmt.Errorf("%s: key-transition record names an invalid key", s.name)
			}
			if !hasTransitionEvent(lines[1:len(lines)-1], ft.NextKey) {
				return rep, fmt.Errorf("%s: key-transition footer without a matching key_rotated event", s.name)
			}
			keys[1] = next
			pub = next
			rep.Keys = append(rep.Keys, ft.NextKey)
			rep.Transitions = append(rep.Transitions, s.seq)
		}
		segKey[s.seq] = keys
		if ft.Segment != s.seq {
			return rep, fmt.Errorf("%s: footer names segment %d", s.name, ft.Segment)
		}
		if ft.Events != len(lines)-2 {
			return rep, fmt.Errorf("%s: footer counts %d events, file has %d", s.name, ft.Events, len(lines)-2)
		}
		if ft.Recovered {
			rep.Recovered = append(rep.Recovered, s.name)
		}
		rep.Segments++
		rep.Events += ft.Events
		cumulative += int64(ft.Events)
		full := sha256.Sum256(b)
		prev = hex.EncodeToString(full[:])
		closed[s.seq] = closedSeg{prev, cumulative}
		lastClosed = s.seq
	}
	a, err := parseAnchor(vo.AnchorPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if lastClosed > 0 {
			return rep, fmt.Errorf("anchor %s is missing", vo.AnchorPath)
		}
		return rep, nil
	case err != nil:
		return rep, err
	}
	if !anchorSigned(a, segKey, rep.Keys) {
		return rep, fmt.Errorf("anchor %s: signature invalid", vo.AnchorPath)
	}
	rep.AnchorSegment = a.Segment
	cs, ok := closed[a.Segment]
	switch {
	case !ok || a.Segment > lastClosed:
		return rep, fmt.Errorf("anchor names segment %d but the journal's last closed segment is %d: segments were removed", a.Segment, lastClosed)
	case a.Segment < lastClosed:
		return rep, fmt.Errorf("anchor names segment %d but segments up to %d are closed: the anchor was replaced or not updated", a.Segment, lastClosed)
	case cs.sha != a.SegmentSHA256:
		return rep, fmt.Errorf("anchor hash for segment %d does not match the segment file", a.Segment)
	case cs.events != a.EventsTotal:
		return rep, fmt.Errorf("anchor counts %d events through segment %d, journal has %d", a.EventsTotal, a.Segment, cs.events)
	}
	return rep, nil
}

// anchorSigned checks the anchor's signature: under the key in force for the
// segment it names (or that segment's next key), or, when the segment is
// not in the journal, under any key of the chain so that the missing
// segments are reported rather than a signature failure.
func anchorSigned(a *anchor, segKey map[int][2]ed25519.PublicKey, chain []string) bool {
	if k, ok := segKey[a.Segment]; ok {
		return a.verify(k[0]) || (k[1] != nil && a.verify(k[1]))
	}
	for _, h := range chain {
		if k, err := hex.DecodeString(h); err == nil && a.verify(k) {
			return true
		}
	}
	return false
}

// hasTransitionEvent reports whether the segment's event lines contain the
// key_rotated event that names next.
func hasTransitionEvent(lines []string, next string) bool {
	for i := len(lines) - 1; i >= 0; i-- {
		var line struct {
			Type string `json:"type"`
			Event
		}
		if json.Unmarshal([]byte(lines[i]), &line) != nil || line.Type != lineEvent || line.Outcome != "key_rotated" {
			continue
		}
		if d, ok := line.Detail.(map[string]any); ok && d["next_key"] == next {
			return true
		}
	}
	return false
}

// ReadEvents returns every event of the journal in order, including events in
// a trailing open segment. It does not verify; call Verify first when the
// result is used as evidence.
func ReadEvents(dir string) ([]Event, error) {
	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, s := range segs {
		f, err := os.Open(filepath.Join(dir, s.name))
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<26)
		for sc.Scan() {
			var line struct {
				Type string `json:"type"`
				Event
			}
			if json.Unmarshal(sc.Bytes(), &line) == nil && line.Type == lineEvent {
				out = append(out, line.Event)
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
