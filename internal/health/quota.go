package health

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// QuotaWarnPercent is the level at which a storage quota warns (FR-9.15,
// CP-26).
const QuotaWarnPercent = 80

// CauseStorageQuota prefixes the non-critical cause a store reports while
// it is at or above QuotaWarnPercent of its quota ("storage_quota_journal").
const CauseStorageQuota = "storage_quota_"

// Quota tracks the size of one store's directory against its quota.
type Quota struct {
	Name  string // "journal", "observation_store"
	Dir   string
	Limit int64 // bytes; 0 disables the quota
	// Interval between directory walks (default one minute).
	Interval time.Duration

	mu    sync.Mutex
	bytes int64
	at    time.Time
	err   error
}

// QuotaLevel is one store's quota level as reported to the Health & Safety
// Monitor.
type QuotaLevel struct {
	Name       string    `json:"name"`
	Bytes      int64     `json:"bytes"`
	Limit      int64     `json:"limit_bytes"`
	Percent    float64   `json:"percent"`
	Warning    bool      `json:"warning"`
	MeasuredAt time.Time `json:"measured_at"`
	Error      string    `json:"error,omitempty"`
}

// Measure walks the directory now and returns the level.
func (q *Quota) Measure() QuotaLevel {
	var size int64
	err := filepath.WalkDir(q.Dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				size += info.Size()
			}
		}
		return nil
	})
	q.mu.Lock()
	q.bytes, q.at, q.err = size, time.Now(), err
	q.mu.Unlock()
	return q.Level()
}

// Level returns the last measured level.
func (q *Quota) Level() QuotaLevel {
	q.mu.Lock()
	defer q.mu.Unlock()
	l := QuotaLevel{Name: q.Name, Bytes: q.bytes, Limit: q.Limit, MeasuredAt: q.at.UTC()}
	if q.Limit > 0 {
		l.Percent = float64(q.bytes) * 100 / float64(q.Limit)
		l.Warning = l.Percent >= QuotaWarnPercent
	}
	if q.err != nil {
		l.Error = q.err.Error()
	}
	return l
}

// Check measures the store at most once per Interval and reports
// storage_quota_<name> while it is at or above 80% of its quota.
func (q *Quota) Check() Check {
	iv := q.Interval
	if iv <= 0 {
		iv = time.Minute
	}
	return Every(iv, func(time.Time) []Cause {
		l := q.Measure()
		if !l.Warning {
			return nil
		}
		return []Cause{{Name: CauseStorageQuota + q.Name,
			Detail: fmt.Sprintf("%s uses %d MiB, %.0f%% of its %d MiB quota", q.Name, l.Bytes>>20, l.Percent, l.Limit>>20)}}
	})
}

// AddQuota registers a store's quota: its check, and its level in every
// report (FR-9.15).
func (m *Monitor) AddQuota(q *Quota) {
	if q == nil {
		return
	}
	m.Register("quota_"+q.Name, q.Check())
	m.mu.Lock()
	m.quotas = append(m.quotas, q)
	m.mu.Unlock()
}

// Quotas returns the level of every registered quota, by name.
func (m *Monitor) Quotas() []QuotaLevel {
	m.mu.Lock()
	qs := append([]*Quota(nil), m.quotas...)
	m.mu.Unlock()
	out := make([]QuotaLevel, 0, len(qs))
	for _, q := range qs {
		out = append(out, q.Level())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
