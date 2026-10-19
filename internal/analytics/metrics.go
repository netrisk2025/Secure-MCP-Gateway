package analytics

import (
	"encoding/json"
	"runtime"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
)

// MetricSources supply the meta-metrics measured outside the service:
// the journal's unsigned events (P-247) and the graph engine's memory
// (P-244). Either may be nil; its parameter is then null.
type MetricSources struct {
	SigningLag  func() (unsigned int, oldest time.Time)
	GraphMemory func() any
}

// SetMetricSources sets the outside sources of the meta-metrics; cmd/smcpd
// calls it once the journal and the graph mirror exist.
func (s *Service) SetMetricSources(m MetricSources) {
	if s.Disabled() {
		return
	}
	s.mu.Lock()
	s.sources = m
	s.mu.Unlock()
}

// MetricsRow builds one system meta-metrics sample (P-240 to P-250,
// FR-10.9). P-244 and P-247 come from SetMetricSources and are null
// without them.
func (s *Service) MetricsRow() obsstore.Row {
	now := s.now()
	st := s.Collector.Stats()
	cpu := processCPU()
	s.mu.Lock()
	iv := now.Sub(s.lastTick).Seconds()
	if iv <= 0 {
		iv = s.S.MetricsInterval.Seconds()
	}
	var rows int64
	if s.writer != nil {
		rows = s.writer.written.Load()
	}
	dAssem := st.Assembled - s.lastAssem
	dRows := rows - s.lastRows
	dCPU := cpu - s.lastCPU
	s.lastTick, s.lastAssem, s.lastRows, s.lastCPU = now, st.Assembled, rows, cpu
	src := s.sources
	s.mu.Unlock()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	queues := map[string]any{"collector": st.QueueDepth, "collector_capacity": st.QueueCap, "pending_calls": st.Pending}
	if s.writer != nil {
		queues["store_writer"] = len(s.writer.ch)
		queues["store_writer_capacity"] = cap(s.writer.ch)
		queues["store_writer_pressure_events"] = s.writer.pressure.Load()
	}
	snapBytes := 0
	if snap := s.Scorer.Snapshot(); snap != nil {
		if b, err := json.Marshal(snap); err == nil {
			snapBytes = len(b)
		}
	}
	row := obsstore.Row{"ts": now, "interval_seconds": iv,
		"throughput":              float64(dAssem) / iv,
		"concurrent_calls":        int64(st.Pending),
		"queue_depths":            queues,
		"rss_per_element":         map[string]any{"smcpd": map[string]any{"go_sys_bytes": ms.Sys, "go_heap_inuse_bytes": ms.HeapInuse}},
		"observation_ingest_rate": float64(dRows) / iv,
		"capture_drops":           s.Drops(),
		"baseline_cache_size":     int64(snapBytes),
		"cpu_per_element":         map[string]any{"smcpd": 100 * dCPU.Seconds() / iv},
	}
	if src.SigningLag != nil {
		n, oldest := src.SigningLag()
		lag := map[string]any{"unsigned_events": int64(n), "oldest_unsigned_age_seconds": 0.0}
		if n > 0 && !oldest.IsZero() {
			lag["oldest_unsigned_age_seconds"] = now.Sub(oldest).Seconds()
		}
		row["journal_signing_lag"] = lag
	}
	if src.GraphMemory != nil {
		if gm := src.GraphMemory(); gm != nil {
			row["graph_memory"] = gm
		}
	}
	if s.Store != nil {
		if ss, err := s.Store.Stats(); err == nil {
			row["store_sizes"] = map[string]any{"observation_store_bytes": ss.Bytes, "observation_store_files": ss.Files, "backend": ss.Backend}
		}
	}
	return row
}

func (s *Service) sampleMetrics() {
	row := s.MetricsRow()
	if s.writer != nil {
		s.writer.offer("metrics", row)
	}
}
