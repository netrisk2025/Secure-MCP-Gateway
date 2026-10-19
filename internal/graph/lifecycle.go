package graph

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Finding is one result of the engine configuration check.
type Finding struct {
	Setting string `json:"setting"`
	Value   string `json:"value"`
	Want    string `json:"want"`
	Reason  string `json:"reason"`
}

// checkedSettings are read from the engine at connect time.
var checkedSettings = []string{
	"server.http.enabled", "server.https.enabled", "dbms.usage_report.enabled",
	"dbms.security.allow_csv_import_from_file_urls", "dbms.security.procedures.unrestricted",
	"server.bolt.listen_address", "server.default_listen_address",
	"server.memory.heap.max_size", "server.memory.pagecache.size",
}

// Budget is the CP-33 memory budget of the graph engine (E-28).
type Budget struct {
	HeapBytes      int64 `json:"heap_bytes"`
	PageCacheBytes int64 `json:"page_cache_bytes"`
}

// CP-33 defaults.
const (
	DefaultHeapBytes      = 1 << 30
	DefaultPageCacheBytes = 1 << 30
)

// CheckSettings compares the engine's effective settings with SR-7.4-1
// (connectors, usage reporting, CSV file URLs, unrestricted procedures),
// SR-4.2-1 (loopback listener) and the memory budget (FR-9.10). A missing
// setting is reported, since it means the default is in effect.
func CheckSettings(s map[string]string, b Budget) []Finding {
	var out []Finding
	want := func(name, value, reason string) {
		got, ok := s[name]
		if !ok {
			got = "(unset)"
		}
		if !strings.EqualFold(got, value) {
			out = append(out, Finding{Setting: name, Value: got, Want: value, Reason: reason})
		}
	}
	want("server.http.enabled", "false", "SR-7.4-1: HTTP connector disabled")
	want("server.https.enabled", "false", "SR-7.4-1: HTTPS connector disabled")
	want("dbms.usage_report.enabled", "false", "SR-7.4-1: no usage reporting")
	want("dbms.security.allow_csv_import_from_file_urls", "false", "SR-7.4-1: file-URL CSV import disabled")
	want("dbms.security.procedures.unrestricted", "", "SR-7.4-1: no unrestricted procedures")
	for _, name := range []string{"server.bolt.listen_address", "server.default_listen_address"} {
		v, ok := s[name]
		if !ok {
			continue
		}
		host := v
		if h, _, err := net.SplitHostPort(v); err == nil {
			host = h
		}
		if host != "" && !isLoopback(host) {
			out = append(out, Finding{Setting: name, Value: v, Want: "127.0.0.1", Reason: "SR-4.2-1: listen on loopback only"})
		}
	}
	size := func(name string, budget int64, what string) {
		v, ok := s[name]
		if !ok || budget <= 0 {
			return
		}
		n, err := ParseSize(v)
		if err != nil || n == 0 || n > budget {
			out = append(out, Finding{Setting: name, Value: v, Want: "<= " + FormatSize(budget), Reason: "FR-9.10: " + what + " within the CP-33 budget"})
		}
	}
	size("server.memory.heap.max_size", b.HeapBytes, "heap")
	size("server.memory.pagecache.size", b.PageCacheBytes, "page cache")
	return out
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// ParseSize parses Neo4j memory sizes such as "512.00MiB", "1g" or
// "1073741824". An empty value is 0.
func ParseSize(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	i := strings.IndexFunc(v, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	num, unit := v, ""
	if i >= 0 {
		num, unit = v[:i], strings.ToLower(strings.TrimSpace(v[i:]))
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", v, err)
	}
	mult := map[string]float64{"": 1, "b": 1, "k": 1 << 10, "kb": 1 << 10, "kib": 1 << 10, "m": 1 << 20, "mb": 1 << 20, "mib": 1 << 20,
		"g": 1 << 30, "gb": 1 << 30, "gib": 1 << 30, "t": 1 << 40, "tb": 1 << 40, "tib": 1 << 40}[unit]
	if mult == 0 {
		return 0, fmt.Errorf("size %q: unknown unit", v)
	}
	return int64(f * mult), nil
}

// FormatSize formats a byte count the way neo4j.conf accepts it.
func FormatSize(n int64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%dg", n>>30)
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dm", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dk", n>>10)
	}
	return strconv.FormatInt(n, 10)
}

// EngineConfig returns the neo4j.conf lines that apply the hardening of
// SR-7.4-1 and SR-4.2-1 and the memory budget of FR-9.10. smcpctl graph
// config prints it; the operator installs it and restarts the engine.
func EngineConfig(b Budget, boltPort int) string {
	if boltPort == 0 {
		boltPort = 7687
	}
	return fmt.Sprintf(`# Secure MCP Gateway graph engine settings (SR-4.2-1, SR-7.4-1, FR-9.10).
server.default_listen_address=127.0.0.1
server.bolt.enabled=true
server.bolt.listen_address=127.0.0.1:%d
server.http.enabled=false
server.https.enabled=false
dbms.usage_report.enabled=false
dbms.security.allow_csv_import_from_file_urls=false
dbms.security.procedures.unrestricted=
server.memory.heap.initial_size=%s
server.memory.heap.max_size=%s
server.memory.pagecache.size=%s
`, boltPort, FormatSize(b.HeapBytes), FormatSize(b.HeapBytes), FormatSize(b.PageCacheBytes))
}
