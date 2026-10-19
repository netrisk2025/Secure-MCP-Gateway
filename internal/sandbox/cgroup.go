package sandbox

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ReadCgroup samples the cgroup v2 directory dir and its descendants. A
// missing file reads as zero (memory.peak needs Linux 5.19 or later).
func ReadCgroup(dir string, now time.Time) (Sample, error) {
	if _, err := os.Stat(dir); err != nil {
		return Sample{}, err
	}
	s := Sample{At: now}
	s.MemoryCurrent = readInt(filepath.Join(dir, "memory.current"))
	s.MemoryPeak = readInt(filepath.Join(dir, "memory.peak"))
	s.Pids = int(readInt(filepath.Join(dir, "pids.current")))
	s.PidsPeak = int(readInt(filepath.Join(dir, "pids.peak")))
	mev := readKV(filepath.Join(dir, "memory.events"))
	s.OOMEvents, s.OOMKills = mev["oom"], mev["oom_kill"]
	s.PidsMaxEvents = readKV(filepath.Join(dir, "pids.events"))["max"]
	s.CPUUsageUsec = int64(readKV(filepath.Join(dir, "cpu.stat"))["usage_usec"]) // #nosec G115 -- microseconds fit in int64
	seen := map[int]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // a cgroup removed while walking is not an error
		}
		if !d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(p, "cgroup.procs")) // #nosec G304 -- cgroup file of a Gateway-managed container
		if err != nil {
			return nil //nolint:nilerr // as above
		}
		for _, f := range strings.Fields(string(b)) {
			if pid, err := strconv.Atoi(f); err == nil {
				seen[pid] = true
			}
		}
		return nil
	})
	for pid := range seen {
		s.Procs = append(s.Procs, pid)
	}
	sort.Ints(s.Procs)
	return s, nil
}

func readInt(p string) int64 {
	b, err := os.ReadFile(p) // #nosec G304 -- cgroup file
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func readKV(p string) map[string]uint64 {
	out := map[string]uint64{}
	b, err := os.ReadFile(p) // #nosec G304 -- cgroup file
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 {
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				out[f[0]] = v
			}
		}
	}
	return out
}

// procComm returns the command name of a host process, or "".
func procComm(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")) // #nosec G304 -- procfs
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
