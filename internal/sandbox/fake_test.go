package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox/probe"
)

// The test binary doubles as a fake `podman` (SMCP_FAKE_PODMAN=1) and as
// the backend server (SMCP_FAKE_SERVER=1, the probe MCP server). The fake
// Podman records each invocation under SMCP_FAKE_DIR, keeps a fake cgroup
// directory per container that tests edit to simulate limit events, and
// runs the server in place of the container with exec, so the container's
// main PID is the podman client's PID.
func TestMain(m *testing.M) {
	switch {
	case os.Getenv("SMCP_FAKE_SUDO") == "1":
		os.Exit(fakeSudo(os.Args[1:]))
	case os.Getenv("SMCP_FAKE_PODMAN") == "1":
		os.Exit(fakePodman(os.Args[1:]))
	case os.Getenv("SMCP_FAKE_SERVER") == "1":
		if os.Getenv("SMCP_FAKE_IGNORE_TERM") == "1" {
			signalIgnoreTerm()
		}
		os.Exit(probe.Main(os.Args[1:]))
	case os.Getenv("SMCP_FAKE_SERVER") == "ignore-eof":
		signalIgnoreTerm()
		if f := os.Getenv("SMCP_FAKE_EOF_FILE"); f != "" {
			// Record when stdin reaches EOF, then keep running.
			go func() {
				_, _ = io.Copy(io.Discard, os.Stdin)
				_ = os.WriteFile(f, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
			}()
		}
		time.Sleep(time.Hour)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func signalIgnoreTerm() { signal.Ignore(syscall.SIGTERM) }

// fakeRun is what the fake records for `podman run`.
type fakeRun struct {
	Argv     []string          `json:"argv"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	Rootfs   string            `json:"rootfs"`
	Command  []string          `json:"command"`
	Mounts   map[string]string `json:"mounts"`
	EnvNames []string          `json:"env_names"`
	EnvSet   map[string]bool   `json:"env_set"`
	Env      map[string]string `json:"env"`
}

func fakeDir() string { return os.Getenv("SMCP_FAKE_DIR") }

// fakeSudo stands in for `sudo -n -E -u USER -- PROGRAM ARGS`: it records
// its arguments and the identity variables it received, then executes
// PROGRAM with the environment it was given (as -E keeps it).
func fakeSudo(args []string) int {
	dir := fakeDir()
	i := slices.Index(args, "--")
	if i < 0 || i+1 >= len(args) {
		return 1
	}
	var ids []string
	for _, k := range []string{"HOME", "USER", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		ids = append(ids, k+"="+os.Getenv(k))
	}
	appendLine(filepath.Join(dir, "sudo.log"), strings.Join(args[:i], " ")+" | "+strings.Join(ids, " ")+" | "+strings.Join(args[i+1:], " "))
	_ = os.Unsetenv("SMCP_FAKE_SUDO")
	if err := syscall.Exec(args[i+1], args[i+1:], os.Environ()); err != nil { // #nosec G204 -- test fake
		fmt.Fprintln(os.Stderr, "fake sudo exec:", err)
		return 127
	}
	return 0
}

func appendLine(path, line string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}

func fakePodman(args []string) int {
	dir := fakeDir()
	appendLine(filepath.Join(dir, "calls.log"), strings.Join(args, " "))
	if len(args) == 0 {
		return 125
	}
	name := args[len(args)-1]
	switch args[0] {
	case "run":
		return fakeRunCmd(dir, args[1:])
	case "create":
		return fakeCreate(dir, args[1:])
	case "init":
		appendLine(filepath.Join(dir, name+".init"), "init")
		return 0
	case "start":
		return fakeStart(dir, name)
	case "unshare":
		return fakeUnshare(dir, args[1:])
	case "kill":
		sig := "KILL"
		for i, a := range args {
			if a == "--signal" && i+1 < len(args) {
				sig = args[i+1]
			}
		}
		appendLine(filepath.Join(dir, name+".kills"), sig+" "+strconv.FormatInt(time.Now().UnixNano(), 10))
		b, err := os.ReadFile(filepath.Join(dir, name+".pid"))
		if err != nil {
			return 125
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		s := syscall.SIGKILL
		if sig == "TERM" {
			s = syscall.SIGTERM
		}
		_ = syscall.Kill(pid, s)
		return 0
	case "inspect":
		if slices.Contains(args, "{{.State.Pid}}") {
			// The created (not started) container's first process.
			if _, err := os.Stat(filepath.Join(dir, name+".init")); err != nil {
				return 125
			}
			fmt.Println("4242")
			return 0
		}
		if slices.Contains(args, "{{.NetworkSettings.SandboxKey}}") {
			if _, err := os.Stat(filepath.Join(dir, name+".create.json")); err != nil {
				return 125
			}
			fmt.Println("/run/user/1000/netns/netns-" + name)
			return 0
		}
		b, err := os.ReadFile(filepath.Join(dir, name+".pid"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "no such container")
			return 125
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		oom := "false"
		if _, err := os.Stat(filepath.Join(dir, name+".oom")); err == nil {
			oom = "true"
		}
		if syscall.Kill(pid, 0) == nil && !isZombie(pid) {
			fmt.Printf("running|%d|/%s|0|%s\n", pid, name, oom)
		} else {
			code := "0"
			if b, err := os.ReadFile(filepath.Join(dir, name+".exit")); err == nil {
				code = strings.TrimSpace(string(b))
			}
			fmt.Printf("exited|0|/%s|%s|%s\n", name, code, oom)
		}
		return 0
	case "rm":
		appendLine(filepath.Join(dir, name+".rm"), "rm")
		return 0
	case "ps":
		if b, err := os.ReadFile(filepath.Join(dir, "ps.txt")); err == nil {
			os.Stdout.Write(b)
		}
		return 0
	case "events":
		// Follow events.jsonl until killed.
		path := filepath.Join(dir, "events.jsonl")
		var off int64
		for {
			if f, err := os.Open(path); err == nil {
				_, _ = f.Seek(off, 0)
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					line := sc.Text()
					off += int64(len(line)) + 1
					fmt.Println(line)
				}
				f.Close()
			}
			time.Sleep(20 * time.Millisecond)
		}
	case "info":
		if b, err := os.ReadFile(filepath.Join(dir, "info.json")); err == nil {
			os.Stdout.Write(b)
			return 0
		}
		return 125
	}
	return 125
}

// isZombie reports whether pid is a zombie (Linux procfs; elsewhere false).
func isZombie(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	f := strings.Fields(string(b))
	return len(f) > 2 && f[2] == "Z"
}

func fakeRunCmd(dir string, args []string) int {
	r := fakeRun{Argv: args, Mounts: map[string]string{}, EnvSet: map[string]bool{}, Env: map[string]string{}}
	rootfs := false
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			break
		}
		switch {
		case a == "--name" || a == "--label":
			if a == "--name" {
				r.Name = args[i+1]
			}
			i++
		case a == "--rootfs":
			rootfs = true
		case strings.HasPrefix(a, "--mount="):
			var src, dst string
			for _, kv := range strings.Split(strings.TrimPrefix(a, "--mount="), ",") {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "src":
					src = v
				case "dst":
					dst = v
				}
			}
			r.Mounts[dst] = src
		case strings.HasPrefix(a, "--env="):
			n := strings.TrimPrefix(a, "--env=")
			if k, v, ok := strings.Cut(n, "="); ok {
				// A value on the command line (egress addresses).
				_ = os.Setenv(k, v)
				n = k
			}
			r.EnvNames = append(r.EnvNames, n)
			r.Env[n], r.EnvSet[n] = os.LookupEnv(n)
		}
	}
	if i >= len(args) {
		return 125
	}
	if rootfs {
		r.Rootfs = args[i]
	} else {
		r.Image = args[i]
	}
	r.Command = args[i+1:]
	b, _ := json.MarshalIndent(r, "", " ")
	_ = os.WriteFile(filepath.Join(dir, r.Name+".run.json"), b, 0o600)
	cg := filepath.Join(dir, "cgroup", r.Name)
	_ = os.MkdirAll(cg, 0o700)
	pid := os.Getpid()
	files := map[string]string{
		"memory.current": "1048576", "memory.peak": "2097152", "pids.current": "1", "pids.peak": "1",
		"memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n", "pids.events": "max 0\n",
		"cpu.stat": "usage_usec 1234\nuser_usec 1000\nsystem_usec 234\n", "cgroup.procs": strconv.Itoa(pid) + "\n",
	}
	if v := os.Getenv("SMCP_FAKE_PIDS_MAX"); v != "" { // the pids limit was hit before the first sample
		files["pids.events"] = "max " + v + "\n"
	}
	for f, v := range files {
		_ = os.WriteFile(filepath.Join(cg, f), []byte(v), 0o600)
	}
	_ = os.WriteFile(filepath.Join(dir, r.Name+".pid"), []byte(strconv.Itoa(pid)), 0o600)
	if len(r.Command) == 0 {
		return 125
	}
	exe := r.Command[0]
	if src, ok := r.Mounts[exe]; ok {
		exe = src
	}
	var env []string
	for _, n := range r.EnvNames {
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+v)
		}
	}
	if err := syscall.Exec(exe, r.Command, env); err != nil { // #nosec G204 -- test fake
		fmt.Fprintln(os.Stderr, "fake podman exec:", err)
		return 127
	}
	return 0
}

// fakeCreated is what the fake keeps between `podman create` and
// `podman start`: the create arguments and the values of the environment
// variables they name (Podman stores them in the container).
type fakeCreated struct {
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
}

func fakeCreate(dir string, args []string) int {
	c := fakeCreated{Args: args, Env: map[string]string{}}
	name := ""
	for i, a := range args {
		if a == "--name" && i+1 < len(args) {
			name = args[i+1]
		}
		if n, ok := strings.CutPrefix(a, "--env="); ok && !strings.Contains(n, "=") {
			if v, ok := os.LookupEnv(n); ok {
				c.Env[n] = v
			}
		}
	}
	if name == "" {
		return 125
	}
	if _, err := os.Stat(filepath.Join(dir, "create.fail")); err == nil {
		fmt.Fprintln(os.Stderr, "Error: fake create failure")
		return 125
	}
	b, _ := json.Marshal(c)
	_ = os.WriteFile(filepath.Join(dir, name+".create.json"), b, 0o600)
	fmt.Println("0123456789ab")
	return 0
}

func fakeStart(dir, name string) int {
	b, err := os.ReadFile(filepath.Join(dir, name+".create.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: no such container")
		return 125
	}
	var c fakeCreated
	if err := json.Unmarshal(b, &c); err != nil {
		return 125
	}
	for k, v := range c.Env {
		_ = os.Setenv(k, v)
	}
	// The created container must not have been started by create itself.
	appendLine(filepath.Join(dir, name+".start"), "start")
	return fakeRunCmd(dir, c.Args)
}

// fakeUnshare records `podman unshare` invocations with their standard
// input. `... nft list table ...` prints back the last installed script.
func fakeUnshare(dir string, args []string) int {
	in, _ := io.ReadAll(os.Stdin)
	appendLine(filepath.Join(dir, "unshare.log"), strings.Join(args, " "))
	if _, err := os.Stat(filepath.Join(dir, "unshare.fail")); err == nil {
		fmt.Fprintln(os.Stderr, "Error: fake nft failure")
		return 1
	}
	if slices.Contains(args, "list") {
		b, err := os.ReadFile(filepath.Join(dir, "rules.nft"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: No such file or directory")
			return 1
		}
		os.Stdout.Write(b)
		return 0
	}
	_ = os.WriteFile(filepath.Join(dir, "rules.nft"), in, 0o600)
	return 0
}
