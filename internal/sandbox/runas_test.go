package sandbox

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/posixacl"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func fakeSrvUser(name string) (*user.User, error) {
	if name != "smcp-srv" {
		return nil, user.UnknownUserError(name)
	}
	return &user.User{Username: name, Uid: "4321", Gid: "4322", HomeDir: "/var/lib/smcp/home/smcp-srv"}, nil
}

// runAsHarness is a harness whose Podman runs through the fake sudo as
// smcp-srv.
func runAsHarness(t *testing.T, rt config.Runtime, adjust ...func(*Options)) (*harness, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	shared := t.TempDir()
	rt.RunAs, rt.Sudo, rt.SharedDir = "smcp-srv", exe, shared
	h := newHarness(t, rt, append([]func(*Options){func(o *Options) {
		o.LookupUser = fakeSrvUser
		o.PodmanEnv["SMCP_FAKE_SUDO"] = "1"
	}}, adjust...)...)
	return h, shared
}

// TestRunAsRunsPodmanAsServerIdentity: with runtime.run_as every Podman
// command runs as the CP-46 server identity through `sudo -n -E -u`,
// with that identity's HOME, XDG_RUNTIME_DIR and user bus, and the
// Gateway-built root directory lives in runtime.shared_dir (the state
// directory is closed to that identity). The instance still receives its
// environment values through Podman.
func TestRunAsRunsPodmanAsServerIdentity(t *testing.T) {
	reqtest.Partial(t, "SR-4.1-2")
	h, shared := runAsHarness(t, testRuntime())
	if h.l.RunAs() != "smcp-srv" {
		t.Fatalf("RunAs() = %q", h.l.RunAs())
	}
	spec := h.spec("fs")
	spec.Env["API_TOKEN"] = "s3cr3t"
	p, err := h.l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	connect(t, p)
	inst := h.l.Instances()[0]
	r := h.run(inst.Container)
	if r.Rootfs != filepath.Join(shared, "rootfs") {
		t.Fatalf("rootfs %q, want it in the shared directory %s", r.Rootfs, shared)
	}
	if _, err := os.Stat(filepath.Join(shared, "rootfs", "etc", "passwd")); err != nil {
		t.Fatalf("root directory not prepared in the shared directory: %v", err)
	}
	// The executable is staged by digest where run_as can read it.
	digest, err := FileDigest(h.exe)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(shared, "bin", strings.TrimPrefix(digest, "sha256:"), filepath.Base(h.exe))
	if src := r.Mounts[ServerBinDir+"/"+filepath.Base(h.exe)]; src != staged {
		t.Fatalf("executable mounted from %q, want the staged copy %q", src, staged)
	}
	if st, err := os.Stat(staged); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("staged copy: %v %v", st, err)
	}
	if inst.LaunchSpec.Artifact.Command != h.exe || inst.LaunchSpec.Artifact.Digest != digest {
		t.Fatalf("artifact %+v", inst.LaunchSpec.Artifact)
	}
	if r.Env["API_TOKEN"] != "s3cr3t" {
		t.Fatalf("instance value did not pass through sudo -E: %v", r.Env)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	sudo, _ := os.ReadFile(filepath.Join(h.dir, "sudo.log"))
	calls, _ := os.ReadFile(filepath.Join(h.dir, "calls.log"))
	lines := strings.Split(strings.TrimSpace(string(sudo)), "\n")
	if n := strings.Count(strings.TrimSpace(string(calls)), "\n") + 1; len(lines) != n {
		t.Fatalf("%d podman calls but %d through sudo:\n%s\n%s", n, len(lines), calls, sudo)
	}
	for _, l := range lines {
		f := strings.SplitN(l, " | ", 3)
		if len(f) != 3 || f[0] != "-n -E -u smcp-srv" || !strings.HasPrefix(f[2], h.exe+" ") {
			t.Fatalf("sudo invocation %q", l)
		}
		for _, want := range []string{"HOME=/var/lib/smcp/home/smcp-srv", "USER=smcp-srv", "XDG_RUNTIME_DIR=/run/user/4321", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/4321/bus"} {
			if !strings.Contains(f[1], want) {
				t.Fatalf("sudo invocation %q lacks %s", l, want)
			}
		}
	}
	if !strings.Contains(string(sudo), "| "+h.exe+" run --interactive --name "+inst.Container) || !strings.Contains(string(sudo), " rm --force --time 0 "+inst.Container) {
		t.Fatalf("run and rm did not go through sudo:\n%s", sudo)
	}

	// An unknown identity or root is refused before anything runs.
	rt := testRuntime()
	rt.RunAs, rt.SharedDir, rt.Podman = "nobody-here", shared, h.exe
	if _, err := New(Options{Runtime: rt, StateDir: t.TempDir(), LookupUser: fakeSrvUser}); err == nil || !strings.Contains(err.Error(), "nobody-here") {
		t.Fatalf("unknown run_as: %v", err)
	}
	rt.RunAs = "root"
	root := func(string) (*user.User, error) { return &user.User{Uid: "0", Gid: "0"}, nil }
	if _, err := New(Options{Runtime: rt, StateDir: t.TempDir(), LookupUser: root}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("run_as root: %v", err)
	}
}

type grant struct {
	path string
	uid  int
	perm uint16
}

type grantRecorder struct {
	mu     sync.Mutex
	grants []grant
	dir    string // fake Podman directory: no container may have started yet
	early  bool
}

func (g *grantRecorder) add(path string, uid int, perm uint16) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m, _ := filepath.Glob(filepath.Join(g.dir, "*.start")); len(m) > 0 {
		g.early = true
	}
	g.grants = append(g.grants, grant{path, uid, perm})
	return nil
}

func (g *grantRecorder) has(path string, uid int, perm uint16) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.grants {
		if x.path == path && x.uid == uid && x.perm == perm {
			return true
		}
	}
	return false
}

// TestSecretFilesForAnotherUID: an instance in an auto user namespace runs
// under a subordinate UID that cannot read the Gateway's 0600 secret
// files. The launcher creates the container, reads the host UID that the
// container user maps to from the created container's uid_map, grants that
// UID search on the secret directory and read on each file, and only then
// starts the server. With runtime.run_as the server identity also gets
// search on the directory and its Gateway-owned ancestors before the
// container is created, so that its Podman can resolve the mount source.
func TestSecretFilesForAnotherUID(t *testing.T) {
	reqtest.Partial(t, "FR-6.8", "SR-4.1-2")
	secrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(secrets, "token"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "4242"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Container UIDs 0-2047 map to host UIDs from 231072.
	if err := os.WriteFile(filepath.Join(proc, "4242", "uid_map"), []byte("         0     231072       2048\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("auto", func(t *testing.T) {
		g := &grantRecorder{}
		h := newHarness(t, testRuntime(), func(o *Options) { o.ProcRoot, o.GrantReader = proc, g.add })
		g.dir = h.dir
		spec := h.spec("vault")
		spec.SecretDir = secrets
		spec.Env["TOKEN_FILE"] = filepath.Join(secrets, "token")
		p, err := h.l.Launch(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		connect(t, p)
		defer p.Close()
		hostUID := 231072 + 1000
		if !g.has(secrets, hostUID, posixacl.Execute) || !g.has(filepath.Join(secrets, "token"), hostUID, posixacl.Read) {
			t.Fatalf("grants %+v, want UID %d on the directory and the file", g.grants, hostUID)
		}
		if g.early {
			t.Fatal("a grant came after the container started")
		}
		inst := h.l.Instances()[0]
		calls, _ := os.ReadFile(filepath.Join(h.dir, "calls.log"))
		for _, want := range []string{"create ", "init " + inst.Container, "{{.State.Pid}} " + inst.Container, "start --attach --interactive " + inst.Container} {
			if !strings.Contains(string(calls), want) {
				t.Fatalf("podman calls lack %q:\n%s", want, calls)
			}
		}
		if r := h.run(inst.Container); r.Env["TOKEN_FILE"] != SecretDir+"/token" || r.Mounts[SecretDir] != secrets {
			t.Fatalf("secret mount %v, env %v", r.Mounts, r.Env)
		}
	})

	t.Run("keep-id needs no grant", func(t *testing.T) {
		g := &grantRecorder{}
		rt := testRuntime()
		rt.Servers = []config.RuntimeServer{{Alias: "vault", UserNS: "keep-id"}}
		h := newHarness(t, rt, func(o *Options) { o.ProcRoot, o.GrantReader = proc, g.add })
		spec := h.spec("vault")
		spec.SecretDir = secrets
		p, err := h.l.Launch(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		connect(t, p)
		defer p.Close()
		if len(g.grants) != 0 {
			t.Fatalf("keep-id under the Gateway's own identity granted %+v", g.grants)
		}
		calls, _ := os.ReadFile(filepath.Join(h.dir, "calls.log"))
		if strings.Contains(string(calls), "create ") {
			t.Fatalf("keep-id launch used create/start:\n%s", calls)
		}
	})

	t.Run("run_as keep-id", func(t *testing.T) {
		g := &grantRecorder{}
		rt := testRuntime()
		rt.Servers = []config.RuntimeServer{{Alias: "vault", UserNS: "keep-id"}}
		h, _ := runAsHarness(t, rt, func(o *Options) { o.ProcRoot, o.GrantReader = proc, g.add })
		g.dir = h.dir
		spec := h.spec("vault")
		spec.SecretDir = secrets
		p, err := h.l.Launch(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		connect(t, p)
		defer p.Close()
		if !g.has(secrets, 4321, posixacl.Execute) || !g.has(filepath.Join(secrets, "token"), 4321, posixacl.Read) {
			t.Fatalf("grants %+v, want smcp-srv (4321) on the directory and the file", g.grants)
		}
		// Ancestors owned by the Gateway identity become traversable too.
		if parent := filepath.Dir(secrets); pathOwnedBySelf(parent) && !g.has(parent, 4321, posixacl.Execute) {
			t.Fatalf("grants %+v lack search on %s", g.grants, parent)
		}
		if g.early {
			t.Fatal("a grant came after the container started")
		}
	})

	t.Run("grant failure removes the container", func(t *testing.T) {
		h := newHarness(t, testRuntime(), func(o *Options) {
			o.ProcRoot = proc
			o.GrantReader = func(string, int, uint16) error { return posixacl.ErrUnsupported }
		})
		spec := h.spec("vault")
		spec.SecretDir = secrets
		if _, err := h.l.Launch(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "POSIX ACLs") {
			t.Fatalf("launch with ACLs unavailable: %v", err)
		}
		m, _ := filepath.Glob(filepath.Join(h.dir, "*.rm"))
		s, _ := filepath.Glob(filepath.Join(h.dir, "*.start"))
		if len(m) != 1 || len(s) != 0 {
			t.Fatalf("removed %v, started %v", m, s)
		}
	})
}

func pathOwnedBySelf(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	return fileUID(st) == os.Getuid()
}

func TestMapID(t *testing.T) {
	m := "0 4321 1\n1 300000 65536\n"
	for in, want := range map[int]int{0: 4321, 1: 300000, 1000: 300999, 65536: 365535} {
		if got, ok := mapID(m, in); !ok || got != want {
			t.Errorf("mapID(%d) = %d %v, want %d", in, got, ok, want)
		}
	}
	if _, ok := mapID(m, 65537); ok {
		t.Error("unmapped ID mapped")
	}
	if _, err := containerUID("x:1"); err == nil {
		t.Error("non-numeric runtime.user accepted")
	}
}
