package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestIntersectRoots is SR-4.6-1 at the launch specification: a packaged
// server's mount grants are cut down to the filesystem slots its manifest
// declares, write only where both the grant and the slot allow it, and a
// grant that meets no slot is refused. A configured command (no manifest)
// keeps its grants.
func TestIntersectRoots(t *testing.T) {
	reqtest.Partial(t, "SR-4.6-1")
	roots := []pipeline.Root{{Slot: "docs", Path: "/srv/data/docs"}, {Slot: "out", Path: "/srv/data/out", Write: true}}
	for _, c := range []struct {
		name   string
		grants []config.RuntimeMount
		want   []config.RuntimeMount
		err    bool
	}{
		{"grant equals a slot", []config.RuntimeMount{{Source: "/srv/data/docs"}}, []config.RuntimeMount{{Source: "/srv/data/docs", Target: "/srv/data/docs"}}, false},
		{"grant within a slot keeps its target", []config.RuntimeMount{{Source: "/srv/data/out/sub", Target: "/out", Write: true}},
			[]config.RuntimeMount{{Source: "/srv/data/out/sub", Target: "/out", Write: true}}, false},
		{"write grant on a read-only slot mounts read-only", []config.RuntimeMount{{Source: "/srv/data/docs", Write: true}},
			[]config.RuntimeMount{{Source: "/srv/data/docs", Target: "/srv/data/docs"}}, false},
		{"read grant on a read-write slot mounts read-only", []config.RuntimeMount{{Source: "/srv/data/out"}},
			[]config.RuntimeMount{{Source: "/srv/data/out", Target: "/srv/data/out"}}, false},
		{"a grant of the parent mounts each slot alone", []config.RuntimeMount{{Source: "/srv/data", Target: "/data", Write: true}},
			[]config.RuntimeMount{{Source: "/srv/data/docs", Target: "/data/docs"}, {Source: "/srv/data/out", Target: "/data/out", Write: true}}, false},
		{"a sibling with a common prefix is outside", []config.RuntimeMount{{Source: "/srv/data/docs2"}}, nil, true},
		{"a grant outside every slot is refused", []config.RuntimeMount{{Source: "/home/user"}}, nil, true},
	} {
		got, err := IntersectRoots("s", c.grants, roots)
		if c.err {
			if !errors.Is(err, ErrMountRefused) || !strings.Contains(err.Error(), "SR-4.6-1") {
				t.Errorf("%s: err %v", c.name, err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: %v %v, want %v", c.name, got, err, c.want)
		}
	}
	// A manifest that declares no slot admits no grant.
	if _, err := IntersectRoots("s", []config.RuntimeMount{{Source: "/srv/data"}}, []pipeline.Root{}); !errors.Is(err, ErrMountRefused) {
		t.Errorf("no declared slot: %v", err)
	}
	// No manifest: the grants stand.
	g := []config.RuntimeMount{{Source: "/srv/data", Write: true}}
	if got, err := IntersectRoots("s", g, nil); err != nil || !slices.Equal(got, g) {
		t.Errorf("no manifest: %v %v", got, err)
	}
}

// mountableDir returns a new directory outside /tmp, which the sandbox
// reserves as a mount target (t.TempDir is below /tmp on Linux).
func mountableDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	d, err := os.MkdirTemp(wd, ".roots-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// TestBuildInterpretedPackage: a node or python package runs in the
// sandbox on the interpreter of its digest-pinned image, with its verified
// artifact tree mounted read-only at its own path and its slot grant cut
// down to the declared slot; without an image it is refused.
func TestBuildInterpretedPackage(t *testing.T) {
	reqtest.Partial(t, "SR-4.6-1", "FR-5.9")
	rt := testRuntime()
	state := mountableDir(t)
	tree := filepath.Join(state, "packages", "unpacked", strings.Repeat("b", 64))
	data := mountableDir(t)
	img := "docker.io/library/node@sha256:" + strings.Repeat("c", 64)
	spec := pipeline.ServerSpec{Alias: "fs", Command: "/usr/bin/node", Args: []string{tree + "/node_modules/server/dist/index.js", data},
		Runtime: "node", ArtifactRoot: tree, Roots: []pipeline.Root{{Slot: "root", Path: data}}}
	srv := config.RuntimeServer{Alias: "fs", Image: img, Mounts: []config.RuntimeMount{{Source: data, Write: true}}}
	ls, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: spec, InstanceID: "i", Gateway: "gw", StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	args := ls.PodmanArgs()
	if ls.Argv[0] != "node" || ls.Argv[1] != spec.Args[0] || args[len(args)-len(ls.Argv)-1] != img {
		t.Fatalf("argv %v, args %v", ls.Argv, args)
	}
	for _, want := range []string{"--mount=type=bind,src=" + tree + ",dst=" + tree + ",ro,bind-propagation=rprivate",
		"--mount=type=bind,src=" + data + ",dst=" + data + ",ro,bind-propagation=rprivate"} {
		if !hasArg(args, want) {
			t.Errorf("args lack %s: %v", want, args)
		}
	}
	spec.Runtime, spec.Command = "python", "/usr/bin/python3"
	if ls, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: spec, InstanceID: "i", Gateway: "gw", StateDir: state}); err != nil || ls.Argv[0] != "python3" {
		t.Fatalf("python: %v %v", ls.Argv, err)
	}
	srv.Image = ""
	if _, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: spec, InstanceID: "i", Gateway: "gw", StateDir: state, Rootfs: t.TempDir()}); !errors.Is(err, ErrNoArtifact) ||
		!strings.Contains(err.Error(), "needs an image") {
		t.Fatalf("without an image: %v", err)
	}
	// A grant outside the declared slot is refused at launch.
	srv.Image = img
	srv.Mounts = []config.RuntimeMount{{Source: mountableDir(t)}}
	if _, err := Build(BuildInput{Runtime: rt, Server: srv, Spec: spec, InstanceID: "i", Gateway: "gw", StateDir: state}); !errors.Is(err, ErrMountRefused) {
		t.Fatalf("grant outside the slot: %v", err)
	}
}
