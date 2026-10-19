package packaging_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestReferenceRecipesArePinned(t *testing.T) {
	// The build, sign, import, enable and call job is
	// scripts/build-reference-packages.sh, which needs the registries.
	reqtest.Partial(t, "FR-14.9")
	want := map[string]string{"filesystem": "npm", "memory": "npm", "git": "pypi", "fetch": "pypi"}
	for name, typ := range want {
		dir := filepath.Join("..", "..", "packaging", "reference", name)
		r, err := packaging.LoadRecipe(filepath.Join(dir, "recipe.json"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Artifact.Type != typ {
			t.Errorf("%s: type %s", name, r.Artifact.Type)
		}
		if err := r.Artifact.Check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := packaging.CheckArgv(r.Launch.Runtime, r.Launch.Argv); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(r.Licenses) == 0 || r.RiskClass == "" || r.RiskClass == "high" || r.Tools.Default.SideEffect == "" || len(r.Tools.Expect) == 0 {
			t.Errorf("%s: classification incomplete", name)
		}
		// The dependency lock pins the top-level artifact by the same digest.
		switch typ {
		case "npm":
			raw, err := os.ReadFile(filepath.Join(dir, r.Dependencies.NPMLockfile))
			if err != nil {
				t.Fatal(err)
			}
			var lock struct {
				Packages map[string]struct{ Version, Integrity string } `json:"packages"`
			}
			json.Unmarshal(raw, &lock)
			e := lock.Packages["node_modules/"+r.Artifact.Name]
			if e.Version != r.Artifact.Version || e.Integrity != r.Artifact.Integrity {
				t.Errorf("%s: lock file pins %s %s", name, e.Version, e.Integrity)
			}
		case "pypi":
			raw, err := os.ReadFile(filepath.Join(dir, r.Dependencies.PipRequirements))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), r.Artifact.Name+"=="+r.Artifact.Version) || !strings.Contains(string(raw), "--hash=sha256:"+r.Artifact.SHA256) {
				t.Errorf("%s: requirements do not pin the artifact", name)
			}
		}
	}
}
