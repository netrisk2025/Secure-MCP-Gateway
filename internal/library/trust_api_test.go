package library

import (
	"net/http"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestTrustAnchorRoutes(t *testing.T) {
	// FR-8.18 also covers the G-10 view (console/e2e) and attestations.
	reqtest.Partial(t, "FR-8.18", "FR-14.8", "FR-7.10")
	r := newRuntime(t, fixtureDesc)
	f := newAPI(t, r)
	k := pkgtest.NewKey(t)
	before, _ := packaging.LoadAnchors(r.state)
	n0 := len(before.Anchors)
	// FR-7.10: a preview shows the fingerprint and enrolls nothing; an
	// enrollment without the confirmed key ID, or with another, is refused.
	st, out := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "team", "public_key": string(k.Public), "classes": []string{"low"}, "expires": "2099-01-01", "preview": true})
	wantID, wantSHA, _ := packaging.Fingerprint(k.Public)
	if st != http.StatusOK || out["key_id"] != k.ID || out["key_id"] != wantID || out["sha256"] != wantSHA || len(wantSHA) != 64 {
		t.Fatalf("preview: %d %v", st, out)
	}
	if a, _ := packaging.LoadAnchors(r.state); len(a.Anchors) != n0 || r.hasEvent("TRUST_ANCHOR_ENROLLED") {
		t.Fatalf("preview enrolled: %+v", a.Anchors)
	}
	if st, out := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "team", "public_key": string(k.Public), "classes": []string{"low"}}); st != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "confirmation_required" {
		t.Fatalf("unconfirmed: %d %v", st, out)
	}
	if st, out := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "team", "public_key": string(k.Public), "classes": []string{"low"}, "confirm_key_id": "0000000000000001"}); st != http.StatusBadRequest || out["error"].(map[string]any)["code"] != "fingerprint_mismatch" {
		t.Fatalf("wrong fingerprint: %d %v", st, out)
	}
	if a, _ := packaging.LoadAnchors(r.state); len(a.Anchors) != n0 {
		t.Fatalf("refused enrollment stored: %+v", a.Anchors)
	}
	st, out = f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "team", "public_key": string(k.Public), "classes": []string{"low"}, "expires": "2099-01-01", "confirm_key_id": k.ID})
	if st != http.StatusCreated || out["key_id"] != k.ID || out["name"] != "team" {
		t.Fatalf("enroll: %d %v", st, out)
	}
	a, err := packaging.LoadAnchors(r.state)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range a.Anchors {
		if x.Name == "team" && x.AddedBy == "operator-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("anchor not saved: %+v", a.Anchors)
	}
	if !r.hasEvent("TRUST_ANCHOR_ENROLLED") {
		t.Fatal("no enrollment evidence")
	}
	// Duplicate key, bad class and bad body are refused.
	if st, _ := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "again", "public_key": string(k.Public), "confirm_key_id": k.ID}); st != http.StatusBadRequest {
		t.Fatalf("duplicate: %d", st)
	}
	bad := pkgtest.NewKey(t)
	if st, _ := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"name": "x", "public_key": string(bad.Public), "classes": []string{"extreme"}, "confirm_key_id": bad.ID}); st != http.StatusBadRequest {
		t.Fatalf("bad class: %d", st)
	}
	if st, _ := f.do("POST", "/api/v1/packages/trust", f.token, map[string]any{"bogus": true}); st != http.StatusBadRequest {
		t.Fatalf("bad body: %d", st)
	}
	if st, _ := f.do("POST", "/api/v1/packages/trust", "", map[string]any{"name": "y"}); st != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", st)
	}
	if st, _ := f.do("DELETE", "/api/v1/packages/trust/team", f.token, nil); st != http.StatusOK {
		t.Fatalf("remove: %d", st)
	}
	if st, _ := f.do("DELETE", "/api/v1/packages/trust/team", f.token, nil); st != http.StatusNotFound {
		t.Fatalf("remove again: %d", st)
	}
	if !r.hasEvent("TRUST_ANCHOR_REMOVED") {
		t.Fatal("no removal evidence")
	}
}
