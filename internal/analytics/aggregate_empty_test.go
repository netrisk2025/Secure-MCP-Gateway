package analytics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
)

// An aggregate over a window with no matching records answers with an
// empty rows array, not null: the console maps over rows (the G-09 scope
// lists read the values seen in stored observations).
func TestAggregateWithNoRecordsHasEmptyRows(t *testing.T) {
	s, _ := jsonlService(t, nil)
	req := httptest.NewRequest("GET", "/api/v1/observations/aggregate?from=1h&feature=request_bytes&group_by=server_id", nil)
	req = req.WithContext(adminapi.WithRole(req.Context(), "test:admin", adminapi.RoleAdministrator))
	w := httptest.NewRecorder()
	s.aggregate(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"rows":[]`) {
		t.Fatalf("aggregate with no records: %d %s", w.Code, w.Body.String())
	}
}
