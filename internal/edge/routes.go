package edge

import (
	"fmt"
	"net/http"

	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// SessionHandler serves a harness-listener route for the session that the
// request's bearer token authenticates.
type SessionHandler func(w http.ResponseWriter, r *http.Request, sess session.Session)

// HandleSession registers a harness-listener route (for example the
// FR-3.16 approval status query) that only a live harness session can
// reach. The listener's host and origin checks apply; an invalid token is
// answered like the MCP endpoint answers it (401 with -31006).
func (g *Gateway) HandleSession(pattern string, h SessionHandler) {
	g.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		sess, err := g.store.Authenticate(session.Bearer(r), "tls")
		if err != nil || sess == nil {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, g.oauth.ResourceMetadataURL()))
			writeRPCError(w, http.StatusUnauthorized, gatewayError(CodeSessionInvalid, "session invalid", "SESSION_INVALID", ids.New(), "", nil))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, *sess)
	})
}
