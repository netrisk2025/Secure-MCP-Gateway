package edge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Pagination cursors (SR-5.7-2, FR-1.24). The SDK pages a session's
// catalog with a cursor that encodes the last tool name. The edge never
// shows that cursor to the harness: tools/list results carry a cursor
// sealed with HMAC-SHA256 under a per-process key over the session ID, the
// policy revision of the catalog and the SDK cursor, and a cursor on a
// request is accepted only when its MAC matches the requesting session and
// the catalog's current revision. Any other cursor (modified, random, from
// another session, from a superseded revision, or from before a restart)
// gets -32602.

const cursorLabel = "smcp-cursor-v1"

// cursorMAC is the HMAC of one cursor binding.
func (g *Gateway) cursorMAC(sessionID, revision string, inner []byte) []byte {
	m := hmac.New(sha256.New, g.cursorKey)
	for _, part := range [][]byte{[]byte(cursorLabel), []byte(sessionID), []byte(revision)} {
		m.Write(part)
		m.Write([]byte{0})
	}
	m.Write(inner)
	return m.Sum(nil)
}

// sealCursor returns the harness-facing cursor for an SDK cursor.
func (g *Gateway) sealCursor(inner, sessionID, revision string) string {
	b := append(g.cursorMAC(sessionID, revision, []byte(inner)), inner...)
	return base64.RawURLEncoding.EncodeToString(b)
}

// openCursor returns the SDK cursor inside a sealed cursor when it was
// issued for sessionID and revision.
func (g *Gateway) openCursor(cursor, sessionID, revision string) (string, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || len(b) <= sha256.Size {
		return "", false
	}
	mac, inner := b[:sha256.Size], b[sha256.Size:]
	if !hmac.Equal(mac, g.cursorMAC(sessionID, revision, inner)) {
		return "", false
	}
	return string(inner), true
}

// pagedList runs tools/list with the cursor translation above.
func (g *Gateway) pagedList(ctx context.Context, catalog *catalogSet, next mcp.MethodHandler, method string, req mcp.Request) (mcp.Result, error) {
	sess, _ := ctx.Value(ctxSession).(*session.Session)
	p, _ := req.GetParams().(*mcp.ListToolsParams)
	if sess == nil || p == nil {
		return next(ctx, method, req)
	}
	rev := catalog.rev()
	if p.Cursor != "" {
		inner, ok := g.openCursor(p.Cursor, sess.ID, rev)
		if !ok {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "invalid cursor"}
		}
		p.Cursor = inner
	}
	res, err := next(ctx, method, req)
	if lr, ok := res.(*mcp.ListToolsResult); ok && err == nil && lr.NextCursor != "" {
		lr.NextCursor = g.sealCursor(lr.NextCursor, sess.ID, rev)
	}
	return res, err
}
