package backend

import (
	"context"
	"errors"
)

// Ping sends an MCP ping to the server instance; the Health & Safety
// Monitor (E-23) uses it to report unreachable backends.
func (s *Server) Ping(ctx context.Context) error {
	in, err := s.current(ctx)
	if err != nil {
		return err
	}
	if in == nil || in.session == nil {
		return errors.New("server " + s.Alias + " has no session")
	}
	return in.session.Ping(ctx, nil)
}
