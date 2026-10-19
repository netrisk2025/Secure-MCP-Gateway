package adminapi

import "net/http"

// Actor returns the authenticated actor of a request served through
// Server.Handle ("operator-token" or "admin:<user>"), for evidence written
// by routes that other packages register.
func Actor(r *http.Request) string { return actorOf(r) }
