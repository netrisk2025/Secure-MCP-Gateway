// Package channel carries the listener a request arrived on through its
// context, so that evidence written while serving it can record the remote
// origin fields of FR-16.8 without the writer knowing which listener it
// serves. The Remote Access listener (internal/remote) sets the origin;
// the Harness Edge and the remote authorization server apply it to their
// events.
package channel

import (
	"context"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Listener names, as stored in session.Session.Listener.
const (
	Local  = "tls"    // CP-02 harness listener
	Remote = "remote" // CP-48 Remote Access listener
	UDS    = "uds"    // CP-02 Unix-domain-socket listener (UDS Harness Profile)
)

// AddressSource labels a tunnel-supplied address (FR-16.8).
const AddressSource = "server-asserted"

// Origin describes where a request came from.
type Origin struct {
	Channel       string // Local, Remote or UDS
	ClientID      string // OAuth client ID when known
	ClientAddress string // tunnel-supplied caller address (remote only)
}

type key struct{}

// With returns ctx carrying o.
func With(ctx context.Context, o Origin) context.Context { return context.WithValue(ctx, key{}, o) }

// From returns the origin carried by ctx; the zero Origin means the local
// listener.
func From(ctx context.Context) Origin { o, _ := ctx.Value(key{}).(Origin); return o }

// Listener is the session listener name for the origin.
func (o Origin) Listener() string {
	switch o.Channel {
	case Remote, UDS:
		return o.Channel
	}
	return Local
}

// Apply sets the remote-origin fields on e when the origin is remote. A
// client ID already on the event is kept.
func (o Origin) Apply(e *audit.Event) {
	if o.Channel != Remote {
		return
	}
	e.Channel = Remote
	if e.ClientID == "" {
		e.ClientID = o.ClientID
	}
	if o.ClientAddress != "" {
		e.ClientAddress, e.ClientAddressSource = o.ClientAddress, AddressSource
	}
}
