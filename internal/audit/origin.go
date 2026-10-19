package audit

// Origin labels of SR-6.5-1: who an event's content comes from.
const (
	OriginGateway = "gateway" // the Gateway's own enforcement and lifecycle
	OriginBackend = "backend" // text a backend server asserted (stderr, error messages, notifications)
	OriginBroker  = "broker"  // the Egress, Secret and Vault brokers
	OriginAdmin   = "admin"   // an administrative action through the control API or the console
)

// OriginLabel labels an event's origin as gateway, backend, broker or
// admin (SR-6.5-1). Origin carries the producing element; the label is
// derived from it and from the event class.
func OriginLabel(e Event) string {
	switch {
	case e.Class == "server_asserted":
		return OriginBackend
	case e.Origin == "E-18" || e.Origin == "E-19" || e.Origin == "E-20" || e.Class == "egress" || e.Class == "secret":
		return OriginBroker
	case e.Class == "admin" || e.Origin == "E-24":
		return OriginAdmin
	}
	return OriginGateway
}

// BackendObserved reports whether an event belongs to the part of a call
// in which the Gateway exchanged messages with the backend (SR-6.5-1):
// dispatch, completion, delivery, and failures, withholdings and
// indeterminate outcomes reported by the dispatcher, the response
// inspection or the release step. Requested, decided, filtered and denied
// events of a call that was never dispatched are not.
func BackendObserved(e Event) bool {
	switch e.Phase {
	case PhaseDispatched, PhaseCompleted, PhaseDelivered:
		return true
	case PhaseFailed, PhaseIndeterminate, PhaseWithheld:
		return e.Origin == "E-10" || e.Origin == "E-11" || e.Origin == "E-12"
	}
	return e.Class == "server_asserted"
}
