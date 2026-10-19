package policy

// SetDefaultRate changes the CP-11 default principal call rate at run time
// (configuration reload of limits.principal_calls_per_minute, FR-17.9).
// Existing rate windows are kept, so a lowered limit applies to calls
// already counted in the current minute.
func (d *Decider) SetDefaultRate(callsPerMinute int) {
	if callsPerMinute < 1 {
		return
	}
	d.mu.Lock()
	d.defRate = callsPerMinute
	d.mu.Unlock()
}

// DefaultRate returns the CP-11 default principal call rate in force.
func (d *Decider) DefaultRate() int { d.mu.RLock(); defer d.mu.RUnlock(); return d.defRate }
