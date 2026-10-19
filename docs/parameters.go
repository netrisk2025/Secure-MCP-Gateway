// Package docs embeds the machine-readable documents of this directory that
// the Gateway binaries need at run time. The files stay the single source:
// the Parameter Catalog (FR-10.37) is read by the Observation Collector
// (E-29), the Observation Store (E-27) and the Research Dataset Service
// (E-32) from this embedded copy.
package docs

import _ "embed"

// ParametersJSON is docs/parameters.json, the versioned Parameter Catalog.
//
//go:embed parameters.json
var ParametersJSON []byte
