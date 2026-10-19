// Package console holds the built Management Console (E-24): the React,
// TypeScript and Vite single-page application whose sources are in this
// directory and whose production build is committed in dist/, so that
// `go build` embeds it without Node.js. Rebuild with `make console` after
// changing the sources; CI checks that dist/ matches the sources.
package console

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built console: index.html at the root and hashed
// assets under assets/.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	return sub
}
