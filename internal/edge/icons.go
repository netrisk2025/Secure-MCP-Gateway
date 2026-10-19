package edge

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// gatewayAdminTool reports whether a verified manifest classifies the tool
// as gateway-admin (SR-3.12-1). A live, unverified tool list cannot
// classify itself, as for the side-effect class.
func gatewayAdminTool(ref *backend.ToolRef) bool {
	if ref.Server == nil || !ref.Server.Verified || ref.Tool == nil {
		return false
	}
	c, _ := ref.Tool.Meta[policy.MetaToolClass].(string)
	return c == policy.ClassGatewayAdmin
}

// maxIconBytes bounds a presented icon's decoded image (SR-5.18-2).
const maxIconBytes = 64 << 10

// presentableIcons keeps only the icons a harness may be shown
// (SR-5.18-2): data: URIs of PNG or JPEG images, base64-encoded, at most
// 64 KiB decoded, whose magic bytes match the declared type. Remote URLs
// (tracking), SVG (script) and anything malformed are removed.
func presentableIcons(icons []mcp.Icon) []mcp.Icon {
	var out []mcp.Icon
	for _, ic := range icons {
		if iconAllowed(ic.Source) {
			out = append(out, ic)
		}
	}
	return out
}

func iconAllowed(src string) bool {
	rest, ok := strings.CutPrefix(src, "data:")
	if !ok {
		return false
	}
	meta, data, ok := strings.Cut(rest, ",")
	if !ok {
		return false
	}
	parts := strings.Split(strings.ToLower(meta), ";")
	if len(parts) != 2 || parts[1] != "base64" {
		return false
	}
	if base64.StdEncoding.DecodedLen(len(data)) > maxIconBytes+3 {
		return false
	}
	img, err := base64.StdEncoding.DecodeString(data)
	if err != nil || len(img) == 0 || len(img) > maxIconBytes {
		return false
	}
	switch parts[0] {
	case "image/png":
		return bytes.HasPrefix(img, []byte("\x89PNG\r\n\x1a\n"))
	case "image/jpeg":
		return bytes.HasPrefix(img, []byte{0xFF, 0xD8, 0xFF})
	}
	return false
}
