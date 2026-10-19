// Package openapi serves the OpenAPI 3.1 description of the control API at
// GET /api/v1/openapi.json (FR-8.1). The operations are the hand-maintained
// table in routes.go; the roles that may use each operation are taken at
// serving time from the routes registered on the control API, so the
// document always states the permissions the Gateway enforces (FR-8.2).
package openapi

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
)

// Version is the info.version of the document; it follows the /api/v1
// prefix and changes when an operation changes incompatibly.
const Version = "1.0.0"

var pathParam = regexp.MustCompile(`\{([A-Za-z_]+)\}`)

// Document builds the OpenAPI document. routes may be nil, which leaves out
// the role annotations.
func Document(routes []adminapi.RouteInfo) map[string]any {
	byPattern := map[string]adminapi.RouteInfo{}
	for _, r := range routes {
		byPattern[r.Pattern] = r
	}
	paths := map[string]map[string]any{}
	tags := map[string]bool{}
	for _, o := range ops {
		method, path, _ := strings.Cut(o.Pattern, " ")
		tags[o.Tag] = true
		params := []any{}
		for _, m := range pathParam.FindAllStringSubmatch(path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
		for _, q := range o.Query {
			params = append(params, map[string]any{"name": q, "in": "query", "required": false, "schema": map[string]any{"type": "string"}})
		}
		okContent := map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}
		switch {
		case o.Stream:
			okContent = map[string]any{"text/event-stream": map[string]any{"schema": map[string]any{"type": "string"}}}
		case o.File:
			okContent = map[string]any{"application/octet-stream": map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}
		}
		operation := map[string]any{
			"operationId": operationID(method, path),
			"tags":        []string{o.Tag},
			"summary":     o.Summary,
			"description": "Reference: docs/api/" + o.Doc,
			"parameters":  params,
			"responses": map[string]any{
				"200":     map[string]any{"description": "Success", "content": okContent},
				"default": map[string]any{"description": "Error", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}},
			},
		}
		if method == http.MethodPost {
			operation["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}
		}
		if r, ok := byPattern[o.Pattern]; ok {
			if r.Public {
				operation["security"] = []any{}
				operation["x-smcp-public"] = true
			} else {
				operation["x-smcp-roles"] = r.Roles
				if r.Refined {
					operation["x-smcp-refined"] = true
				}
			}
		}
		if paths[path] == nil {
			paths[path] = map[string]any{}
		}
		paths[path][strings.ToLower(method)] = operation
	}
	tagList := []any{}
	names := make([]string, 0, len(tags))
	for t := range tags {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		tagList = append(tagList, map[string]any{"name": t})
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "Secure MCP Gateway control API",
			"version":     Version,
			"description": "The control API of the Management Console & Control API (E-24) on the loopback admin listener. Every operation except sign-in needs a bearer token; x-smcp-roles lists the Appendix C roles that may use it, and x-smcp-refined marks operations where a listed role may use only part of the operation. POST bodies are application/json of at most 64 KiB. Errors are {\"error\": {\"code\", \"message\"}}.",
		},
		"tags":     tagList,
		"security": []any{map[string]any{"bearer": []any{}}},
		"paths":    paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}},
			"schemas": map[string]any{
				"Error": map[string]any{
					"type":     "object",
					"required": []string{"error"},
					"properties": map[string]any{
						"error": map[string]any{
							"type":       "object",
							"required":   []string{"code", "message"},
							"properties": map[string]any{"code": map[string]any{"type": "string"}, "message": map[string]any{"type": "string"}},
						},
					},
				},
			},
		},
	}
}

func operationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, seg := range strings.Split(path, "/") {
		seg = strings.Trim(seg, "{}")
		if seg == "" || seg == "api" || seg == "v1" {
			continue
		}
		for _, part := range strings.FieldsFunc(seg, func(r rune) bool { return r == '.' || r == '_' || r == '-' }) {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}

// Register serves the document on the control API. Register it after the
// other elements so that their routes are known; the document is built per
// request, so later registrations appear as well.
func Register(a *adminapi.Server) {
	a.Handle("GET /api/v1/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		_ = enc.Encode(Document(a.Routes()))
	})
}
