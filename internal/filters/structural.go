package filters

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// SizeOptions bound arguments and results.
type SizeOptions struct {
	ArgumentBytes int64 // default CP-07 request body bound
	ArgumentDepth int   // default 32
	StringBytes   int64 // longest single argument string; 0 = no separate bound
	ResultBytes   int64 // expanded result size; default CP-08
	ResultDepth   int   // structured content depth; default 32 (CP-08)
}

type sizeRequest struct{ o SizeOptions }

func (sizeRequest) ID() string      { return IDSizeLimit }
func (sizeRequest) Version() string { return filterVersion }

func (f sizeRequest) FilterRequest(_ context.Context, _ *pipeline.Call, args json.RawMessage) (pipeline.RequestVerdict, error) {
	block := func(reason, rule, msg string) (pipeline.RequestVerdict, error) {
		return pipeline.RequestVerdict{Action: pipeline.Block, ReasonCode: reason, Finding: msg, Findings: []pipeline.Finding{{Filter: IDSizeLimit, Rule: rule}}}, nil
	}
	if int64(len(args)) > f.o.ArgumentBytes {
		return block(ReasonArgumentsTooLarge, "argument-bytes", fmt.Sprintf("arguments are %d bytes; the limit is %d", len(args), f.o.ArgumentBytes))
	}
	v, ss, ok := argSurfaces(args)
	if !ok {
		return block(ReasonArgumentsInvalid, "unparseable", "arguments are not valid JSON")
	}
	if d := depth(v); d > f.o.ArgumentDepth {
		return block(ReasonArgumentsTooDeep, "argument-depth", fmt.Sprintf("arguments nest %d levels; the limit is %d", d, f.o.ArgumentDepth))
	}
	if f.o.StringBytes > 0 {
		for _, s := range ss {
			if int64(len(s.get())) > f.o.StringBytes {
				return block(ReasonArgumentsTooLarge, "string-bytes", fmt.Sprintf("argument at %s exceeds %d bytes", locOrRoot(s.loc), f.o.StringBytes))
			}
		}
	}
	return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
}

type sizeResponse struct{ o SizeOptions }

func (sizeResponse) ID() string      { return IDSizeLimit }
func (sizeResponse) Version() string { return filterVersion }

// ExpandedSize is the decoded size of a result: text surfaces, binary data
// after Base64 decoding and the serialized structured content.
func ExpandedSize(res *mcp.CallToolResult) int64 {
	var n int64
	for _, s := range resultSurfaces(res) {
		n += int64(len(s.get()))
	}
	for _, c := range res.Content {
		switch t := c.(type) {
		case *mcp.ImageContent:
			n += int64(len(t.Data))
		case *mcp.AudioContent:
			n += int64(len(t.Data))
		case *mcp.EmbeddedResource:
			if t.Resource != nil {
				n += int64(len(t.Resource.Blob))
			}
		}
	}
	return n
}

func (f sizeResponse) FilterResponse(_ context.Context, _ *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	withhold := func(rule, msg string) (pipeline.ResponseVerdict, error) {
		return pipeline.ResponseVerdict{Action: pipeline.Block, ReasonCode: ReasonResultTooLarge, Finding: msg, Findings: []pipeline.Finding{{Filter: IDSizeLimit, Rule: rule}}}, nil
	}
	if n := ExpandedSize(res); n > f.o.ResultBytes {
		return withhold("result-bytes", fmt.Sprintf("result expands to %d bytes; the limit is %d", n, f.o.ResultBytes))
	}
	if res.StructuredContent != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return pipeline.ResponseVerdict{}, err
		}
		v, err := decodeJSON(raw)
		if err != nil {
			return pipeline.ResponseVerdict{}, err
		}
		if d := depth(v); d > f.o.ResultDepth {
			return withhold("result-depth", fmt.Sprintf("structured content nests %d levels; the limit is %d", d, f.o.ResultDepth))
		}
	}
	return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
}

// outputSchema withholds a non-error result whose structured content is
// missing or does not validate against the tool's output schema (SR-5.20-2).
type outputSchema struct{}

func (outputSchema) ID() string      { return IDOutputSchema }
func (outputSchema) Version() string { return filterVersion }

func (outputSchema) FilterResponse(ctx context.Context, call *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	if call.OutputSchema == nil || res.IsError {
		return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
	}
	withhold := func(rule, msg string) (pipeline.ResponseVerdict, error) {
		return pipeline.ResponseVerdict{Action: pipeline.Block, ReasonCode: ReasonFilterBlocked, Finding: msg, Findings: []pipeline.Finding{{Filter: IDOutputSchema, Rule: rule, Location: "/structuredContent"}}}, nil
	}
	if res.StructuredContent == nil {
		return withhold("missing", "the tool declares an output schema but returned no structuredContent")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return pipeline.ResponseVerdict{}, err
	}
	if bytes.Equal(raw, []byte("null")) {
		return withhold("missing", "the tool declares an output schema but returned null structuredContent")
	}
	if msg := pipeline.ValidateArgumentsContext(ctx, call.OutputSchema, raw); msg != "" {
		return withhold("invalid", "structuredContent does not match the output schema: "+msg)
	}
	return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
}

// ContentTypeOptions configure content-type-gate (SR-5.18-1).
type ContentTypeOptions struct {
	Allow    []string // allowed MIME types of image, audio and binary content
	MaxBytes int64    // largest allowed item; default 1 MiB
}

type contentTypeGate struct{ o ContentTypeOptions }

func (contentTypeGate) ID() string      { return IDContentTypeGate }
func (contentTypeGate) Version() string { return filterVersion }

// magic holds the leading bytes each supported MIME type must start with.
var magic = map[string][][]byte{
	"image/png":       {[]byte("\x89PNG\r\n\x1a\n")},
	"image/jpeg":      {[]byte("\xff\xd8\xff")},
	"image/gif":       {[]byte("GIF87a"), []byte("GIF89a")},
	"image/webp":      {[]byte("RIFF")}, // plus "WEBP" at offset 8
	"image/bmp":       {[]byte("BM")},
	"application/pdf": {[]byte("%PDF-")},
	"audio/wav":       {[]byte("RIFF")}, // plus "WAVE" at offset 8
	"audio/x-wav":     {[]byte("RIFF")},
	"audio/mpeg":      {[]byte("ID3"), []byte("\xff\xfb"), []byte("\xff\xf3"), []byte("\xff\xf2")},
	"audio/ogg":       {[]byte("OggS")},
	"audio/flac":      {[]byte("fLaC")},
	"application/zip": {[]byte("PK\x03\x04")},
	"application/gzip": {
		[]byte("\x1f\x8b"),
	},
}

// MagicMatches reports whether data starts with the signature of mimeType.
func MagicMatches(mimeType string, data []byte) bool {
	sigs, ok := magic[mimeType]
	if !ok {
		return false
	}
	for _, s := range sigs {
		if bytes.HasPrefix(data, s) {
			switch mimeType {
			case "image/webp":
				return len(data) >= 12 && string(data[8:12]) == "WEBP"
			case "audio/wav", "audio/x-wav":
				return len(data) >= 12 && string(data[8:12]) == "WAVE"
			}
			return true
		}
	}
	return false
}

func baseMIME(m string) string {
	t, _, err := mime.ParseMediaType(m)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(m))
	}
	return t
}

func (f contentTypeGate) check(mimeType string, data []byte) string {
	t := baseMIME(mimeType)
	switch {
	case !slices.Contains(f.o.Allow, t):
		return "type-not-allowed"
	case int64(len(data)) > f.o.MaxBytes:
		return "too-large"
	case !MagicMatches(t, data):
		return "magic-mismatch"
	}
	return ""
}

func (f contentTypeGate) FilterResponse(_ context.Context, _ *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	type removal struct {
		idx        int
		rule, mime string
		size       int
	}
	var rm []removal
	for i, c := range res.Content {
		switch t := c.(type) {
		case *mcp.TextContent, *mcp.ResourceLink:
		case *mcp.ImageContent:
			if r := f.check(t.MIMEType, t.Data); r != "" {
				rm = append(rm, removal{i, r, t.MIMEType, len(t.Data)})
			}
		case *mcp.AudioContent:
			if r := f.check(t.MIMEType, t.Data); r != "" {
				rm = append(rm, removal{i, r, t.MIMEType, len(t.Data)})
			}
		case *mcp.EmbeddedResource:
			if t.Resource != nil && len(t.Resource.Blob) > 0 {
				if r := f.check(t.Resource.MIMEType, t.Resource.Blob); r != "" {
					rm = append(rm, removal{i, r, t.Resource.MIMEType, len(t.Resource.Blob)})
				}
			}
		default:
			rm = append(rm, removal{i, "unsupported-content", fmt.Sprintf("%T", c), 0})
		}
	}
	if len(rm) == 0 {
		return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
	}
	out, err := cloneResult(res)
	if err != nil {
		return pipeline.ResponseVerdict{}, err
	}
	var findings []pipeline.Finding
	for _, r := range rm {
		mt := baseMIME(r.mime)
		out.Content[r.idx] = &mcp.TextContent{Text: "[removed by content-type-gate: " + mt + ", " + strconv.Itoa(r.size) + " bytes, " + r.rule + "]"}
		findings = append(findings, pipeline.Finding{Filter: IDContentTypeGate, Rule: r.rule, Location: "/content/" + strconv.Itoa(r.idx)})
	}
	return pipeline.ResponseVerdict{Action: pipeline.Transform, Result: out, ReasonCode: ReasonRedacted, Findings: findings}, nil
}

// Delimiter lines of FR-4.18.
const (
	DelimiterBegin = "<<<SMCP-UNTRUSTED-BEGIN nonce="
	DelimiterEnd   = "<<<SMCP-UNTRUSTED-END nonce="
)

// delimiterLine matches any line that looks like a delimiter, whatever its
// nonce, case or spacing; such lines are removed from enclosed text.
var delimiterLine = regexp.MustCompile(`(?im)^[^\n]*<<<\s*smcp-untrusted-(?:begin|end)\b[^\n]*(?:\n|$)`)

// delimitUntrusted encloses each text item of a result from an untrusted
// tool between delimiter lines that carry a fresh 128-bit nonce (FR-4.18).
type delimitUntrusted struct {
	trust func(*pipeline.Call) string
}

func (delimitUntrusted) ID() string      { return IDDelimitUntrusted }
func (delimitUntrusted) Version() string { return filterVersion }

func (f delimitUntrusted) FilterResponse(_ context.Context, call *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	if f.trust != nil && f.trust(call) == "trusted" {
		return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
	}
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return pipeline.ResponseVerdict{}, err
	}
	nonce := hex.EncodeToString(nb[:])
	out, err := cloneResult(res)
	if err != nil {
		return pipeline.ResponseVerdict{}, err
	}
	var findings []pipeline.Finding
	n := 0
	for i, c := range out.Content {
		t, ok := c.(*mcp.TextContent)
		if !ok {
			continue
		}
		body := t.Text
		if strings.Contains(body, "<<<") && delimiterLine.MatchString(body) { // a delimiter line contains <<<
			body = delimiterLine.ReplaceAllString(body, "")
			findings = append(findings, pipeline.Finding{Filter: IDDelimitUntrusted, Rule: "forged-delimiter-removed", Location: "/content/" + strconv.Itoa(i) + "/text"})
		}
		t.Text = DelimiterBegin + nonce + ">>>\n" + strings.TrimSuffix(body, "\n") + "\n" + DelimiterEnd + nonce + ">>>"
		n++
	}
	if n == 0 {
		return pipeline.ResponseVerdict{Action: pipeline.Pass, Findings: findings}, nil
	}
	return pipeline.ResponseVerdict{Action: pipeline.Transform, Result: out, Findings: findings}, nil
}
