package egress

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sync"
)

// ReasonSecretDetected refuses an operation whose URL, headers or body
// carry a registered secret (SR-5.8-2).
const ReasonSecretDetected = "EGRESS_SECRET_DETECTED"

// SecretMatcher finds registered secret fingerprints in text; the
// inspector's fingerprint set (internal/filters) implements it.
type SecretMatcher interface {
	Match(s string) (ref string, found bool)
}

type secretScan struct {
	mu sync.RWMutex
	m  SecretMatcher
}

// SetFingerprints gives the broker the registered secret fingerprints. The
// broker then applies the secret-fingerprint filter to the URL, headers and
// body of every brokered HTTP operation before it leaves, excluding only
// the header it inserts for S1 delivery, which is added after the scan
// (SR-5.8-2). Bytes of a CONNECT tunnel are TLS the broker does not
// terminate and are not scanned.
func (b *Broker) SetFingerprints(m SecretMatcher) {
	if b == nil {
		return
	}
	b.scan.mu.Lock()
	b.scan.m = m
	b.scan.mu.Unlock()
}

func (b *Broker) matcher() SecretMatcher {
	b.scan.mu.RLock()
	defer b.scan.mu.RUnlock()
	return b.scan.m
}

// scanRequest looks for a registered secret in the outbound URL, headers
// and body. It buffers the body (at most limit bytes; a larger body is
// left for the size check) and replaces out.Body with the buffered copy.
// It returns where a secret was found ("" when none).
func (b *Broker) scanRequest(out *http.Request, target *url.URL, limit int64) (string, error) {
	m := b.matcher()
	if m == nil {
		return "", nil
	}
	if _, hit := m.Match(target.String()); hit {
		return "URL", nil
	}
	if u, err := url.QueryUnescape(target.RawQuery); err == nil {
		if _, hit := m.Match(u); hit {
			return "URL", nil
		}
	}
	for name, vs := range out.Header {
		for _, v := range vs {
			if _, hit := m.Match(v); hit {
				return "header " + name, nil
			}
		}
	}
	if out.Body == nil || out.Body == http.NoBody {
		return "", nil
	}
	raw, err := io.ReadAll(io.LimitReader(out.Body, limit+1))
	if err != nil {
		return "", err
	}
	_ = out.Body.Close()
	out.Body = io.NopCloser(bytes.NewReader(raw))
	if _, hit := m.Match(string(raw)); hit {
		return "body", nil
	}
	return "", nil
}
