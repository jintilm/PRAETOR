package traffic

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

const captureUser = "praetor-capture"

// captureReceipt exists only for one platform-originated request. It is never
// inferred from a URL or time window, and its credential is stripped at ingress.
type captureReceipt struct {
	method, url string
	mu          sync.Mutex
	hits        int
	meta        ExchangeMeta
}

func (r *captureReceipt) result() ExchangeMeta {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hits != 1 {
		return ExchangeMeta{}
	}
	return r.meta
}

// RoundTripCaptured sends the original request with one-time proxy credentials.
// Only a transport explicitly using this Traffic instance's recording proxy is
// eligible; direct/custom transports still execute, but return no attribution.
// The cloned transport is never shared with another task or another request.
func (t *Traffic) RoundTripCaptured(base http.RoundTripper, req *http.Request) (*http.Response, ExchangeMeta, error) {
	rt, ok := base.(*http.Transport)
	if t == nil || !ok || rt == nil || rt.Proxy == nil {
		if base == nil {
			base = http.DefaultTransport
		}
		resp, err := base.RoundTrip(req)
		return resp, ExchangeMeta{}, err
	}
	proxyURL, err := rt.Proxy(req)
	if err != nil || proxyURL == nil || !t.isRecordingProxy(proxyURL) || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
		resp, e := base.RoundTrip(req)
		return resp, ExchangeMeta{}, e
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		resp, e := base.RoundTrip(req)
		return resp, ExchangeMeta{}, e
	}
	token := hex.EncodeToString(nonce[:])
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	receipt := &captureReceipt{method: method, url: req.URL.String()}
	t.captures.Store(token, receipt)
	defer t.captures.Delete(token)
	cloned := rt.Clone()
	proxyCopy := *proxyURL
	proxyCopy.User = url.UserPassword(captureUser, token)
	cloned.Proxy = http.ProxyURL(&proxyCopy)
	// CloseIdleConnections also marks active connections to close when returned.
	defer cloned.CloseIdleConnections()
	request := req.Clone(req.Context())
	request.Header.Del("Proxy-Authorization")
	resp, e := cloned.RoundTrip(request)

	return resp, receipt.result(), e
}

// claimCapture runs for CONNECT and for ordinary/decrypted HTTP requests.
func (t *Traffic) claimCapture(f *mproxy.Flow) {
	if f == nil || f.Request == nil {
		return
	}
	header := f.Request.Header
	auth := header.Get("Proxy-Authorization")
	header.Del("Proxy-Authorization") // proxy credentials never reach a target or evidence
	var receipt *captureReceipt
	if strings.HasPrefix(auth, "Basic ") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic ")); err == nil {
			user, token, ok := strings.Cut(string(decoded), ":")
			if ok && user == captureUser {
				if value, ok := t.captures.Load(token); ok {
					receipt = value.(*captureReceipt)
				}
			}
		}
	}
	conn := f.ConnContext
	if f.Request.Method == http.MethodConnect {
		if receipt != nil && conn != nil {
			t.captureConnections.Store(conn, receipt)
		}
		return
	}
	if receipt == nil && conn != nil {
		if value, ok := t.captureConnections.Load(conn); ok {
			receipt = value.(*captureReceipt)
		}
	}
	if receipt != nil && f.Request.URL != nil && f.Request.Method == receipt.method && f.Request.URL.String() == receipt.url {
		t.captureFlows.Store(f.Id, receipt)
		if done := f.Done(); done != nil {
			go func() { <-done; t.captureFlows.Delete(f.Id) }()
		}
	}
}

// completeCapture is called only after the exchange transaction commits.
func (t *Traffic) completeCapture(f *mproxy.Flow, meta ExchangeMeta) {
	value, ok := t.captureFlows.LoadAndDelete(f.Id)
	if !ok {
		return
	}
	r := value.(*captureReceipt)
	r.mu.Lock()
	r.hits++
	r.meta = meta
	r.mu.Unlock()
}

func (t *Traffic) isRecordingProxy(u *url.URL) bool {
	own, err := url.Parse(t.ProxyAddr())
	if err != nil || own.Port() != u.Port() {
		return false
	}
	return strings.EqualFold(own.Hostname(), u.Hostname())
}
