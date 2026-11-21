package server

import (
	"net/http"

	"github.com/jintilm/praetor/traffic"
)

// One instance per attempt: receipts are never shared between requests or tasks.
type capturedTransport struct {
	traffic *traffic.Traffic
	base    http.RoundTripper
	meta    traffic.ExchangeMeta
}

func (c *capturedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, meta, err := c.traffic.RoundTripCaptured(c.base, req)
	c.meta = meta
	return resp, err
}
