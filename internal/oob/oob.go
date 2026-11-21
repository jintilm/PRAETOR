// Package oob records one-shot HTTP callbacks as evidence bound to a task.
// DNS callbacks are intentionally not supported by this minimal HTTP implementation.
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const callbackPrefix = "/oob/"

var (
	ErrUnknownToken = errors.New("oob: unknown token")
	ErrInvalidTask  = errors.New("oob: task ID is required")
	ErrInvalidTTL   = errors.New("oob: TTL must be positive")
)

type Status string

const (
	Pending      Status = "pending"
	Hit          Status = "hit"
	Inconclusive Status = "inconclusive"
)

// Evidence is a snapshot; Hit is populated only for the first callback before expiry.
// An inconclusive timeout is not a negative finding.
type Evidence struct {
	Token     string    `json:"token"`
	TaskID    string    `json:"task_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    Status    `json:"status"`
	Hit       *Callback `json:"hit,omitempty"`
}

type Callback struct {
	Time       time.Time   `json:"time"`
	Method     string      `json:"method"`
	Headers    http.Header `json:"headers"`
	RemoteAddr string      `json:"remote_addr"`
}

type Probe struct {
	Token     string    `json:"token"`
	TaskID    string    `json:"task_id"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

type entry struct {
	evidence Evidence
	arrived  chan struct{}
}

// Catcher is safe for concurrent callback and result lookups. Its storage is in memory:
// callers should persist Evidence if results must survive process restart.
type Catcher struct {
	mu      sync.Mutex
	baseURL string
	entries map[string]*entry
	now     func() time.Time
}

// New requires a public HTTP(S) base URL reachable by the callback sender.
// Serving on a loopback listener works for tests; remote callbacks require a reachable URL.
func New(baseURL string) (*Catcher, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("oob: base URL must be http(s) origin without path, credentials, query or fragment")
	}
	return &Catcher{baseURL: strings.TrimRight(u.String(), "/"), entries: make(map[string]*entry), now: time.Now}, nil
}

func (c *Catcher) Issue(taskID string, ttl time.Duration) (Probe, error) {
	if strings.TrimSpace(taskID) == "" {
		return Probe{}, ErrInvalidTask
	}
	if ttl <= 0 {
		return Probe{}, ErrInvalidTTL
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Probe{}, fmt.Errorf("oob: generate token: %w", err)
	}
	token := hex.EncodeToString(raw[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	e := &entry{evidence: Evidence{Token: token, TaskID: taskID, IssuedAt: now, ExpiresAt: now.Add(ttl), Status: Pending}, arrived: make(chan struct{})}
	c.entries[token] = e
	return Probe{Token: token, TaskID: taskID, URL: c.baseURL + callbackPrefix + token, ExpiresAt: e.evidence.ExpiresAt}, nil
}

// Result returns a copy. Unknown tokens never disclose another task's evidence.
func (c *Catcher) Result(token string) (Evidence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[token]
	if !ok {
		return Evidence{}, ErrUnknownToken
	}
	return snapshot(e, c.now()), nil
}

func snapshot(e *entry, now time.Time) Evidence {
	out := e.evidence
	if out.Status == Pending && !now.Before(out.ExpiresAt) {
		out.Status = Inconclusive
	}
	if out.Hit != nil {
		h := *out.Hit
		h.Headers = out.Hit.Headers.Clone()
		out.Hit = &h
	}
	return out
}

// Wait returns a hit or an inconclusive result at the deadline. Context cancellation
// preserves the last snapshot and returns ctx.Err(), never a failed verdict.
func (c *Catcher) Wait(ctx context.Context, token string) (Evidence, error) {
	c.mu.Lock()
	e, ok := c.entries[token]
	if !ok {
		c.mu.Unlock()
		return Evidence{}, ErrUnknownToken
	}
	state := snapshot(e, c.now())
	arrived := e.arrived
	c.mu.Unlock()
	if state.Status != Pending {
		return state, nil
	}
	timer := time.NewTimer(time.Until(state.ExpiresAt))
	defer timer.Stop()
	select {
	case <-arrived:
	case <-timer.C:
	case <-ctx.Done():
		state, _ = c.Result(token)
		return state, ctx.Err()
	}
	return c.Result(token)
}

// Handler accepts exactly /oob/<64 lower-case hex characters>. Each issued token
// records at most one hit. Unknown/replayed/expired callbacks have no task effect.
func (c *Catcher) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		token := strings.TrimPrefix(r.URL.Path, callbackPrefix)
		if !strings.HasPrefix(r.URL.Path, callbackPrefix) || len(token) != 64 || !isHex(token) || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		c.mu.Lock()
		e, ok := c.entries[token]
		if !ok {
			c.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		now := c.now().UTC()
		if e.evidence.Status == Pending && now.Before(e.evidence.ExpiresAt) {
			headers := r.Header.Clone()
			// Retain ordinary request headers, but never persist bearer tokens or cookies.
			for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
				if headers.Get(key) != "" {
					headers.Set(key, "[REDACTED]")
				}
			}
			e.evidence.Hit = &Callback{Time: now, Method: r.Method, Headers: headers, RemoteAddr: r.RemoteAddr}
			e.evidence.Status = Hit
			close(e.arrived)
		}
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
}

func isHex(s string) bool {
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			if ch < 'a' || ch > 'f' {
				return false
			}
		}
	}
	return true
}
