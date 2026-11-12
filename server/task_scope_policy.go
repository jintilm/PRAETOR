package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
)

type taskScopeSeed struct {
	Kind  string
	Value string
}

var reTaskScopeCIDR = regexp.MustCompile(`(?i)(?:\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|\b[0-9a-f:]+/\d{1,3}\b)`)

// validateTaskScopePolicy enforces DomainPack.Policy.ScopeRequired before a task
// is persisted. It deliberately checks the operator's task envelope, not shell
// commands: a clear target/company scope is enough for the autonomous planner.
func validateTaskScopePolicy(domainKey string, companyIDs []int64, text string) error {
	pack, ok := domain.Get(domain.Key(strings.TrimSpace(domainKey)))
	if !ok || !pack.Policy().ScopeRequired {
		return nil
	}
	if len(companyIDs) > 0 || len(taskScopeSeedsFromText(text)) > 0 {
		return nil
	}
	return fmt.Errorf(
		"领域 %s 要求显式测试范围：请在任务描述或目标中给出目标 URL、域名、IP/CIDR，或关联企业后再下发。"+
			"不需要细化到命令，但空白范围的任务不会启动",
		pack.Key())
}

// taskScopeSeedsFromText extracts conservative authorization scope from the
// operator's task text. Only explicit parsable targets become scope rows; normal
// prose is never promoted to a wildcard.
func taskScopeSeedsFromText(text string) []taskScopeSeed {
	seen := map[string]bool{}
	var out []taskScopeSeed
	addTarget := func(candidate string) {
		_, host, _, ok := parseTarget(candidate)
		if !ok {
			return
		}
		kind := "subdomain"
		if net.ParseIP(host) != nil {
			kind = "ip"
		}
		key := kind + ":" + host
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, taskScopeSeed{Kind: kind, Value: host})
	}
	addMatch := func(match string, start, end int) {
		if start > 0 && text[start-1] == '.' {
			return // suffix of a longer domain, e.g. "com:8443"
		}
		if end < len(text) && text[end] == '/' {
			return // IP prefix of a CIDR; the CIDR is emitted separately
		}
		addTarget(match)
	}

	for _, m := range reURL.FindAllString(text, -1) {
		addTarget(m)
	}
	for _, loc := range reDomain.FindAllStringIndex(text, -1) {
		// The regex can also match the suffix of a longer domain (for example
		// "com:8443" inside "app.example.com:8443"). Only accept a match when it
		// starts at the beginning or after a non-domain boundary.
		if loc[0] > 0 && text[loc[0]-1] == '.' {
			continue
		}
		addMatch(text[loc[0]:loc[1]], loc[0], loc[1])
	}
	for _, loc := range reIPPort.FindAllStringIndex(text, -1) {
		addMatch(text[loc[0]:loc[1]], loc[0], loc[1])
	}
	for _, loc := range reHostPort.FindAllStringIndex(text, -1) {
		addMatch(text[loc[0]:loc[1]], loc[0], loc[1])
	}
	for _, candidate := range reTaskScopeCIDR.FindAllString(text, -1) {
		if _, _, err := net.ParseCIDR(candidate); err != nil {
			continue
		}
		key := "cidr:" + candidate
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, taskScopeSeed{Kind: "cidr", Value: candidate})
	}
	if len(out) == 0 {
		// Fallback for unusual explicit forms that only parseTarget knows about.
		addTarget(text)
	}
	return out
}

// recordTaskScopeSeeds persists the explicit scope derived from task text. It is
// idempotent through task_scope's unique index and does not expand on discovered
// assets.
func (s *Server) recordTaskScopeSeeds(t *Task, text string) {
	if t == nil || s.m == nil || s.m.assets == nil {
		return
	}
	taskID, err := parseTaskID(t.ID)
	if err != nil {
		return
	}
	for _, seed := range taskScopeSeedsFromText(text) {
		if _, err := s.m.assets.AddAgentScope(taskID, seed.Kind, seed.Value, "由任务目标自动登记", "manual"); err != nil {
			// A malformed candidate must not prevent the task from starting; the
			// preflight already guaranteed at least one valid scope source.
			continue
		}
	}
}
