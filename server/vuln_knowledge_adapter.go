package server

import (
	"context"
	"strings"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/config"
	"github.com/jintilm/praetor/db"
)

type dbVulnKnowledgeSearcher struct{ pg *db.DB }

func (a dbVulnKnowledgeSearcher) SearchActiveVulnKnowledge(ctx context.Context, query agent.VulnKnowledgeQuery) ([]agent.VulnKnowledgeHit, error) {
	rows, err := a.pg.SearchActiveVulnKnowledge(ctx, query.Query, query.VulnClass, query.Limit)
	if err != nil {
		return nil, err
	}
	out := make([]agent.VulnKnowledgeHit, 0, len(rows))
	for _, row := range rows {
		out = append(out, agent.VulnKnowledgeHit{
			ID: row.ID, Kind: row.Kind, Title: row.Title, Summary: row.Summary,
			VulnClass: row.VulnClass, CWE: row.CWE, Technology: row.Technology,
			Preconditions: row.Preconditions, TestSteps: row.TestSteps,
			ExpectedSignals: row.ExpectedSignals, FalsePositiveChecks: row.FalsePositiveChecks,
			Confidence: row.Confidence, SourceRef: row.SourceRef,
		})
	}
	return out, nil
}

func (s *Server) vulnKnowledgeSearcher() agent.VulnKnowledgeSearcher {
	if s == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(config.Env("VULN_KB"))) {
	case "0", "off", "false", "no":
		return nil
	}
	return dbVulnKnowledgeSearcher{pg: s.m.pg}
}
