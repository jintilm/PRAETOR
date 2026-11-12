package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jintilm/praetor/db"
)

func (s *Server) listVulnKnowledge(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用")
		return
	}
	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	if status == "all" {
		status = ""
	}
	kind := strings.TrimSpace(q.Get("kind"))
	if kind == "all" {
		kind = ""
	}
	page := atoiDefault(q.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	pageSize := atoiDefault(q.Get("page_size"), 20)
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	items, total, err := s.m.pg.ListVulnKnowledge(db.VulnKnowledgeFilter{
		Status: status,
		Kind:   kind,
		Query:  strings.TrimSpace(q.Get("q")),
		Limit:  pageSize,
		Offset: (page - 1) * pageSize,
	})
	if err != nil {
		if errors.Is(err, db.ErrVulnKBInvalidStatus) || errors.Is(err, db.ErrVulnKBInvalidKind) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "total": total, "page": page, "page_size": pageSize,
	})
}

func (s *Server) vulnKnowledgeStats(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用")
		return
	}
	st, err := s.m.pg.VulnKnowledgeStats()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) getVulnKnowledge(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的知识条目 id")
		return
	}
	detail, err := s.m.pg.GetVulnKnowledge(id)
	if errors.Is(err, db.ErrVulnKBNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) updateVulnKnowledge(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的知识条目 id")
		return
	}
	var body db.VulnKnowledgeUpdate
	if err := decode(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	body.ID = id
	if body.Version <= 0 {
		writeErr(w, http.StatusBadRequest, "缺少当前版本号，请刷新后重试")
		return
	}
	item, err := s.m.pg.UpdateVulnKnowledge(r.Context(), body)
	switch {
	case errors.Is(err, db.ErrVulnKBVersion):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, db.ErrVulnKBNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, db.ErrVulnKBInvalidStatus), errors.Is(err, db.ErrVulnKBInvalidKind):
		writeErr(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		detail, detailErr := s.m.pg.GetVulnKnowledge(item.ID)
		if detailErr != nil {
			writeErr(w, http.StatusInternalServerError, detailErr.Error())
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}
}

func (s *Server) backfillVulnKnowledge(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用")
		return
	}
	n, err := s.m.pg.BackfillVulnKnowledgeCandidates(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"processed": n})
}
