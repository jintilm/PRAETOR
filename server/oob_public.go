package server

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"

	"github.com/jintilm/praetor/internal/oob"
)

// publicOOB 复用同一个公网端点：每次探测都申请一个新端点会白烧请求，
// 而端点本身是按 token 区分的，复用不会串结果。
func (s *Server) publicOOB(ctx context.Context) (*oob.Public, error) {
	s.oobPubMu.Lock()
	defer s.oobPubMu.Unlock()
	if s.oobPub != nil {
		return s.oobPub, nil
	}
	if s.oobPubErr != "" {
		return nil, errors.New(s.oobPubErr)
	}
	p, err := oob.NewPublic(ctx)
	if err != nil {
		s.oobPubErr = err.Error()
		return nil, err
	}
	s.oobPub = p
	log.Printf("[oob] 已申请公网回连端点（零配置）: %s", p.URL(""))
	return p, nil
}

var _ = sync.Mutex{}

// oobPublicProvider 返回零配置公网端点的提供者；设置写成 off 时返回 nil，彻底关闭回连。
func (s *Server) oobPublicProvider() func(context.Context) (*oob.Public, error) {
	if v, _, _ := s.m.pg.GetSetting(settingOOBBaseURL); strings.EqualFold(strings.TrimSpace(v), "off") {
		return nil
	}
	return s.publicOOB
}
