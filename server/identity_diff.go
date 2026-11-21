package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/oracle"
	"github.com/jintilm/praetor/traffic"
)

const identityDiffMaxBody = 2 << 20

// taskIdentityDiffer 执行越权差分：三次请求都走记录代理，结论交给 oracle 纯函数。
// 凭据从库里取，模型只给身份名，避免它把 A 的 Cookie 抄进 B。
type taskIdentityDiffer struct {
	rt      http.RoundTripper
	scope   ScopeFunc
	traffic *traffic.Traffic
	store   *db.DB
	taskID  int64
}

func NewTaskIdentityDiffer(proxyAddr, caCertPath string, scope ScopeFunc, tr *traffic.Traffic, store *db.DB, taskID int64) agent.IdentityDiffer {
	return &taskIdentityDiffer{rt: replayTransport(proxyAddr, caCertPath), scope: scope, traffic: tr, store: store, taskID: taskID}
}

func (d *taskIdentityDiffer) identities(ctx context.Context, a, b string) (*db.TaskIdentity, *db.TaskIdentity, error) {
	list, err := d.store.ListTaskIdentities(ctx, d.taskID)
	if err != nil {
		return nil, nil, err
	}
	byLabel := map[string]*db.TaskIdentity{}
	for i := range list {
		byLabel[list[i].Label] = &list[i]
	}
	ia, ib := byLabel[a], byLabel[b]
	if ia == nil {
		return nil, nil, fmt.Errorf("身份 %s 未登记，先用 register_identity", a)
	}
	if ib == nil {
		return nil, nil, fmt.Errorf("身份 %s 未登记，先用 register_identity", b)
	}
	return ia, ib, nil
}

// observe 发一次请求并记录观测；错误写进 Observation 而不是中断整次差分。
func (d *taskIdentityDiffer) observe(ctx context.Context, method, url string, headers map[string]string) (oracle.Observation, string) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return oracle.Observation{Error: err.Error()}, ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept-Encoding", "identity")
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "praetor-identity-diff")
	}
	capture := &capturedTransport{traffic: d.traffic, base: d.rt}
	client := &http.Client{Transport: capture, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return oracle.Observation{Error: err.Error()}, capture.meta.ID
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, identityDiffMaxBody))
	if rerr != nil {
		return oracle.Observation{Status: resp.StatusCode, Error: rerr.Error()}, capture.meta.ID
	}
	sum := sha256.Sum256(body)
	return oracle.Observation{Status: resp.StatusCode, Hash: hex.EncodeToString(sum[:]), Body: string(body)}, capture.meta.ID
}

func (d *taskIdentityDiffer) DiffIdentity(ctx context.Context, in agent.IdentityDiffRequest) (*agent.IdentityDiffResult, error) {
	if d.store == nil {
		return nil, errors.New("没有任务数据库，无法读取身份")
	}
	ia, ib, err := d.identities(ctx, in.LabelA, in.LabelB)
	if err != nil {
		return nil, err
	}
	url := strings.TrimSpace(in.URL)
	if url == "" {
		return nil, errors.New("url 必填")
	}
	if d.scope != nil {
		if serr := d.scope(url); serr != nil {
			return nil, fmt.Errorf("目标不在任务范围：%w", serr)
		}
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}
	canary := strings.TrimSpace(in.Canary)
	if canary == "" {
		canary = strings.TrimSpace(ia.Canary)
	}

	owner, tidA := d.observe(ctx, method, url, ia.Headers)
	peer, tidB := d.observe(ctx, method, url, ib.Headers)
	var anon oracle.Observation
	if in.Anonymous {
		anon, _ = d.observe(ctx, method, url, nil)
	}
	owner.TrafficID, peer.TrafficID = tidA, tidB

	verdict := oracle.IdentityDiff(owner, peer, anon, canary, ia.Fingerprint() != ib.Fingerprint())
	out := &agent.IdentityDiffResult{State: string(verdict.State), Reason: verdict.Reason, Canary: canary}
	if tidA != "" || tidB != "" {
		out.TrafficID = []string{}
		if tidA != "" {
			out.TrafficID = append(out.TrafficID, tidA)
		}
		if tidB != "" {
			out.TrafficID = append(out.TrafficID, tidB)
		}
	}
	out.Statuses = map[string]int{"a": owner.Status, "b": peer.Status}
	if in.Anonymous {
		out.Statuses["anonymous"] = anon.Status
	}
	return out, nil
}
