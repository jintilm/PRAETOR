package traffic

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/db"
)

// RawExchangeImport is one external HTTP exchange, currently used by the Burp
// MCP bridge. Raw messages keep their original headers and bodies; only the
// index metadata is normalized for traffic_search/traffic_get.
type RawExchangeImport struct {
	Source     string
	Scheme     string
	Request    string
	Response   string
	Notes      string
	CapturedAt time.Time
}

// RawExchangeImportResult reports whether the exchange was newly inserted.
func (t *Traffic) ImportRawExchange(ctx context.Context, in RawExchangeImport) (ExchangeMeta, bool, error) {
	if t == nil {
		return ExchangeMeta{}, false, errors.New("流量存储不可用")
	}
	if err := ctx.Err(); err != nil {
		return ExchangeMeta{}, false, err
	}
	parsed, err := parseRawExchange(in)
	if err != nil {
		return ExchangeMeta{}, false, err
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()

	var existing int
	err = t.db.QueryRowContext(ctx, `SELECT 1 FROM exchanges WHERE id=?`, parsed.meta.ID).Scan(&existing)
	if err == nil {
		return parsed.meta, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ExchangeMeta{}, false, err
	}

	reqBody := t.spill(parsed.requestBody, parsed.requestContentType)
	respBody := t.spill(parsed.responseBody, parsed.meta.ContentType)

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return ExchangeMeta{}, false, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`,
		parsed.meta.ID, parsed.meta.TS, parsed.meta.Host, parsed.meta.Method,
		parsed.meta.URLTemplate, parsed.meta.URL, parsed.meta.Status,
		parsed.meta.ContentType, len(parsed.requestBody), len(parsed.responseBody))
	if err != nil {
		return ExchangeMeta{}, false, err
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		return ExchangeMeta{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`,
		parsed.meta.ID, parsed.requestHead, reqBody.inline, nullIfEmpty(reqBody.hash),
		parsed.responseHead, respBody.inline, nullIfEmpty(respBody.hash)); err != nil {
		return ExchangeMeta{}, false, err
	}
	for _, hash := range []string{reqBody.hash, respBody.hash} {
		if hash == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, hash, parsed.meta.ID); err != nil {
			return ExchangeMeta{}, false, err
		}
	}
	if t.fts {
		idx := strings.Join([]string{
			parsed.meta.URL, parsed.requestHead, reqBody.index,
			parsed.responseHead, respBody.index, strings.TrimSpace(in.Notes),
		}, "\n")
		if _, err := tx.ExecContext(ctx, `INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			return ExchangeMeta{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return ExchangeMeta{}, false, err
	}
	return parsed.meta, true, nil
}

type parsedRawExchange struct {
	meta               ExchangeMeta
	requestHead        string
	requestBody        []byte
	responseHead       string
	responseBody       []byte
	requestContentType string
}

func parseRawExchange(in RawExchangeImport) (parsedRawExchange, error) {
	requestHead, requestBody := splitHTTPMessage(in.Request)
	responseHead, responseBody := splitHTTPMessage(in.Response)
	if requestHead == "" {
		return parsedRawExchange{}, errors.New("Burp 请求为空")
	}
	lines := strings.Split(strings.ReplaceAll(requestHead, "\r\n", "\n"), "\n")
	requestLine := strings.Fields(lines[0])
	if len(requestLine) < 2 {
		return parsedRawExchange{}, errors.New("Burp 请求行无效")
	}
	method, target := requestLine[0], requestLine[1]
	headers := parseRawHeaders(lines[1:])
	host := strings.TrimSpace(headers["host"])
	if host == "" {
		return parsedRawExchange{}, errors.New("Burp 请求缺少 Host")
	}
	scheme := strings.ToLower(strings.TrimSpace(in.Scheme))
	if scheme != "http" && scheme != "https" {
		scheme = "https"
		if bare, port, ok := splitHostPortLoose(host); ok && port == "80" {
			host, scheme = bare, "http"
		}
	}
	u, err := buildImportedURL(scheme, host, target)
	if err != nil {
		return parsedRawExchange{}, err
	}

	status := 0
	respLines := strings.Split(strings.ReplaceAll(responseHead, "\r\n", "\n"), "\n")
	if len(respLines) > 0 {
		for _, field := range strings.Fields(respLines[0]) {
			if code, err := strconv.Atoi(field); err == nil && code >= 100 && code <= 599 {
				status = code
				break
			}
		}
	}
	respHeaders := map[string]string{}
	if len(respLines) > 1 {
		respHeaders = parseRawHeaders(respLines[1:])
	}
	contentType := respHeaders["content-type"]
	ts := in.CapturedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	source := safeTrafficSource(in.Source)
	sum := sha256.Sum256([]byte(in.Request + "\x00" + in.Response))
	id := source + "-" + hex.EncodeToString(sum[:])[:24]
	return parsedRawExchange{
		meta: ExchangeMeta{
			ID: id, TS: ts.Unix(), Host: u.Hostname(), Method: strings.ToUpper(method),
			URLTemplate: db.TemplatePath(u.EscapedPath()), URL: u.String(), Status: status,
			ContentType: contentType, RespLen: len(responseBody),
		},
		requestHead: requestHead, requestBody: requestBody,
		responseHead: responseHead, responseBody: responseBody,
		requestContentType: headers["content-type"],
	}, nil
}

func splitHTTPMessage(raw string) (string, []byte) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], []byte(raw[i+2:])
	}
	return raw, nil
}

func parseRawHeaders(lines []string) map[string]string {
	out := map[string]string{}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		if prev := out[key]; prev != "" {
			out[key] = prev + ", " + strings.TrimSpace(value)
		} else {
			out[key] = strings.TrimSpace(value)
		}
	}
	return out
}

func buildImportedURL(scheme, host, target string) (*url.URL, error) {
	ref, err := url.ParseRequestURI(target)
	if err != nil {
		return nil, fmt.Errorf("Burp 请求目标无效: %w", err)
	}
	if ref.IsAbs() {
		if ref.Scheme == "" {
			ref.Scheme = scheme
		}
		if ref.Host == "" {
			ref.Host = host
		}
		return ref, nil
	}
	return &url.URL{Scheme: scheme, Host: host, Path: ref.Path, RawPath: ref.RawPath, RawQuery: ref.RawQuery}, nil
}

func splitHostPortLoose(raw string) (host, port string, ok bool) {
	i := strings.LastIndexByte(raw, ':')
	if i <= 0 || i == len(raw)-1 || strings.Contains(raw, "]") {
		return raw, "", false
	}
	if strings.Count(raw, ":") != 1 {
		return raw, "", false
	}
	return raw[:i], raw[i+1:], true
}

func safeTrafficSource(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	for _, r := range raw {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "external"
	}
	return b.String()
}
