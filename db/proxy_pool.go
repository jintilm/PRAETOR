package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jintilm/praetor/proxypool"
)

// ProxyPoolEntry is one candidate egress proxy plus its observed health.
type ProxyPoolEntry struct {
	ID                  int64      `json:"id"`
	URL                 string     `json:"url"`
	Protocol            string     `json:"protocol"`
	Host                string     `json:"host"`
	Port                int        `json:"port"`
	Region              string     `json:"region"`
	Source              string     `json:"source"`
	Enabled             bool       `json:"enabled"`
	Status              string     `json:"status"`
	LatencyMS           int64      `json:"latency_ms"`
	SuccessCount        int        `json:"success_count"`
	FailureCount        int        `json:"failure_count"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	SuccessRate         float64    `json:"success_rate"`
	Score               int        `json:"score"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	LastError           string     `json:"last_error"`
	ExitIP              string     `json:"exit_ip"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// ProxyPoolSource is a remote list that is periodically fetched and parsed.
type ProxyPoolSource struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	Region        string     `json:"region"`
	Protocol      string     `json:"protocol"`
	Enabled       bool       `json:"enabled"`
	LastFetchAt   *time.Time `json:"last_fetch_at,omitempty"`
	LastError     string     `json:"last_error"`
	ImportedCount int        `json:"imported_count"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type ProxyPoolFilter struct {
	Status  string
	Query   string
	Source  string
	Enabled *bool
	Limit   int
	Offset  int
}

type ProxyPoolStats struct {
	Total      int `json:"total"`
	Enabled    int `json:"enabled"`
	Healthy    int `json:"healthy"`
	Unhealthy  int `json:"unhealthy"`
	Quarantine int `json:"quarantine"`
	Unknown    int `json:"unknown"`
	Sources    int `json:"sources"`
}

type ProxyPoolRun struct {
	ID         int64      `json:"id"`
	Kind       string     `json:"kind"`
	SourceID   *int64     `json:"source_id,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Imported   int        `json:"imported"`
	Checked    int        `json:"checked"`
	Healthy    int        `json:"healthy"`
	Failed     int        `json:"failed"`
	Error      string     `json:"error"`
}

var defaultProxyPoolSources = []ProxyPoolSource{
	// scdn.io exposes a small random API; the CN endpoint keeps domestic
	// candidates flowing without downloading its very large full text dump.
	{Name: "scdn-cn", URL: "https://proxy.scdn.io/api/get_proxy.php?protocol=http&count=20&country_code=CN", Region: "cn", Protocol: "http", Enabled: true},
	{Name: "scdn-api", URL: "https://proxy.scdn.io/api/get_proxy.php?protocol=all&count=20", Region: "global", Protocol: "http", Enabled: true},
	// Proxy5 publishes a JSON snapshot with ip_address/port/protocols fields;
	// proxypool.Parse maps those fields and ignores unsupported SOCKS4-only rows.
	{Name: "proxy5-json", URL: "https://proxy5.net/assets/data/free-proxies.json", Region: "global", Protocol: "http", Enabled: true},
	// Kuaidaili currently serves a JavaScript bot challenge to non-browser
	// clients. Keep the entry available for operators, but do not let a known
	// failing source create noise in every automatic refresh.
	{Name: "kuaidaili-free", URL: "https://www.kuaidaili.com/free/", Region: "cn", Protocol: "http", Enabled: false},
	// 国内源：proxifly 的 CN 分区列表（混合 http/https/socks5，socks4 会被解析器跳过）。
	{Name: "proxifly-cn", URL: "https://" + "raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/CN/data.txt", Region: "cn", Protocol: "http", Enabled: true},
	{Name: "proxifly-all", URL: "https://" + "raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt", Region: "global", Protocol: "http", Enabled: true},
	{Name: "thespeedx-http", URL: "https://" + "raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", Region: "global", Protocol: "http", Enabled: true},
	{Name: "thespeedx-socks5", URL: "https://" + "raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", Region: "global", Protocol: "socks5", Enabled: true},
	{Name: "monosans-http", URL: "https://" + "raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", Region: "global", Protocol: "http", Enabled: true},
	{Name: "monosans-socks5", URL: "https://" + "raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", Region: "global", Protocol: "socks5", Enabled: true},
}

// EnsureProxyPoolSources seeds the built-in public lists without overwriting
// operator edits. It runs on every startup so existing installs pick up newly
// added built-in sources (e.g. the domestic CN list); rows are matched by the
// unique name/url constraints, so local health data and operator changes stay
// intact.
func (d *DB) EnsureProxyPoolSources(ctx context.Context) error {
	for _, src := range defaultProxyPoolSources {
		if _, err := d.ExecContext(ctx, `
INSERT INTO proxy_pool_sources(name, url, region, protocol, enabled)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT DO NOTHING`, src.Name, src.URL, src.Region, src.Protocol, src.Enabled); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) ListProxyPoolSources(ctx context.Context) ([]ProxyPoolSource, error) {
	rows, err := d.QueryContext(ctx, `
SELECT id,name,url,region,protocol,enabled,last_fetch_at,last_error,imported_count,created_at,updated_at
FROM proxy_pool_sources ORDER BY enabled DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyPoolSource
	for rows.Next() {
		var s ProxyPoolSource
		var last sql.NullTime
		if err := rows.Scan(&s.ID, &s.Name, &s.URL, &s.Region, &s.Protocol, &s.Enabled, &last, &s.LastError, &s.ImportedCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			s.LastFetchAt = &last.Time
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) GetProxyPoolSource(ctx context.Context, id int64) (*ProxyPoolSource, error) {
	var s ProxyPoolSource
	var last sql.NullTime
	err := d.QueryRowContext(ctx, `
SELECT id,name,url,region,protocol,enabled,last_fetch_at,last_error,imported_count,created_at,updated_at
FROM proxy_pool_sources WHERE id=$1`, id).Scan(
		&s.ID, &s.Name, &s.URL, &s.Region, &s.Protocol, &s.Enabled, &last, &s.LastError, &s.ImportedCount, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if last.Valid {
		s.LastFetchAt = &last.Time
	}
	return &s, nil
}

func validateProxyPoolSource(name, rawURL, protocol string) (string, string, error) {
	name = strings.TrimSpace(name)
	rawURL = strings.TrimSpace(rawURL)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if name == "" || rawURL == "" {
		return "", "", errors.New("来源名称和 URL 不能为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", errors.New("来源 URL 必须是 http/https 地址")
	}
	if protocol == "" {
		protocol = "http"
	}
	if protocol != "http" && protocol != "https" && protocol != "socks5" {
		return "", "", errors.New("来源默认协议必须是 http/https/socks5")
	}
	return name, rawURL, nil
}

func (d *DB) CreateProxyPoolSource(ctx context.Context, name, rawURL, region, protocol string) (int64, error) {
	name, rawURL, err := validateProxyPoolSource(name, rawURL, protocol)
	if err != nil {
		return 0, err
	}
	region = strings.TrimSpace(region)
	if region == "" {
		region = "global"
	}
	var id int64
	err = d.QueryRowContext(ctx, `
INSERT INTO proxy_pool_sources(name,url,region,protocol,enabled)
VALUES ($1,$2,$3,$4,true) RETURNING id`, name, rawURL, region, strings.ToLower(strings.TrimSpace(protocol))).Scan(&id)
	return id, err
}

func (d *DB) UpdateProxyPoolSource(ctx context.Context, id int64, name, rawURL, region, protocol *string, enabled *bool) error {
	if id <= 0 {
		return errors.New("无效的来源 id")
	}
	sets := []string{}
	args := []any{}
	add := func(expr string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf(expr, len(args)))
	}
	if name != nil {
		add("name=$%d", strings.TrimSpace(*name))
	}
	if rawURL != nil {
		add("url=$%d", strings.TrimSpace(*rawURL))
	}
	if region != nil {
		add("region=$%d", strings.TrimSpace(*region))
	}
	if protocol != nil {
		add("protocol=$%d", strings.ToLower(strings.TrimSpace(*protocol)))
	}
	if enabled != nil {
		add("enabled=$%d", *enabled)
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := d.ExecContext(ctx, "UPDATE proxy_pool_sources SET "+strings.Join(sets, ",")+fmt.Sprintf(" WHERE id=$%d", len(args)), args...)
	return err
}

func (d *DB) DeleteProxyPoolSource(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM proxy_pool_sources WHERE id=$1`, id)
	return err
}

func (d *DB) MarkProxyPoolSourceFetch(ctx context.Context, id int64, imported int, errText string) error {
	_, err := d.ExecContext(ctx, `
UPDATE proxy_pool_sources SET last_fetch_at=now(), imported_count=$2, last_error=$3 WHERE id=$1`, id, imported, errText)
	return err
}

func (d *DB) ListDueProxyPoolSources(ctx context.Context, interval time.Duration) ([]ProxyPoolSource, error) {
	rows, err := d.QueryContext(ctx, `
SELECT id,name,url,region,protocol,enabled,last_fetch_at,last_error,imported_count,created_at,updated_at
FROM proxy_pool_sources
WHERE enabled AND (last_fetch_at IS NULL OR last_fetch_at < now() - $1::interval)
ORDER BY last_fetch_at NULLS FIRST, id`, fmt.Sprintf("%d seconds", int(interval.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyPoolSource
	for rows.Next() {
		var s ProxyPoolSource
		var last sql.NullTime
		if err := rows.Scan(&s.ID, &s.Name, &s.URL, &s.Region, &s.Protocol, &s.Enabled, &last, &s.LastError, &s.ImportedCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			s.LastFetchAt = &last.Time
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

const proxyPoolEntryColumns = `
id,url,protocol,host,port,region,source,enabled,status,latency_ms,
success_count,failure_count,consecutive_failures,success_rate,score,
last_checked_at,last_error,exit_ip,created_at,updated_at`

type proxyPoolScanner interface {
	Scan(dest ...any) error
}

func scanProxyPoolEntry(scanner proxyPoolScanner) (ProxyPoolEntry, error) {
	var e ProxyPoolEntry
	var last sql.NullTime
	err := scanner.Scan(
		&e.ID, &e.URL, &e.Protocol, &e.Host, &e.Port, &e.Region, &e.Source,
		&e.Enabled, &e.Status, &e.LatencyMS, &e.SuccessCount, &e.FailureCount,
		&e.ConsecutiveFailures, &e.SuccessRate, &e.Score, &last, &e.LastError,
		&e.ExitIP, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return ProxyPoolEntry{}, err
	}
	if last.Valid {
		e.LastCheckedAt = &last.Time
	}
	return e, nil
}

// UpsertProxyPoolCandidate preserves the learned health/statistics of an
// existing proxy and only refreshes its provenance. Once maxEntries is reached,
// one non-healthy row with the lowest score is evicted before inserting, so a
// malicious/huge public list cannot exhaust the DB while the pool still refreshes.
func (d *DB) UpsertProxyPoolCandidate(ctx context.Context, c proxypool.Candidate, maxEntries int) (bool, error) {
	u, err := proxypool.Normalize(c.URL, c.Protocol)
	if err != nil {
		return false, err
	}
	protocol := u.Scheme
	host := u.Hostname()
	port := 0
	fmt.Sscanf(u.Port(), "%d", &port)
	region := strings.TrimSpace(c.Region)
	source := strings.TrimSpace(c.Source)
	rawURL := u.String()

	var id int64
	err = d.QueryRowContext(ctx, `SELECT id FROM proxy_pool_entries WHERE url=$1`, rawURL).Scan(&id)
	switch {
	case err == nil:
		_, err = d.ExecContext(ctx, `
UPDATE proxy_pool_entries
SET protocol=$2, host=$3, port=$4,
    region=CASE WHEN $5 <> '' THEN $5 ELSE region END,
    source=CASE WHEN $6 <> '' THEN $6 ELSE source END
WHERE id=$1`, id, protocol, host, port, region, source)
		return false, err
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}

	if maxEntries > 0 {
		var count int
		if err := d.QueryRowContext(ctx, `SELECT count(*) FROM proxy_pool_entries`).Scan(&count); err != nil {
			return false, err
		}
		if count >= maxEntries {
			// Keep the pool fresh at the cap: drop one lowest-value entry that is
			// not currently healthy. Healthy rows are never evicted, so a steady
			// state of working proxies is preserved even under heavy churn.
			res, err := d.ExecContext(ctx, `
DELETE FROM proxy_pool_entries
WHERE id = (
  SELECT id FROM proxy_pool_entries
  WHERE status <> 'healthy'
  ORDER BY enabled ASC,
           CASE status WHEN 'quarantine' THEN 0 WHEN 'unhealthy' THEN 1 ELSE 2 END,
           score ASC,
           last_checked_at ASC NULLS FIRST,
           id ASC
  LIMIT 1
)`)
			if err != nil {
				return false, err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return false, nil
			}
		}
	}
	res, err := d.ExecContext(ctx, `
INSERT INTO proxy_pool_entries(url,protocol,host,port,region,source)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (url) DO UPDATE SET
    protocol=EXCLUDED.protocol,
    host=EXCLUDED.host,
    port=EXCLUDED.port,
    region=CASE WHEN EXCLUDED.region <> '' THEN EXCLUDED.region ELSE proxy_pool_entries.region END,
    source=CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE proxy_pool_entries.source END`,
		rawURL, protocol, host, port, region, source)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

type proxyPoolImportRow struct {
	URL      string `json:"url"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Region   string `json:"region"`
	Source   string `json:"source"`
}

// ImportProxyPoolCandidates returns how many NEW rows were inserted. Updates to
// existing candidates are intentionally not counted as imports. The whole
// source is applied in one transaction: public lists can contain tens of
// thousands of rows, and per-row SELECT/INSERT loops make a manual fetch look
// hung even though the download already succeeded.
func (d *DB) ImportProxyPoolCandidates(ctx context.Context, candidates []proxypool.Candidate, maxEntries int) (int, error) {
	return d.ImportProxyPoolCandidatesWithSourceLimit(ctx, candidates, maxEntries, 0)
}

// ImportProxyPoolCandidatesWithSourceLimit applies a per-source retention
// quota before the global capacity trim. Without this, a large source that was
// imported earlier can keep its old rows by ID and evict every later source.
func (d *DB) ImportProxyPoolCandidatesWithSourceLimit(ctx context.Context, candidates []proxypool.Candidate, maxEntries, perSourceLimit int) (int, error) {
	if len(candidates) == 0 {
		return 0, nil
	}
	rows := make([]proxyPoolImportRow, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		u, err := proxypool.Normalize(c.URL, c.Protocol)
		if err != nil {
			return 0, err
		}
		rawURL := u.String()
		if _, ok := seen[rawURL]; ok {
			continue
		}
		seen[rawURL] = struct{}{}
		port := 0
		if _, err := fmt.Sscanf(u.Port(), "%d", &port); err != nil {
			return 0, fmt.Errorf("代理 %q 端口无效: %w", rawURL, err)
		}
		rows = append(rows, proxyPoolImportRow{
			URL: rawURL, Protocol: u.Scheme, Host: u.Hostname(), Port: port,
			Region: strings.TrimSpace(c.Region), Source: strings.TrimSpace(c.Source),
		})
	}
	if len(rows) == 0 {
		return 0, nil
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return 0, err
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var inserted int
	err = tx.QueryRowContext(ctx, `
WITH input AS (
  SELECT DISTINCT ON (url) url, protocol, host, port, region, source
  FROM jsonb_to_recordset($1::jsonb) AS x(
    url text, protocol text, host text, port integer, region text, source text
  )
  ORDER BY url
), upserted AS (
  INSERT INTO proxy_pool_entries(url,protocol,host,port,region,source)
  SELECT url,protocol,host,port,region,source FROM input
  ON CONFLICT (url) DO UPDATE SET
    protocol=EXCLUDED.protocol,
    host=EXCLUDED.host,
    port=EXCLUDED.port,
    region=CASE WHEN EXCLUDED.region <> '' THEN EXCLUDED.region ELSE proxy_pool_entries.region END,
    source=CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE proxy_pool_entries.source END
  RETURNING (xmax = 0) AS inserted
)
SELECT count(*) FILTER (WHERE inserted) FROM upserted`, string(payload)).Scan(&inserted)
	if err != nil {
		return 0, err
	}
	if perSourceLimit > 0 {
		// Keep the best non-healthy rows in each source. Healthy rows are
		// excluded from the quota and are never removed by this pass.
		if _, err := tx.ExecContext(ctx, `
WITH ranked AS (
  SELECT id,
         row_number() OVER (
           PARTITION BY source
           ORDER BY enabled DESC,
                    CASE status WHEN 'unknown' THEN 0 WHEN 'unhealthy' THEN 1 ELSE 2 END,
                    score DESC,
                    last_checked_at DESC NULLS LAST,
                    id ASC
         ) AS rn
  FROM proxy_pool_entries
  WHERE status <> 'healthy'
)
DELETE FROM proxy_pool_entries p
USING ranked r
WHERE p.id = r.id AND r.rn > $1`, perSourceLimit); err != nil {
			return 0, err
		}
	}
	if maxEntries > 0 {
		// Trim only the incoming batch to the space actually available. Applying
		// the cap over the whole table here would discard rows that the previous
		// per-source imports already chose to retain.
		if _, err := tx.ExecContext(ctx, `
WITH protected AS (
  SELECT count(*)::integer AS healthy FROM proxy_pool_entries WHERE status='healthy'
), budget AS (
  SELECT GREATEST($1 - healthy, 0) AS n FROM protected
), ranked AS (
  SELECT id,
         row_number() OVER (
           ORDER BY enabled DESC,
                    CASE status WHEN 'unknown' THEN 0 WHEN 'unhealthy' THEN 1 ELSE 2 END,
                    score DESC,
                    last_checked_at DESC NULLS LAST,
                    id ASC
         ) AS rn
  FROM proxy_pool_entries
  WHERE status <> 'healthy'
)
DELETE FROM proxy_pool_entries p
USING ranked r, budget b
WHERE p.id = r.id AND r.rn > b.n`, maxEntries); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

// proxyPoolFilterWhere builds the shared WHERE clause for list/count so the
// pagination total can never drift from the rows it describes.
func proxyPoolFilterWhere(filter ProxyPoolFilter) (string, []any) {
	where := []string{"1=1"}
	args := []any{}
	add := func(expr string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(expr, len(args)))
	}
	switch strings.ToLower(strings.TrimSpace(filter.Status)) {
	case "healthy", "unhealthy", "quarantine", "unknown":
		add("status=$%d", strings.ToLower(strings.TrimSpace(filter.Status)))
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		add("(url ILIKE $%d OR host ILIKE $%d OR region ILIKE $%d OR source ILIKE $%d)", "%"+q+"%")
		// The helper only binds one placeholder; expand the same argument index.
		idx := len(args)
		where[len(where)-1] = fmt.Sprintf("(url ILIKE $%d OR host ILIKE $%d OR region ILIKE $%d OR source ILIKE $%d)", idx, idx, idx, idx)
	}
	if src := strings.TrimSpace(filter.Source); src != "" {
		add("source=$%d", src)
	}
	if filter.Enabled != nil {
		add("enabled=$%d", *filter.Enabled)
	}
	return strings.Join(where, " AND "), args
}

func (d *DB) ListProxyPoolEntries(ctx context.Context, filter ProxyPoolFilter) ([]ProxyPoolEntry, error) {
	whereClause, args := proxyPoolFilterWhere(filter)
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	query := "SELECT " + proxyPoolEntryColumns + " FROM proxy_pool_entries WHERE " +
		whereClause +
		fmt.Sprintf(" ORDER BY enabled DESC, CASE status WHEN 'healthy' THEN 0 WHEN 'unknown' THEN 1 WHEN 'unhealthy' THEN 2 ELSE 3 END, score DESC, latency_ms ASC, id LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ProxyPoolEntry, 0)
	for rows.Next() {
		e, err := scanProxyPoolEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountProxyPoolEntries returns the number of rows matching the same filters as
// ListProxyPoolEntries, so the UI can paginate without fetching everything.
func (d *DB) CountProxyPoolEntries(ctx context.Context, filter ProxyPoolFilter) (int, error) {
	whereClause, args := proxyPoolFilterWhere(filter)
	var total int
	err := d.QueryRowContext(ctx, "SELECT count(*) FROM proxy_pool_entries WHERE "+whereClause, args...).Scan(&total)
	return total, err
}

func (d *DB) GetProxyPoolEntry(ctx context.Context, id int64) (*ProxyPoolEntry, error) {
	e, err := scanProxyPoolEntry(d.QueryRowContext(ctx, "SELECT "+proxyPoolEntryColumns+" FROM proxy_pool_entries WHERE id=$1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) GetProxyPoolEntryByURL(ctx context.Context, rawURL string) (*ProxyPoolEntry, error) {
	u, err := proxypool.Normalize(rawURL, "http")
	if err != nil {
		return nil, err
	}
	e, err := scanProxyPoolEntry(d.QueryRowContext(ctx, "SELECT "+proxyPoolEntryColumns+" FROM proxy_pool_entries WHERE url=$1", u.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) SetProxyPoolEntryEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := d.ExecContext(ctx, `UPDATE proxy_pool_entries SET enabled=$2 WHERE id=$1`, id, enabled)
	return err
}

func (d *DB) DeleteProxyPoolEntry(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM proxy_pool_entries WHERE id=$1`, id)
	return err
}

func (d *DB) ProxyPoolStats(ctx context.Context) (ProxyPoolStats, error) {
	var st ProxyPoolStats
	err := d.QueryRowContext(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE enabled),
       count(*) FILTER (WHERE status='healthy'),
       count(*) FILTER (WHERE status='unhealthy'),
       count(*) FILTER (WHERE status='quarantine'),
       count(*) FILTER (WHERE status='unknown'),
       (SELECT count(*) FROM proxy_pool_sources)
FROM proxy_pool_entries`).Scan(&st.Total, &st.Enabled, &st.Healthy, &st.Unhealthy, &st.Quarantine, &st.Unknown, &st.Sources)
	return st, err
}

// SelectProxyPoolEntry returns the best currently healthy, enabled proxy. The
// caller falls back according to Config.FallbackMode when nil is returned.
func (d *DB) SelectProxyPoolEntry(ctx context.Context) (*ProxyPoolEntry, error) {
	e, err := scanProxyPoolEntry(d.QueryRowContext(ctx, `
SELECT `+proxyPoolEntryColumns+`
FROM proxy_pool_entries
WHERE enabled AND status='healthy' AND url <> ''
ORDER BY score DESC, latency_ms ASC, last_checked_at DESC
LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (d *DB) DueProxyPoolEntries(ctx context.Context, interval time.Duration, limit int) ([]ProxyPoolEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := d.QueryContext(ctx, `
SELECT `+proxyPoolEntryColumns+`
FROM proxy_pool_entries
WHERE enabled AND (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
ORDER BY last_checked_at NULLS FIRST, score DESC, id
LIMIT $2`, fmt.Sprintf("%d seconds", int(interval.Seconds())), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ProxyPoolEntry, 0)
	for rows.Next() {
		e, err := scanProxyPoolEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ApplyProxyPoolCheck records one deterministic probe outcome and recomputes the
// score. A row lock keeps concurrent manual/background checks from double
// counting the same observation.
func (d *DB) ApplyProxyPoolCheck(ctx context.Context, id int64, result proxypool.CheckResult, failureThreshold int) error {
	if failureThreshold < 1 {
		failureThreshold = proxypool.DefaultFailureLimit
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var e ProxyPoolEntry
	err = tx.QueryRowContext(ctx, `
SELECT success_count,failure_count,consecutive_failures,latency_ms
FROM proxy_pool_entries WHERE id=$1 FOR UPDATE`, id).Scan(
		&e.SuccessCount, &e.FailureCount, &e.ConsecutiveFailures, &e.LatencyMS)
	if err != nil {
		return err
	}
	now := result.CheckedAt
	if now.IsZero() {
		now = time.Now()
	}
	status := "healthy"
	lastError := ""
	exitIP := ""
	latency := e.LatencyMS
	if result.OK {
		e.SuccessCount++
		e.ConsecutiveFailures = 0
		if result.LatencyMS >= 0 {
			latency = result.LatencyMS
		}
		exitIP = strings.TrimSpace(result.ExitIP)
	} else {
		e.FailureCount++
		e.ConsecutiveFailures++
		status = "unhealthy"
		if e.ConsecutiveFailures >= failureThreshold {
			status = "quarantine"
		}
		if result.LatencyMS >= 0 {
			latency = result.LatencyMS
		}
		lastError = strings.TrimSpace(result.Error)
		if len(lastError) > 1000 {
			lastError = lastError[:1000]
		}
	}
	total := e.SuccessCount + e.FailureCount
	successRate := 0.0
	if total > 0 {
		successRate = float64(e.SuccessCount) / float64(total)
	}
	score := proxypool.Score(e.SuccessCount, e.FailureCount, e.ConsecutiveFailures, latency, now, now)
	_, err = tx.ExecContext(ctx, `
UPDATE proxy_pool_entries SET
  status=$2, latency_ms=$3, success_count=$4, failure_count=$5,
  consecutive_failures=$6, success_rate=$7, score=$8,
  last_checked_at=$9, last_error=$10,
  exit_ip=CASE WHEN $11 <> '' THEN $11 ELSE exit_ip END
WHERE id=$1`,
		id, status, latency, e.SuccessCount, e.FailureCount,
		e.ConsecutiveFailures, successRate, score, now, lastError, exitIP)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) StartProxyPoolRun(ctx context.Context, kind string, sourceID *int64) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO proxy_pool_runs(kind, source_id) VALUES ($1,$2) RETURNING id`, kind, sourceID).Scan(&id)
	return id, err
}

func (d *DB) FinishProxyPoolRun(ctx context.Context, id int64, imported, checked, healthy, failed int, errText string) error {
	_, err := d.ExecContext(ctx, `
UPDATE proxy_pool_runs
SET finished_at=now(), imported=$2, checked=$3, healthy=$4, failed=$5, error=$6
WHERE id=$1`, id, imported, checked, healthy, failed, errText)
	return err
}

func (d *DB) ListProxyPoolRuns(ctx context.Context, limit int) ([]ProxyPoolRun, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := d.QueryContext(ctx, `
SELECT id,kind,source_id,started_at,finished_at,imported,checked,healthy,failed,error
FROM proxy_pool_runs ORDER BY started_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ProxyPoolRun, 0)
	for rows.Next() {
		var r ProxyPoolRun
		var source sql.NullInt64
		var finished sql.NullTime
		if err := rows.Scan(&r.ID, &r.Kind, &source, &r.StartedAt, &finished, &r.Imported, &r.Checked, &r.Healthy, &r.Failed, &r.Error); err != nil {
			return nil, err
		}
		if source.Valid {
			r.SourceID = &source.Int64
		}
		if finished.Valid {
			r.FinishedAt = &finished.Time
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
