// Package bench 提供独立的能力评测题面、结论判定与纯函数指标汇总。
// 本包不连接数据库或启动靶场；调用方负责提供已脱敏的事实记录。
package bench

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type CaseKind string

const (
	Positive CaseKind = "positive"
	Negative CaseKind = "negative"
	Trap     CaseKind = "trap"
	Boundary CaseKind = "boundary"
)

type OracleState string

const (
	OraclePass         OracleState = "pass"
	OracleFail         OracleState = "fail"
	OracleInconclusive OracleState = "inconclusive"
)

type Conclusion string

const (
	Confirmed    Conclusion = "confirmed"
	Rejected     Conclusion = "rejected"
	Inconclusive Conclusion = "inconclusive"
)

// Case 是 bench/corpus/<class>/<id>.yaml 的结构。payload 为抽象请求模板，
// fixture 是目标/版本标识，不参与判分；真实漏洞真值只由 kind 决定。
type Case struct {
	ID                 string      `yaml:"id" json:"id"`
	Class              string      `yaml:"class" json:"class"`
	Kind               CaseKind    `yaml:"kind" json:"kind"`
	Fixture            string      `yaml:"fixture" json:"fixture"`
	URL                string      `yaml:"url" json:"url"`
	Payload            string      `yaml:"payload" json:"payload"`
	ExpectedOracle     OracleState `yaml:"expected_oracle" json:"expected_oracle"`
	ExpectedConclusion Conclusion  `yaml:"expected_conclusion" json:"expected_conclusion"`
}

var slug = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func (c Case) Validate() error {
	if !slug.MatchString(c.ID) || !slug.MatchString(c.Class) {
		return fmt.Errorf("id/class 必须是小写 slug")
	}
	if c.Fixture == "" || c.URL == "" || c.Payload == "" {
		return fmt.Errorf("%s: fixture/url/payload 必填", c.ID)
	}
	if !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://") {
		return fmt.Errorf("%s: URL 必须是 HTTP(S)", c.ID)
	}
	switch c.Kind {
	case Positive, Negative, Trap, Boundary:
	default:
		return fmt.Errorf("%s: 未知 kind %q", c.ID, c.Kind)
	}
	switch c.ExpectedOracle {
	case OraclePass, OracleFail, OracleInconclusive:
	default:
		return fmt.Errorf("%s: 未知 oracle %q", c.ID, c.ExpectedOracle)
	}
	switch c.ExpectedConclusion {
	case Confirmed, Rejected, Inconclusive:
	default:
		return fmt.Errorf("%s: 未知 conclusion %q", c.ID, c.ExpectedConclusion)
	}
	if (c.Kind == Positive && (c.ExpectedOracle != OraclePass || c.ExpectedConclusion != Confirmed)) ||
		(c.Kind == Negative || c.Kind == Trap) && (c.ExpectedOracle == OraclePass || c.ExpectedConclusion == Confirmed) ||
		(c.Kind == Boundary && c.ExpectedOracle == OraclePass && c.ExpectedConclusion != Confirmed) ||
		(c.ExpectedOracle == OraclePass && c.ExpectedConclusion != Confirmed) ||
		(c.ExpectedOracle == OracleFail && c.ExpectedConclusion != Rejected) ||
		(c.ExpectedOracle == OracleInconclusive && c.ExpectedConclusion != Inconclusive) {
		return fmt.Errorf("%s: kind/oracle/conclusion 矛盾", c.ID)
	}
	return nil
}

// ParseCase 严格解析单个 YAML 文档：拒绝未知键、重复键和尾随文档。
func ParseCase(r io.Reader) (Case, error) {
	var c Case
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return Case{}, fmt.Errorf("解析 corpus: %w", err)
	}
	var tail any
	if err := d.Decode(&tail); !errors.Is(err, io.EOF) {
		if err == nil {
			return Case{}, errors.New("corpus 只能有一个 YAML 文档")
		}
		return Case{}, fmt.Errorf("解析尾部: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Case{}, err
	}
	return c, nil
}

// LoadCorpus 加载两级 class/id.yaml 目录，不执行样本 payload；重复 ID 直接报错。
func LoadCorpus(root string) ([]Case, error) {
	var out []Case
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, e os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 2 {
			return fmt.Errorf("%s: 样本必须位于 <class>/<id>.yaml", path)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		c, err := ParseCase(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if c.Class != parts[0] || c.ID != strings.TrimSuffix(parts[1], ".yaml") {
			return fmt.Errorf("%s: 文件路径和 class/id 不一致", path)
		}
		key := c.Class + "/" + c.ID
		if seen[key] {
			return fmt.Errorf("%s: 重复样本", key)
		}
		seen[key] = true
		out = append(out, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class == out[j].Class {
			return out[i].ID < out[j].ID
		}
		return out[i].Class < out[j].Class
	})
	return out, nil
}

// Judge 保留真值与观测值的区别；oracle pass 仅在正样本可算真实 confirmed。
// 未运行/采集不完整为 inconclusive，而不是失败或真阴性。
type Judgment struct {
	Match         bool
	FalsePositive bool
	Confirmed     bool
	Inconclusive  bool
}

func Judge(c Case, reported bool, oracle OracleState, conclusion Conclusion) Judgment {
	if oracle == OracleInconclusive || conclusion == Inconclusive || oracle == "" || conclusion == "" {
		return Judgment{Inconclusive: true}
	}
	// 误报的定义是「声称这是漏洞，而真值不是」。
	// 早先的写法把「上报过负例」一律算误报，于是把陷阱正确拒绝也记成 FP：
	// precision 被系统性压低，越认真做拒绝判定的运行反而分数越差。
	claimsVuln := oracle == OraclePass && conclusion == Confirmed
	matched := oracle == c.ExpectedOracle && conclusion == c.ExpectedConclusion
	fp := reported && claimsVuln && c.Kind != Positive
	good := reported && c.Kind == Positive && claimsVuln
	return Judgment{Match: matched, FalsePositive: fp, Confirmed: good}
}
