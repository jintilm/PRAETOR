// Package tool defines the CoreTool contract and the built-in file/shell tools
// that give the agent its hands. Every tool is self-describing: a name and
// description for the model, a JSON-Schema input, behavioral flags used by the
// scheduler (read-only / concurrency-safe), a permission self-check, and a Call
// method. New tools are built through Build, which applies fail-closed defaults.
package tool

import (
	"context"
	"encoding/json"

	"github.com/jintilm/praetor/internal/norma/llm"
	"github.com/jintilm/praetor/internal/norma/permission"
)

// ProgressInfo is an incremental progress update emitted during a long tool run.
type ProgressInfo struct {
	Message string
}

// ToolContext carries per-call execution state into a tool.
type ToolContext struct {
	WorkingDir string
	AgentID    string
	// ToolUseID is the id of the tool_use block this call answers. Tools that
	// need to refer back to their own call in the conversation — to anchor
	// something to it, or to recognise it later — read it here.
	ToolUseID      string
	MaxOutputChars int
	// OutputDir, when set, makes oversized tool output spill to a file there
	// (full content preserved) instead of being discarded by truncation; the
	// tool returns a head + a pointer to the file. Empty disables spilling.
	OutputDir string
	// Emit reports progress; may be nil. Safe to call from the tool goroutine.
	Emit func(ProgressInfo)
	// Tasks is the background-task manager for this session; may be nil (background
	// execution disabled). Tools use it to spawn, read, and stop background work.
	Tasks *Manager
	// Env holds extra "KEY=VALUE" entries injected into the environment of Bash
	// subprocesses (both foreground and background). Applied on top of the parent
	// process environment, so these override inherited values. Empty = inherit
	// unchanged. Used e.g. to route child-command HTTP through a proxy + trust a
	// CA, without affecting the agent's own process.
	Env []string
	// SandboxPath 把「容器内路径」翻译成宿主路径；nil = 不在沙箱模式。
	//
	// 为什么需要它：文件类工具（Read/Write/Edit/LS/Glob/Grep）跑在宿主进程里，
	// 而模型的视角在容器里 —— 它说 `/chal/files/challenge` 时，宿主上那条路径不存在
	// （Windows 上更糟：`filepath.IsAbs("/chal/x")` 是 false，会被当成相对路径拼到
	// 工作目录下，于是报 "open E://...//data//tasks//<id>//chal//...: no such file"）。
	// 返回 (宿主路径, true) 表示命中挂载点；false 表示不归它管，调用方按原逻辑处理。
	SandboxPath func(string) (string, bool)
	// SandboxWriteDeny 在沙箱模式下回答「这个路径能不能写」：空串 = 可以，非空 = 拒绝理由。
	//
	// 为什么需要一个**写**专用判断（而不是复用 SandboxPath）：
	//   - 容器里 `/chal` 是 `-v ...:ro`，Bash 写不进去；但写文件的工具跑在宿主进程上，
	//     内核不知道那层约束，`Write /chal/x` 会真的改题面目录（题库可能就在那儿）。
	//   - 反过来，`/tmp/x`、`/etc/x` 这类**没挂载**的容器路径，resolvePath 会原样返回，
	//     于是 Write 会落到宿主的 /tmp（Linux）或盘根的 E:\tmp（Windows）——
	//     等于绕开沙箱在宿主上写文件，比只读那个口子更严重。
	// 所以沙箱模式下的写操作只允许落在已映射的可写挂载里（/work）。
	SandboxWriteDeny func(string) string
	// ArtifactSink captures binary tool output (for example a Playwright
	// screenshot image block) without putting base64 into the model context.
	// It returns a workspace-relative pointer that can be passed to an evidence
	// attachment tool. Nil = binary blocks are omitted as text only.
	ArtifactSink func(context.Context, *ToolContext, string, string, []byte) (string, error)
}

func (tc *ToolContext) progress(msg string) {
	if tc != nil && tc.Emit != nil {
		tc.Emit(ProgressInfo{Message: msg})
	}
}

// Result is the outcome of a tool call. Content is the tool_result payload fed
// back to the model.
type Result struct {
	Content []llm.ContentBlock
	IsError bool
	// Extra holds additional messages the tool injects into the conversation
	// right after its tool_result (e.g. the Skill tool emits the invoked skill's
	// instructions as an independent user message rather than burying them in the
	// tool_result). Appended in order; nil for ordinary tools.
	Extra []llm.Message
}

// Text builds a successful text result.
func Text(s string) Result { return Result{Content: []llm.ContentBlock{llm.TextBlock(s)}} }

// Errorf builds an error result.
func Errorf(s string) Result {
	return Result{Content: []llm.ContentBlock{llm.TextBlock(s)}, IsError: true}
}

// Flatten concatenates the text of a result's content blocks.
func (r Result) Flatten() string {
	var s string
	for _, b := range r.Content {
		if b.Type == llm.BlockText {
			s += b.Text
		}
	}
	return s
}

// CoreTool is a capability the agent can invoke (FR-04.1).
type CoreTool interface {
	Name() string
	Description() string
	Prompt() string
	InputSchema() map[string]any
	IsReadOnly(input json.RawMessage) bool
	IsConcurrencySafe(input json.RawMessage) bool
	CheckPermissions(ctx context.Context, input json.RawMessage, pc permission.Context) permission.Decision
	Call(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error)
}

// Spec declares a tool. Build fills unset behavioral fields with fail-closed
// defaults (FR-04.2): not read-only, not concurrency-safe, requires approval.
type Spec struct {
	Name        string
	Description string
	Prompt      string
	Schema      map[string]any
	ReadOnly    func(json.RawMessage) bool
	Concurrent  func(json.RawMessage) bool
	Permissions func(ctx context.Context, input json.RawMessage, pc permission.Context) permission.Decision
	Run         func(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error)

	// RawInput hands Run whatever the model produced, skipping the schema check
	// the harness otherwise applies first.
	//
	// Schema stays required and is still advertised to the model — the two are
	// separate jobs. Schema tells the model what to send; validation decides what
	// gets through. A tool that repairs malformed arguments itself needs the
	// first and is defeated by the second: a truncated or fence-wrapped call is
	// not valid JSON, so it would be rejected before Run ever saw it, and the
	// repair could never run.
	//
	// Only set this on a tool that treats its input as untrusted bytes and
	// answers every shape with a Result rather than an error.
	RawInput bool
}

// Build constructs a CoreTool from a Spec, applying fail-closed defaults.
func Build(s Spec) CoreTool { return &builtTool{spec: s} }

type builtTool struct{ spec Spec }

func (t *builtTool) Name() string                { return t.spec.Name }
func (t *builtTool) Description() string         { return t.spec.Description }
func (t *builtTool) Prompt() string              { return t.spec.Prompt }
func (t *builtTool) InputSchema() map[string]any { return t.spec.Schema }

// AcceptsRawInput reports whether this tool parses its own arguments.
//
// Deliberately not on CoreTool: that interface is public, and adding a method
// would break every host implementing it. The harness asks for it with an
// optional type assertion, the same way it discovers ContextView.
func (t *builtTool) AcceptsRawInput() bool { return t.spec.RawInput }

func (t *builtTool) IsReadOnly(in json.RawMessage) bool {
	if t.spec.ReadOnly == nil {
		return false
	}
	return t.spec.ReadOnly(in)
}

func (t *builtTool) IsConcurrencySafe(in json.RawMessage) bool {
	if t.spec.Concurrent == nil {
		return false
	}
	return t.spec.Concurrent(in)
}

func (t *builtTool) CheckPermissions(ctx context.Context, in json.RawMessage, pc permission.Context) permission.Decision {
	if t.spec.Permissions == nil {
		return permission.AskUser("approve " + t.spec.Name + "?")
	}
	return t.spec.Permissions(ctx, in, pc)
}

func (t *builtTool) Call(ctx context.Context, in json.RawMessage, tc *ToolContext) (Result, error) {
	return t.spec.Run(ctx, in, tc)
}

// readOnlyTrue / concurrentTrue are shared helpers for read tools.
func always(json.RawMessage) bool { return true }

// allowReadOnly is a permission self-check that auto-allows (used by read tools;
// the pipeline also auto-allows read-only, this makes intent explicit).
func allowReadOnly(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}
