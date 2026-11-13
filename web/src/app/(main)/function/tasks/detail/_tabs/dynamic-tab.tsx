"use client";

import * as React from "react";

import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import {
  dynamicOpOptions,
  type DeviceProbeResult,
  type DynamicGrantAudit,
  type DynamicGrantRecord,
  type DynamicOpsCatalog,
  type MobileTargetDevice,
  type WorkspaceEntry,
} from "@/lib/types";
import { toast } from "sonner";

/**
 * 目标设备卡（双作用域）。
 *
 * assume 模式下任务不签发授权记录，设备从哪来就成了必须回答的问题：上游把序列号
 * 存在授权记录里（一任务一设备），没有记录时改由后端 settings 表提供 —— 这里就是
 * 它的读写界面。换手机、多机轮换改一次即生效，不用动 .env 更不用重建容器。
 *
 * 两级各有用途，所以都给全了：
 *   本任务  → 只影响这一个任务（settings: mobile.task_device.<id>），多机并行时各占一台
 *   全局    → 影响所有未单独指定的任务（settings: mobile.target_device）
 *
 * 每级三种状态互不重叠，都在按钮上：
 *   切换/设为全局 → 写入指定序列号
 *   不锁设备      → 显式空值（盖住下一层）
 *   跟随全局 / 恢复部署默认 → 删键回落下一层
 */
function TargetDeviceCard({ taskId }: { taskId: string }) {
  const [info, setInfo] = React.useState<MobileTargetDevice | null>(null);
  const [taskSerial, setTaskSerial] = React.useState("");
  const [globalSerial, setGlobalSerial] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const load = React.useCallback(() => {
    let alive = true;
    api
      .mobileTargetDevice(taskId)
      .then((d) => {
        if (!alive) return;
        setInfo(d);
        setTaskSerial(d.task_serial ?? "");
        setGlobalSerial(d.global_serial ?? "");
      })
      .catch(() => {
        if (alive) setInfo(null);
      });
    return () => {
      alive = false;
    };
  }, [taskId]);
  React.useEffect(() => load(), [load]);

  const save = async (scope: "task" | "global", input: { serial?: string; reset?: boolean }) => {
    setBusy(true);
    try {
      const d = await api.setMobileTargetDevice(input, scope === "task" ? taskId : undefined);
      setInfo(d);
      setTaskSerial(d.task_serial ?? "");
      setGlobalSerial(d.global_serial ?? "");
      toast.success(
        input.reset
          ? scope === "task"
            ? "本任务已改为跟随全局目标设备"
            : d.global_serial
              ? `全局默认已恢复为 ${d.global_serial}`
              : "全局默认已清除（不锁设备）"
          : input.serial
            ? scope === "task"
              ? `本任务目标设备已设为 ${input.serial}`
              : `全局目标设备已切换为 ${input.serial}`
            : scope === "task"
              ? "本任务已设为不锁设备"
              : "全局已设为不锁设备",
      );
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "保存目标设备失败");
    } finally {
      setBusy(false);
    }
  };

  if (!info) return null;

  const devices = info.devices ?? [];
  const sourceLabel =
    info.source === "task"
      ? "本任务专属"
      : info.source === "setting"
        ? "全局默认"
        : info.source === "env"
          ? "部署默认（.env）"
          : "未设置";

  const scopeRow = (
    scope: "task" | "global",
    value: string,
    setValue: (v: string) => void,
    followLabel: string,
    followValue: string,
  ) => {
    const picked = devices.includes(value) ? value : "";
    return (
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground w-14 shrink-0">{scope === "task" ? "本任务" : "全局"}</span>
        <select
          className="border-input bg-background h-8 rounded-md border px-2 text-xs"
          value={picked}
          onChange={(e) => setValue(e.target.value)}
          disabled={busy || devices.length === 0}
        >
          <option value="">{devices.length ? "— 从在线设备选择 —" : "— 无在线设备 —"}</option>
          {devices.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={info.hint}
          className="h-8 w-44"
          disabled={busy}
        />
        <Button
          size="sm"
          disabled={busy || (scope === "task" ? value === taskSerial : value === globalSerial)}
          onClick={() => void save(scope, { serial: value })}
        >
          {busy && <Spinner data-icon="inline-start" />}
          {scope === "task" ? "切换" : "设为全局"}
        </Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void save(scope, { serial: "" })}>
          不锁设备
        </Button>
        {/* 回落下一层：任务是「回到跟随全局」，全局是「回到部署默认」。
            只给前两个按钮的话，写过一次空值就永久盖住下一层，没有出口退回。 */}
        {scope === "task" ? (
          <Button
            size="sm"
            variant="outline"
            disabled={busy || (info.task_serial ?? "") === ""}
            onClick={() => void save("task", { reset: true })}
          >
            {followLabel}
          </Button>
        ) : (
          <Button
            size="sm"
            variant="outline"
            disabled={busy || info.global_source !== "setting"}
            onClick={() => void save("global", { reset: true })}
          >
            恢复部署默认
          </Button>
        )}
        {followValue ? <span className="text-muted-foreground">→ {followValue}</span> : null}
      </div>
    );
  };

  return (
    <div className="space-y-2 rounded-md border p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2 font-medium">
        目标设备
        <Badge variant="outline">{sourceLabel}</Badge>
        <Badge variant={info.locked ? "secondary" : "outline"}>{info.locked ? "已锁定独占" : "不锁设备"}</Badge>
      </div>

      {scopeRow("task", taskSerial, setTaskSerial, "跟随全局", globalSerial || "不锁设备")}
      {scopeRow("global", globalSerial, setGlobalSerial, "", info.env_serial || "不锁设备")}

      <p className="text-muted-foreground">
        adb 落点 <code>{info.adb_addr}</code> ·{" "}
        {info.adb_reachable ? `在线设备 ${devices.length} 台` : "adb 不可达（仅能改值）"}
        {info.env_serial ? ` · 部署默认 ${info.env_serial}` : " · 部署默认为空"}
      </p>
      <p className="text-muted-foreground">
        设备独占锁按生效的那个序列号生效：同一台机器被另一个任务占用时会等待对方释放。
        本任务留空即跟随全局；想让某个任务固定跑另一台机器，在这里或创建任务时指定即可。
      </p>
    </div>
  );
}

const STATE_LABEL: Record<string, string> = {
  none: "未签发",
  active: "生效中",
  revoked: "已撤销",
  expired: "已过期",
};

function opLabel(op: string, catalog?: DynamicOpsCatalog | null): string {
  return dynamicOpOptions(catalog).find((x) => x.value === op)?.label ?? op;
}

function ts(v?: string): string {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? v : d.toLocaleString("zh-CN");
}

export function DynamicTab({ taskId }: { taskId: string }) {
  const [loading, setLoading] = React.useState(true);
  const [state, setState] = React.useState<string>("none");
  const [grant, setGrant] = React.useState<DynamicGrantRecord | null>(null);
  const [audits, setAudits] = React.useState<DynamicGrantAudit[]>([]);
  const [probe, setProbe] = React.useState<DeviceProbeResult | null>(null);
  const [probing, setProbing] = React.useState(false);
  const [reason, setReason] = React.useState("");
  const [operator, setOperator] = React.useState("");
  const [revoking, setRevoking] = React.useState(false);
  const [catalog, setCatalog] = React.useState<DynamicOpsCatalog | null>(null);
  const [evidence, setEvidence] = React.useState<WorkspaceEntry[]>([]);
  const [evidenceReady, setEvidenceReady] = React.useState(false);
  const [preview, setPreview] = React.useState<{ name: string; content: string } | null>(null);

  const load = React.useCallback(() => {
    let alive = true;
    setLoading(true);
    Promise.all([
      api.taskDynamicGrant(taskId),
      api.taskDynamicGrantAudits(taskId),
    ])
      .then(([g, a]) => {
        if (!alive) return;
        setState(g.state);
        setGrant(g.grant);
        setAudits(a.items);
      })
      .catch(() => {
        if (!alive) return;
        setState("none");
        setGrant(null);
        setAudits([]);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [taskId]);

  React.useEffect(() => load(), [load]);

  // 证据与运行时前置：目录不存在时 wsList 返回 404，这里当成"暂无证据"而不是错误。
  React.useEffect(() => {
    let alive = true;
    api.dynamicOps()
      .then((c) => { if (alive) setCatalog(c); })
      .catch(() => { if (alive) setCatalog(null); });
    // 工作空间文件浏览器的根是 data/，任务工作区是 data/work/<taskID>/，
    // 容器内 /work 对应的正是后者，所以这里必须带 work/ 前缀。
    api.workspaceList(`work/${taskId}/mobile`)
      .then((r) => {
        if (!alive) return;
        setEvidence((r.entries ?? []).filter((e) => !e.dir));
        setEvidenceReady(true);
      })
      .catch(() => {
        if (!alive) return;
        setEvidence([]);
        setEvidenceReady(true);
      });
    return () => { alive = false; };
  }, [taskId]);

  async function previewEvidence(entry: WorkspaceEntry) {
    try {
      const f = await api.workspaceRead(entry.path);
      if (f.binary || f.too_large || f.content === undefined) {
        toast.info("该文件不适合内联预览，请下载后查看");
        return;
      }
      setPreview({ name: entry.name, content: f.content || "（空文件）" });
    } catch (e) {
      toast.error("读取证据失败：" + String(e));
    }
  }

  async function downloadEvidence(entry: WorkspaceEntry) {
    try {
      await api.workspaceDownload(entry.path);
    } catch (e) {
      toast.error("下载失败：" + String(e));
    }
  }

  async function runProbe() {
    setProbing(true);
    try {
      setProbe(await api.mobileDevices(grant?.device_serial || undefined));
    } catch (e) {
      toast.error("设备探测失败：" + String(e));
    } finally {
      setProbing(false);
    }
  }

  async function revoke() {
    if (!reason.trim()) {
      toast.error("请填写撤销原因");
      return;
    }
    setRevoking(true);
    try {
      await api.revokeTaskDynamicGrant(taskId, reason.trim(), operator.trim());
      toast.success("动态授权已撤销，设备锁已释放");
      load();
    } catch (e) {
      toast.error("撤销失败：" + String(e));
    } finally {
      setRevoking(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Spinner /> 正在读取动态授权…
      </div>
    );
  }

  const assumed = catalog?.auth_assumed === true;
  const modeHint = catalog && catalog.device_mode === false ? (
    <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs text-amber-700 dark:text-amber-400">
      后端未开启 <code>PRAETOR_MOBILE_DEVICE_MODE=1</code>：授权记录可能有效，但 mobile_* 工具不会注入，任务会降级静态分析。
      adb 落点 {catalog.adb_addr}；请在 .env 开启并重建容器。
    </div>
  ) : null;

  if (!grant) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            Android 真机动态授权 <Badge variant="outline">{STATE_LABEL[state] ?? state}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          {modeHint}
          {assumed ? (
            <>
              <p>
                当前为 <code>assume</code> 模式（授权已获得）：本任务<strong>无需签发</strong>授权记录，
                <code>mobile_*</code> 工具照常注入，可用范围取全量动态操作。
              </p>
              <p>
                设备独占锁、adb shell 命令白名单、取证边界与审计落库全部照常生效。目标设备在下面切换，
                改完立即生效 —— 不必改 <code>.env</code>，也不必重建容器。
              </p>
              <TargetDeviceCard taskId={taskId} />
            </>
          ) : (
            <>
              <p>该任务未签发动态授权，<code>mobile_*</code> 工具不会出现在 agent 工具面里；所有真机操作一律 fail-closed 降级为静态分析。</p>
              <p>授权只能由人在<strong>创建任务</strong>时显式签发一次，任务下发只传递与校验，不产生授权；创建后没有补签入口。</p>
            </>
          )}
          <Button variant="outline" size="sm" onClick={() => void runProbe()} disabled={probing}>
            {probing && <Spinner data-icon="inline-start" />}
            探测宿主 adb 设备
          </Button>
          {probe && <ProbeView probe={probe} />}
        </CardContent>
      </Card>
    );
  }

  const stateVariant = state === "active" ? "default" : state === "revoked" ? "destructive" : "secondary";

  return (
    <div className="space-y-4">
      {modeHint}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">Android 真机动态授权</CardTitle>
          <Badge variant={stateVariant}>{STATE_LABEL[state] ?? state}</Badge>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 text-sm sm:grid-cols-2">
            <Field label="书面授权编号" value={grant.grant_ref} />
            <Field label="签发人" value={grant.operator} />
            <Field label="设备序列号" value={grant.device_serial} mono />
            <Field label="APK SHA256" value={grant.apk_sha256} mono />
            <Field label="生效时间" value={ts(grant.valid_from)} />
            <Field label="失效时间" value={ts(grant.valid_until)} />
            <Field label="书面授权确认" value={grant.written_authorization ? "已勾选" : "未勾选"} />
            {grant.revoked_at && <Field label="撤销时间 / 原因" value={`${ts(grant.revoked_at)} · ${grant.revoke_reason || "—"}`} />}
          </div>
          <div>
            <p className="mb-1.5 text-xs font-medium text-muted-foreground">允许的操作集（闭集）</p>
            <div className="flex flex-wrap gap-1.5">
              {(grant.ops ?? []).map((op) => (
                <Badge key={op} variant="outline">{opLabel(op, catalog)}</Badge>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void runProbe()} disabled={probing}>
              {probing && <Spinner data-icon="inline-start" />}
              探测这台设备
            </Button>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive" size="sm" disabled={state !== "active" || revoking}>
                  撤销授权
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>撤销任务 #{taskId} 的动态授权？</AlertDialogTitle>
                  <AlertDialogDescription>
                    撤销后立即作废调用令牌并释放设备独占锁，之后所有动态工具调用都会被拒绝并引导改走静态。授权不能重新签发，只能新建任务。
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <div className="space-y-2 py-2">
                  <Input placeholder="撤销原因（必填）" value={reason} onChange={(e) => setReason(e.target.value)} />
                  <Input placeholder="操作者（可选）" value={operator} onChange={(e) => setOperator(e.target.value)} />
                </div>
                <AlertDialogFooter>
                  <AlertDialogCancel>取消</AlertDialogCancel>
                  <AlertDialogAction onClick={() => void revoke()}>确认撤销</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
          {probe && <ProbeView probe={probe} />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">授权审计（append-only，最近 100 条）</CardTitle>
        </CardHeader>
        <CardContent>
          {audits.length === 0 ? (
            <p className="text-sm text-muted-foreground">暂无动态调用记录。</p>
          ) : (
            <div className="divide-y rounded-md border text-xs">
              {audits.map((a) => (
                <div key={a.id} className="grid gap-1 px-3 py-2 sm:grid-cols-[130px_90px_110px_1fr]">
                  <span className="text-muted-foreground">{ts(a.created_at)}</span>
                  <span className={a.action === "block" || a.action === "revoke" ? "text-destructive" : "text-foreground"}>{a.action}</span>
                  <code className="truncate">{a.op || a.tool || "—"}</code>
                  <span className="truncate text-muted-foreground" title={a.reason}>{a.reason || a.device_serial || a.ticket_digest || "—"}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">动态证据</CardTitle>
          <a
            href={`/function/workspace?path=${encodeURIComponent(`work/${taskId}/mobile`)}`}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-muted-foreground underline underline-offset-4 hover:text-foreground"
          >
            在工作空间打开
          </a>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>工具输出脱敏后落到容器可见的 <code>/work/mobile/</code>（宿主侧 <code>data/work/{taskId}/mobile/</code>，同一 bind mount，容器销毁后仍在）。</p>
          {evidenceReady && evidence.length === 0 ? (
            <p>暂无证据文件：任务尚未产生动态输出，或授权未生效。</p>
          ) : (
            <div className="divide-y rounded-md border text-xs">
              {evidence.map((e) => (
                <div key={e.path} className="flex flex-wrap items-center gap-2 px-3 py-2">
                  <code className="min-w-0 flex-1 truncate" title={e.path}>{e.name}</code>
                  <span className="text-muted-foreground">
                    {(e.size / 1024).toFixed(1)} KB · {ts(new Date(e.mtime).toISOString())}
                  </span>
                  <Button variant="ghost" size="sm" onClick={() => void previewEvidence(e)}>预览</Button>
                  <Button variant="ghost" size="sm" onClick={() => void downloadEvidence(e)}>下载</Button>
                </div>
              ))}
            </div>
          )}
          {preview && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <code>{preview.name}</code>
                <Button variant="ghost" size="sm" onClick={() => setPreview(null)}>关闭预览</Button>
              </div>
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted/40 p-2 text-[11px] leading-relaxed">
                {preview.content}
              </pre>
            </div>
          )}
          <p><code>_index.jsonl</code> 是证据索引；Cookie / Token / Authorization / 完整 HTTP 报文在落盘前会被替换为哈希指纹，账号与口令按提交材料需要保留。</p>
          <p>任务落到终态时平台自动复位代理、清理临时 APK 并释放设备锁；frida-server 若由签发人手工启动，仍需自行停止。</p>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={`truncate ${mono ? "font-mono text-xs" : ""}`} title={value}>{value?.length ? value : "—"}</p>
    </div>
  );
}

function ProbeView({ probe }: { probe: DeviceProbeResult }) {
  return (
    <div className="space-y-2 rounded-md border p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={probe.ready ? "default" : "secondary"}>{probe.ready ? "设备就绪" : "降级 / 未就绪"}</Badge>
        <span className="text-muted-foreground">adb server: {probe.adb_server}</span>
        <span className="text-muted-foreground">{ts(new Date(probe.probed_at ?? Date.now()).toISOString())}</span>
      </div>
      {probe.reason && <p className="text-amber-600 dark:text-amber-400">{probe.reason}</p>}
      {probe.devices && probe.devices.length > 0 && (
        <p className="text-muted-foreground">在线设备：{probe.devices.join("、")}</p>
      )}
      <div className="divide-y">
        {(probe.checks ?? []).map((c) => (
          <div key={c.name} className="grid gap-1 py-1 sm:grid-cols-[150px_70px_1fr]">
            <code>{c.name}</code>
            <span className={c.state === "fail" ? "text-destructive" : c.state === "manual" ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"}>{c.state}</span>
            <span className="text-muted-foreground">{c.detail}</span>
          </div>
        ))}
      </div>
      {probe.manual_note && <p className="text-muted-foreground">{probe.manual_note}</p>}
    </div>
  );
}
