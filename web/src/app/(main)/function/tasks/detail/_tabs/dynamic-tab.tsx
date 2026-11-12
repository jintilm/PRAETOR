"use client";

import * as React from "react";

import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { api } from "@/lib/api";
import { DYNAMIC_OPS, type DeviceProbeResult, type DynamicGrantAudit, type DynamicGrantRecord } from "@/lib/types";
import { toast } from "sonner";

const STATE_LABEL: Record<string, string> = {
  none: "未签发",
  active: "生效中",
  revoked: "已撤销",
  expired: "已过期",
};

function opLabel(op: string): string {
  return DYNAMIC_OPS.find((x) => x.value === op)?.label ?? op;
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

  if (!grant) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            Android 真机动态授权 <Badge variant="outline">{STATE_LABEL[state] ?? state}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>该任务未签发动态授权，<code>mobile_*</code> 工具不会出现在 agent 工具面里；所有真机操作一律 fail-closed 降级为静态分析。</p>
          <p>授权只能由人在<strong>创建任务</strong>时显式签发一次，任务下发只传递与校验，不产生授权；创建后没有补签入口。</p>
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
                <Badge key={op} variant="outline">{opLabel(op)}</Badge>
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
        <CardHeader>
          <CardTitle className="text-base">动态证据</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>工具输出脱敏后落到容器可见的 <code>/work/mobile/</code>（宿主侧 <code>data/work/{taskId}/mobile/</code>，同一 bind mount，容器销毁后仍在）。</p>
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
      <p className={`truncate ${mono ? "font-mono text-xs" : ""}`} title={value}>{value || "—"}</p>
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
