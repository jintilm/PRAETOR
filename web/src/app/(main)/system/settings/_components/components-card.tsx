"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { api, sseUrl } from "@/lib/api";
import type { ComponentsResp } from "@/lib/types";

// 可选组件面板。
//
// 为什么装进沙箱镜像而不是宿主：宿主安装要提权、卸载留残渣、三平台三套逻辑，
// 而且与「一任务一容器」的隔离模型冲突。镜像层可以切回 :latest 一键回滚。
//
// 这一层是**可选加速器**（对应执行文档 R6）：不勾也能正常跑，只是能力浅一些。

const GROUP_LABELS: Record<string, string> = {
  pwn: "Pwn 二进制利用",
  rev: "逆向分析",
  crypto: "密码学",
  forensics: "取证 / 隐写",
};

const GROUP_ORDER = ["pwn", "rev", "crypto", "forensics"];

type ProbeState = "unknown" | "ok" | "missing";

export function ComponentsCard() {
  const [data, setData] = React.useState<ComponentsResp | null>(null);
  const [sel, setSel] = React.useState<string[]>([]);
  const [probe, setProbe] = React.useState<Record<string, { ok: boolean; detail?: string }>>({});
  const [probed, setProbed] = React.useState(false);
  const [lines, setLines] = React.useState<string[]>([]);
  const [running, setRunning] = React.useState(false);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const esRef = React.useRef<EventSource | null>(null);
  const logRef = React.useRef<HTMLPreElement | null>(null);

  const load = React.useCallback(async () => {
    try {
      const r = await api.components();
      setData(r);
      setSel(r.selected ?? r.items.filter((i) => i.selected).map((i) => i.id));
      setLines(r.job?.lines ?? []);
      setRunning(!!r.job?.running);
      if (r.job?.error) setError(r.job.error);
    } catch (e) {
      setError(e instanceof Error ? e.message : "读取组件清单失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 构建进行中时订阅日志；结束时自动刷新一次清单（拿到新镜像 tag）
  const openStream = React.useCallback(() => {
    esRef.current?.close();
    const es = new EventSource(sseUrl("/api/components/stream"));
    esRef.current = es;
    es.onmessage = (ev) => {
      type Frame = { line?: string; done?: boolean; error?: string };
      let f: Frame;
      try {
        f = JSON.parse(ev.data) as Frame;
      } catch {
        return;
      }
      if (f.line) setLines((prev) => [...prev, f.line as string].slice(-400));
      if (f.done) {
        es.close();
        esRef.current = null;
        setRunning(false);
        if (f.error) setError(f.error);
        void load();
      }
    };
    es.onerror = () => {
      // 构建结束或网络抖动：关掉并刷新状态，不自动重连（重连会拿到"已完成"帧，没有意义）
      es.close();
      esRef.current = null;
      setRunning(false);
      void load();
    };
  }, [load]);

  React.useEffect(() => () => esRef.current?.close(), []);

  React.useEffect(() => {
    if (running) openStream();
    // running 只在"用户点击应用"或"清单显示构建中"时变 true，这里不依赖 openStream 的引用
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  React.useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [lines]);

  const toggle = (id: string) =>
    setSel((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));

  const items = data?.items ?? [];
  const totalMB = items.filter((i) => sel.includes(i.id)).reduce((n, i) => n + i.size_mb, 0);
  const dirty = React.useMemo(() => {
    const saved = data?.selected ?? [];
    if (saved.length !== sel.length) return true;
    const s = new Set(saved);
    return sel.some((id) => !s.has(id));
  }, [data, sel]);

  const apply = async () => {
    setBusy(true);
    setError("");
    setLines([]);
    try {
      const r = await api.applyComponents(sel);
      if (r.skipped) {
        setError(""); // 已是同一组合，直接切换，无需构建
        void load();
      } else {
        setRunning(true);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "应用失败");
    } finally {
      setBusy(false);
    }
  };

  const runProbe = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await api.probeComponents();
      setProbe(r.results ?? {});
      setProbed(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "探测失败");
    } finally {
      setBusy(false);
    }
  };

  const probeState = (id: string): ProbeState => {
    if (!probed) return "unknown";
    const r = probe[id];
    if (!r) return "unknown";
    return r.ok ? "ok" : "missing";
  };

  const grouped = React.useMemo(() => {
    const m = new Map<string, typeof items>();
    for (const it of items) {
      const arr = m.get(it.group) ?? [];
      arr.push(it);
      m.set(it.group, arr);
    }
    const groups = Array.from(m.keys()).sort(
      (a, b) =>
        (GROUP_ORDER.indexOf(a) === -1 ? 99 : GROUP_ORDER.indexOf(a)) -
        (GROUP_ORDER.indexOf(b) === -1 ? 99 : GROUP_ORDER.indexOf(b)),
    );
    return groups.map((g) => ({ key: g, label: GROUP_LABELS[g] ?? g, items: m.get(g) ?? [] }));
  }, [items]);

  return (
    <Card className="mb-4 md:mb-6">
      <CardHeader>
        <CardTitle>可选组件（沙箱镜像）</CardTitle>
        <CardDescription>
          这些是<strong>可选加速器</strong>：不选也能正常跑，只是逆向 / CTF 的深度能力会浅一些。
          选中后点「应用」，系统会在<strong>沙箱镜像</strong>里安装（不动你的宿主机），
          失败可切回基础镜像一键回滚。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {loading ? (
          <p className="text-sm text-muted-foreground">加载中…</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <span>
                当前镜像：<code className="rounded bg-muted px-1 py-0.5">{data?.image || data?.base_image}</code>
              </span>
              <span>·</span>
              <span>基础镜像：<code className="rounded bg-muted px-1 py-0.5">{data?.base_image}</code></span>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {grouped.map((g) => (
                <div key={g.key} className="rounded-lg border p-3">
                  <div className="mb-2 text-sm font-medium">{g.label}</div>
                  <div className="space-y-2">
                    {g.items.map((it) => {
                      const st = probeState(it.id);
                      return (
                        <div key={it.id} className="flex items-start gap-2">
                          <Checkbox
                            checked={sel.includes(it.id)}
                            onCheckedChange={() => toggle(it.id)}
                            disabled={running}
                            className="mt-0.5"
                          />
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="text-sm">{it.title}</span>
                              <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                                {it.size_mb}MB
                              </Badge>
                              {st === "ok" ? (
                                <Badge variant="secondary" className="px-1.5 py-0 text-[10px]">
                                  已装{probe[it.id]?.detail ? ` · ${probe[it.id]?.detail}` : ""}
                                </Badge>
                              ) : st === "missing" ? (
                                <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
                                  未装
                                </Badge>
                              ) : null}
                            </div>
                            <div className="truncate text-xs text-muted-foreground" title={it.why}>
                              {it.why}
                            </div>
                            <div className="text-[10px] text-muted-foreground/70">
                              {it.license}
                              {it.needs && it.needs.length > 0 ? ` · 依赖 ${it.needs.join("/")}` : ""}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button onClick={apply} disabled={busy || running || !dirty}>
                {running ? "构建中…" : "应用"}
              </Button>
              <Button variant="outline" onClick={runProbe} disabled={busy || running}>
                检测已装
              </Button>
              <span className="text-xs text-muted-foreground">
                已选 {sel.length} 项 · 约 {totalMB}MB
                {dirty ? " · 有未应用的修改" : " · 与当前镜像一致"}
              </span>
            </div>

            {error ? (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
                {error}
              </div>
            ) : null}

            {lines.length > 0 ? (
              <div>
                <div className="mb-1 text-xs text-muted-foreground">构建日志</div>
                <pre
                  ref={logRef}
                  className="max-h-56 overflow-auto rounded-md border bg-muted/40 p-2 text-[11px] leading-relaxed"
                >
                  {lines.join("\n")}
                </pre>
              </div>
            ) : null}

            <p className="text-xs text-muted-foreground">
              说明：镜像构建完成后，<strong>新启动的任务容器</strong>会自动使用新镜像；
              已在跑的容器不受影响（常驻容器模式需要手动重建）。
              组件全部装进容器，宿主环境保持干净。
            </p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
