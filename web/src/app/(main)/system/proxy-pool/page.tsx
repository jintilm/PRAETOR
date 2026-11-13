"use client";

import * as React from "react";

import {
  ActivityIcon,
  AlertTriangleIcon,
  CheckCircle2Icon,
  CircleHelpIcon,
  DownloadIcon,
  Globe2Icon,
  NetworkIcon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  ServerIcon,
  ShieldAlertIcon,
  Trash2Icon,
  XCircleIcon,
} from "lucide-react";
import { toast } from "sonner";

import { TablePagination } from "@/components/table-pagination";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  ProxyPoolConfig,
  ProxyPoolEntry,
  ProxyPoolResponse,
  ProxyPoolRun,
  ProxyPoolSource,
  ProxyPoolStats,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const EMPTY_STATS: ProxyPoolStats = {
  total: 0,
  enabled: 0,
  healthy: 0,
  unhealthy: 0,
  quarantine: 0,
  unknown: 0,
  sources: 0,
};

const EMPTY_DATA: ProxyPoolResponse = {
  entries: [],
  total: 0,
  page: 1,
  page_size: 20,
  stats: EMPTY_STATS,
  config: {
    enabled: true,
    route_mode: "pool",
    fallback_mode: "system",
    auto_collect: true,
    auto_check: true,
    sources_via_system: true,
    collect_interval_minutes: 360,
    check_interval_minutes: 30,
    probe_url: "https://api.ipify.org?format=json",
    timeout_seconds: 8,
    concurrency: 20,
    max_entries: 2000,
    failure_threshold: 3,
  },
  selected_proxy: "",
  route_mode: "pool",
  effective_egress: "",
  running: false,
  last_error: "",
  sources: [],
  runs: [],
};

const STATUS_META: Record<string, { label: string; className: string }> = {
  healthy: {
    label: "健康",
    className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  },
  unhealthy: { label: "异常", className: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300" },
  quarantine: { label: "隔离", className: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300" },
  unknown: { label: "未检测", className: "text-muted-foreground" },
};

const ROUTE_LABEL: Record<string, string> = {
  pool: "代理池优先",
  system: "系统代理",
  direct: "直连",
};

function fmtTime(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("zh-CN", { hour12: false });
}

function statusBadge(status: string) {
  const meta = STATUS_META[status] ?? STATUS_META.unknown;
  return (
    <Badge variant="outline" className={meta.className}>
      {meta.label}
    </Badge>
  );
}

function runSummary(run: ProxyPoolRun) {
  if (run.kind === "collect") return "采集 " + run.imported + " 条";
  if (run.kind === "check") return "检查 " + run.checked + " 条 · 健康 " + run.healthy;
  return run.kind + " · 导入 " + run.imported + " · 检查 " + run.checked;
}

export default function ProxyPoolPage() {
  const [data, setData] = React.useState<ProxyPoolResponse>(EMPTY_DATA);
  const [config, setConfig] = React.useState<ProxyPoolConfig>(EMPTY_DATA.config);
  const [loading, setLoading] = React.useState(true);
  const [savingConfig, setSavingConfig] = React.useState(false);
  const [action, setAction] = React.useState<string | null>(null);
  const [checkingIDs, setCheckingIDs] = React.useState<Set<number>>(new Set());

  const [search, setSearch] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [status, setStatus] = React.useState("all");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);

  const [importOpen, setImportOpen] = React.useState(false);
  const [importText, setImportText] = React.useState("");
  const [importProtocol, setImportProtocol] = React.useState("auto");
  const [importRegion, setImportRegion] = React.useState("");

  const [sourceOpen, setSourceOpen] = React.useState(false);
  const [sourceForm, setSourceForm] = React.useState({ name: "", url: "", region: "global", protocol: "http" });

  const load = React.useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const next = await api.proxyPool({
          status: status === "all" ? "" : status,
          q: query,
          page,
          pageSize,
        });
        setData(next);
        setConfig(next.config);
      } catch (error) {
        if (!silent) toast.error("代理池加载失败：" + (error as Error).message);
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [page, pageSize, query, status],
  );

  React.useEffect(() => {
    void load();
  }, [load]);

  React.useEffect(() => {
    const timer = window.setTimeout(() => {
      setPage(1);
      setQuery(search.trim());
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search]);

  // 后台采集/探测可能持续数分钟。只在运行时轮询，空闲时不打扰后端。
  React.useEffect(() => {
    if (!data.running) return;
    const timer = window.setInterval(() => void load(true), 3000);
    return () => window.clearInterval(timer);
  }, [data.running, load]);

  function setCfg<K extends keyof ProxyPoolConfig>(key: K, value: ProxyPoolConfig[K]) {
    setConfig((current) => ({ ...current, [key]: value }));
  }

  async function saveConfig() {
    if (savingConfig) return;
    setSavingConfig(true);
    try {
      const saved = await api.updateProxyPoolConfig(config);
      setConfig(saved.config);
      setData((current) => ({
        ...current,
        config: saved.config,
        selected_proxy: saved.selected_proxy,
        effective_egress: saved.effective_egress,
        route_mode: saved.config.route_mode,
      }));
      toast.success("代理池配置已保存，新 Agent/容器按新出口生效");
      await load(true);
    } catch (error) {
      toast.error("保存失败：" + (error as Error).message);
    } finally {
      setSavingConfig(false);
    }
  }

  async function runAction(kind: "refresh" | "check") {
    if (action) return;
    setAction(kind);
    try {
      if (kind === "refresh") await api.proxyPoolRefresh();
      else await api.proxyPoolCheckAll();
      toast.success(kind === "refresh" ? "已开始抓取来源并检测新代理" : "已开始检查代理可用性");
      window.setTimeout(() => void load(true), 900);
    } catch (error) {
      toast.error((error as Error).message);
    } finally {
      setAction(null);
    }
  }

  async function toggleEntry(entry: ProxyPoolEntry, enabled: boolean) {
    try {
      await api.proxyPoolPatchEntry(entry.id, enabled);
      toast.success(enabled ? "代理已启用" : "代理已禁用");
      await load(true);
    } catch (error) {
      toast.error("更新失败：" + (error as Error).message);
    }
  }

  async function checkEntry(entry: ProxyPoolEntry) {
    setCheckingIDs((current) => new Set(current).add(entry.id));
    try {
      const result = await api.proxyPoolCheckEntry(entry.id);
      toast.success(result.entry?.status === "healthy" ? "代理可用" : "代理检测完成");
      await load(true);
    } catch (error) {
      toast.error("检测失败：" + (error as Error).message);
    } finally {
      setCheckingIDs((current) => {
        const next = new Set(current);
        next.delete(entry.id);
        return next;
      });
    }
  }

  async function deleteEntry(entry: ProxyPoolEntry) {
    if (!window.confirm("删除代理 " + entry.host + ":" + entry.port + "？该条目的历史健康数据会一并删除。")) return;
    try {
      await api.proxyPoolDeleteEntry(entry.id);
      toast.success("代理已删除");
      await load(true);
    } catch (error) {
      toast.error("删除失败：" + (error as Error).message);
    }
  }

  async function importProxies() {
    if (!importText.trim()) {
      toast.error("请粘贴代理列表");
      return;
    }
    setAction("import");
    try {
      const result = await api.proxyPoolImport({
        text: importText,
        protocol: importProtocol === "auto" ? "" : importProtocol,
        region: importRegion.trim(),
        source: "manual",
      });
      toast.success("解析 " + result.parsed + " 条，新导入 " + result.imported + " 条");
      setImportOpen(false);
      setImportText("");
      await load(true);
    } catch (error) {
      toast.error("导入失败：" + (error as Error).message);
    } finally {
      setAction(null);
    }
  }

  async function createSource() {
    if (!sourceForm.name.trim() || !sourceForm.url.trim()) {
      toast.error("请填写来源名称和 URL");
      return;
    }
    setAction("source");
    try {
      await api.proxyPoolCreateSource(sourceForm);
      toast.success("来源已添加");
      setSourceOpen(false);
      setSourceForm({ name: "", url: "", region: "global", protocol: "http" });
      await load(true);
    } catch (error) {
      toast.error("添加失败：" + (error as Error).message);
    } finally {
      setAction(null);
    }
  }

  async function toggleSource(source: ProxyPoolSource, enabled: boolean) {
    try {
      await api.proxyPoolUpdateSource(source.id, { enabled });
      await load(true);
    } catch (error) {
      toast.error("更新来源失败：" + (error as Error).message);
    }
  }

  async function fetchSource(source: ProxyPoolSource) {
    setAction("source-" + source.id);
    try {
      const result = await api.proxyPoolFetchSource(source.id);
      toast.success(source.name + "：新导入 " + result.imported + " 条");
      await load(true);
    } catch (error) {
      toast.error("抓取失败：" + (error as Error).message);
    } finally {
      setAction(null);
    }
  }

  async function deleteSource(source: ProxyPoolSource) {
    if (!window.confirm("删除来源「" + source.name + "」？已导入的代理条目会保留。")) return;
    try {
      await api.proxyPoolDeleteSource(source.id);
      toast.success("来源已删除");
      await load(true);
    } catch (error) {
      toast.error("删除失败：" + (error as Error).message);
    }
  }

  const stats = data.stats;
  const statCards = [
    { label: "代理条目", value: stats.total, icon: ServerIcon, tone: "text-foreground" },
    { label: "已启用", value: stats.enabled, icon: CheckCircle2Icon, tone: "text-sky-600 dark:text-sky-400" },
    { label: "健康", value: stats.healthy, icon: ActivityIcon, tone: "text-emerald-600 dark:text-emerald-400" },
    {
      label: "隔离 / 异常",
      value: stats.quarantine + stats.unhealthy,
      icon: ShieldAlertIcon,
      tone: "text-amber-600 dark:text-amber-400",
    },
    { label: "采集来源", value: stats.sources, icon: Globe2Icon, tone: "text-foreground" },
  ];

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">代理池</h1>
          <p className="text-muted-foreground text-sm">
            自动采集公开代理、检测可用性，并为 Agent 目标流量选择出口。任务级 egress_upstreams 仍拥有最高优先级。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => void runAction("refresh")}
            disabled={!!action || data.running}
          >
            {action === "refresh" || data.running ? <Spinner /> : <RefreshCwIcon />}
            立即刷新
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void runAction("check")}
            disabled={!!action || data.running}
          >
            {action === "check" ? <Spinner /> : <ActivityIcon />}
            检查全部
          </Button>
          <Button size="sm" onClick={() => setImportOpen(true)}>
            <DownloadIcon /> 手动导入
          </Button>
        </div>
      </div>

      <Alert className="border-amber-500/40 bg-amber-500/5 text-amber-900 dark:text-amber-200">
        <AlertTriangleIcon />
        <AlertTitle>公共代理不可信</AlertTitle>
        <AlertDescription>
          公开代理可能记录、篡改或注入流量。不要通过代理池传输敏感凭据、Cookie
          或内部资料；仅用于已授权的目标侦察与测试。 代理池只影响目标流量，不影响 LLM、网络搜索或宿主的
          HTTP_PROXY/HTTPS_PROXY。
        </AlertDescription>
      </Alert>

      {data.last_error && (
        <Alert variant="destructive">
          <XCircleIcon />
          <AlertTitle>后台任务错误</AlertTitle>
          <AlertDescription>{data.last_error}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {statCards.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.label} className="gap-1 py-4">
              <CardHeader className="px-4">
                <CardDescription>{stat.label}</CardDescription>
                <CardTitle className={cn("flex items-center gap-2 text-2xl tabular-nums", stat.tone)}>
                  <Icon className="size-5" aria-hidden="true" />
                  {stat.value}
                </CardTitle>
              </CardHeader>
            </Card>
          );
        })}
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(380px,0.72fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <NetworkIcon className="size-4" /> 出口路由
            </CardTitle>
            <CardDescription>
              优先级：任务级出口池 → 代理池健康代理 → 系统代理 → 直连。池空时按「池空回落」处理。
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label>路由模式</Label>
                <Select value={config.route_mode} onValueChange={(value) => setCfg("route_mode", value)}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pool">代理池优先</SelectItem>
                    <SelectItem value="system">始终使用系统代理</SelectItem>
                    <SelectItem value="direct">始终直连</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>池空回落</Label>
                <Select value={config.fallback_mode} onValueChange={(value) => setCfg("fallback_mode", value)}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="system">回落系统代理</SelectItem>
                    <SelectItem value="direct">直接连</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-3 text-sm sm:grid-cols-2">
              <div className="rounded-lg border p-3">
                <p className="text-muted-foreground text-xs">当前选中代理</p>
                <p className="mt-1 break-all font-mono text-xs">{data.selected_proxy || "无健康代理"}</p>
              </div>
              <div className="rounded-lg border p-3">
                <p className="text-muted-foreground text-xs">当前有效出口</p>
                <p className="mt-1 break-all font-mono text-xs">{data.effective_egress || "直连（未使用上游代理）"}</p>
                <p className="text-muted-foreground mt-1 text-xs">{ROUTE_LABEL[data.route_mode] ?? data.route_mode}</p>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <ToggleRow
                label="启用代理池"
                description="关闭后不自动采集/检查，出口按系统代理配置。"
                checked={config.enabled}
                onCheckedChange={(checked) => setCfg("enabled", checked)}
              />
              <ToggleRow
                label="自动采集"
                description="按采集间隔抓取所有启用来源。"
                checked={config.auto_collect}
                onCheckedChange={(checked) => setCfg("auto_collect", checked)}
              />
              <ToggleRow
                label="自动检查"
                description="周期性探测代理可用性并更新评分。"
                checked={config.auto_check}
                onCheckedChange={(checked) => setCfg("auto_check", checked)}
              />
              <ToggleRow
                label="来源经系统代理抓取"
                description="访问 GitHub 等来源时复用全局代理；候选探测仍直连各代理。"
                checked={config.sources_via_system}
                onCheckedChange={(checked) => setCfg("sources_via_system", checked)}
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <NumberField
                label="采集间隔（分钟）"
                value={config.collect_interval_minutes}
                min={5}
                max={10080}
                onChange={(value) => setCfg("collect_interval_minutes", value)}
              />
              <NumberField
                label="检查间隔（分钟）"
                value={config.check_interval_minutes}
                min={5}
                max={10080}
                onChange={(value) => setCfg("check_interval_minutes", value)}
              />
              <NumberField
                label="探测超时（秒）"
                value={config.timeout_seconds}
                min={1}
                max={60}
                onChange={(value) => setCfg("timeout_seconds", value)}
              />
              <NumberField
                label="并发数"
                value={config.concurrency}
                min={1}
                max={100}
                onChange={(value) => setCfg("concurrency", value)}
              />
              <NumberField
                label="最大条目"
                value={config.max_entries}
                min={1}
                max={20000}
                onChange={(value) => setCfg("max_entries", value)}
              />
              <NumberField
                label="失败隔离阈值"
                value={config.failure_threshold}
                min={1}
                max={20}
                onChange={(value) => setCfg("failure_threshold", value)}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="proxy-probe-url">探测 URL</Label>
              <Input
                id="proxy-probe-url"
                value={config.probe_url}
                onChange={(event) => setCfg("probe_url", event.target.value)}
                placeholder="https://api.ipify.org?format=json"
              />
              <p className="text-muted-foreground text-xs">
                响应中的 IP 会记录为出口 IP；应选择能稳定返回客户端地址的 HTTPS 端点。
              </p>
            </div>

            <div className="flex items-center justify-between gap-3 border-t pt-4">
              <p className="text-muted-foreground text-xs">
                修改路由后立即更新 MITM；正在运行的 Agent 会在下一次重建后使用新出口。
              </p>
              <Button onClick={() => void saveConfig()} disabled={savingConfig}>
                {savingConfig && <Spinner />} 保存配置
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="min-h-0">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CircleHelpIcon className="size-4" /> 最近运行
            </CardTitle>
            <CardDescription>
              {data.running ? "后台任务运行中，页面会自动刷新。" : "采集与健康检查共用一个互斥任务槽。"}
            </CardDescription>
          </CardHeader>
          <CardContent className="max-h-[520px] overflow-y-auto">
            {data.runs.length === 0 ? (
              <p className="text-muted-foreground py-8 text-center text-sm">暂无运行记录。</p>
            ) : (
              <div className="space-y-2">
                {data.runs.map((run) => (
                  <div key={run.id} className="rounded-lg border p-3 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <Badge variant="outline">{run.kind}</Badge>
                      <span className="text-muted-foreground">{fmtTime(run.started_at)}</span>
                    </div>
                    <p className="mt-2">{runSummary(run)}</p>
                    {run.error && <p className="mt-1 text-red-600 dark:text-red-400">{run.error}</p>}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="gap-0 overflow-hidden py-0">
        <CardHeader className="gap-3 border-b py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <CardTitle>代理条目</CardTitle>
              <CardDescription>健康代理按评分和延迟排序；被隔离的代理不会参与路由。</CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <SearchIcon className="text-muted-foreground pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2" />
                <Input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="搜索 host / 地区 / 来源"
                  className="h-8 w-60 pl-8"
                />
              </div>
              <Select
                value={status}
                onValueChange={(value) => {
                  setPage(1);
                  setStatus(value);
                }}
              >
                <SelectTrigger size="sm" className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部状态</SelectItem>
                  <SelectItem value="healthy">健康</SelectItem>
                  <SelectItem value="unknown">未检测</SelectItem>
                  <SelectItem value="unhealthy">异常</SelectItem>
                  <SelectItem value="quarantine">隔离</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-56 pl-4">代理</TableHead>
                <TableHead className="w-24">状态</TableHead>
                <TableHead className="w-20">协议</TableHead>
                <TableHead className="w-20">延迟</TableHead>
                <TableHead className="w-20">评分</TableHead>
                <TableHead className="w-24">成功率</TableHead>
                <TableHead className="w-36">来源 / 地区</TableHead>
                <TableHead className="w-40">最后检测</TableHead>
                <TableHead className="w-32 pr-4 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={9} className="h-40 text-center">
                    <Spinner />
                  </TableCell>
                </TableRow>
              ) : data.entries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="h-48 text-center">
                    <div className="text-muted-foreground mx-auto flex max-w-md flex-col items-center gap-2">
                      <NetworkIcon className="size-8" />
                      <p className="text-foreground font-medium">代理池为空</p>
                      <p className="text-xs leading-relaxed">
                        点「立即刷新」抓取默认公开来源，或手动导入。首次采集后会自动检测新条目。
                      </p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                data.entries.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="pl-4">
                      <div className="flex min-w-0 flex-col gap-0.5">
                        <span className="font-mono text-xs">{entry.url}</span>
                        <span className="text-muted-foreground text-xs">
                          {entry.exit_ip ? "出口 IP " + entry.exit_ip : "未知出口 IP"}
                          {entry.last_error ? " · " + entry.last_error : ""}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>{statusBadge(entry.status)}</TableCell>
                    <TableCell className="uppercase">{entry.protocol}</TableCell>
                    <TableCell className="tabular-nums">
                      {entry.latency_ms > 0 ? entry.latency_ms + " ms" : "—"}
                    </TableCell>
                    <TableCell className="tabular-nums">{entry.score}</TableCell>
                    <TableCell className="tabular-nums">
                      {entry.success_count + entry.failure_count > 0 ? Math.round(entry.success_rate * 100) + "%" : "—"}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col text-xs">
                        <span className="truncate">{entry.source || "unknown"}</span>
                        <span className="text-muted-foreground">{entry.region || "global"}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">{fmtTime(entry.last_checked_at)}</TableCell>
                    <TableCell className="pr-4">
                      <div className="flex items-center justify-end gap-1">
                        <Switch
                          checked={entry.enabled}
                          onCheckedChange={(checked) => void toggleEntry(entry, checked)}
                          aria-label="启用代理"
                        />
                        <Button
                          size="icon-sm"
                          variant="ghost"
                          onClick={() => void checkEntry(entry)}
                          disabled={checkingIDs.has(entry.id)}
                          aria-label="检测代理"
                        >
                          {checkingIDs.has(entry.id) ? <Spinner /> : <RefreshCwIcon />}
                        </Button>
                        <Button
                          size="icon-sm"
                          variant="ghost"
                          onClick={() => void deleteEntry(entry)}
                          aria-label="删除代理"
                        >
                          <Trash2Icon className="text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
        <TablePagination
          page={data.page}
          pageSize={data.page_size}
          total={data.total}
          onPageChange={setPage}
          onPageSizeChange={(nextSize) => {
            setPageSize(nextSize);
            setPage(1);
          }}
          pageSizeOptions={[10, 20, 50, 100]}
        />
      </Card>

      <Card className="gap-0 overflow-hidden py-0">
        <CardHeader className="flex flex-row items-center justify-between gap-3 border-b py-4">
          <div>
            <CardTitle>采集来源</CardTitle>
            <CardDescription>国内外公开列表均可添加；抓取失败只影响当前来源，不会清空已有代理。</CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => setSourceOpen(true)}>
            <PlusIcon /> 添加来源
          </Button>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-64 pl-4">名称 / URL</TableHead>
                <TableHead className="w-24">地区</TableHead>
                <TableHead className="w-20">协议</TableHead>
                <TableHead className="w-24">导入数</TableHead>
                <TableHead className="w-40">最后抓取</TableHead>
                <TableHead className="w-20">启用</TableHead>
                <TableHead className="w-32 pr-4 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.sources.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-muted-foreground h-32 text-center">
                    暂无采集来源。
                  </TableCell>
                </TableRow>
              ) : (
                data.sources.map((source) => (
                  <TableRow key={source.id}>
                    <TableCell className="pl-4">
                      <div className="flex min-w-0 flex-col gap-0.5">
                        <span className="font-medium">{source.name}</span>
                        <span className="text-muted-foreground max-w-2xl truncate font-mono text-xs">{source.url}</span>
                        {source.last_error && (
                          <span className="text-xs text-red-600 dark:text-red-400">{source.last_error}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>{source.region || "global"}</TableCell>
                    <TableCell className="uppercase">{source.protocol}</TableCell>
                    <TableCell className="tabular-nums">{source.imported_count}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{fmtTime(source.last_fetch_at)}</TableCell>
                    <TableCell>
                      <Switch
                        checked={source.enabled}
                        onCheckedChange={(checked) => void toggleSource(source, checked)}
                        aria-label="启用来源"
                      />
                    </TableCell>
                    <TableCell className="pr-4">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => void fetchSource(source)}
                          disabled={!!action || !source.enabled}
                        >
                          {action === "source-" + source.id ? <Spinner /> : <RefreshCwIcon />}
                          抓取
                        </Button>
                        <Button
                          size="icon-sm"
                          variant="ghost"
                          onClick={() => void deleteSource(source)}
                          aria-label="删除来源"
                        >
                          <Trash2Icon className="text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Sheet open={importOpen} onOpenChange={setImportOpen}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          <SheetHeader>
            <SheetTitle>手动导入代理</SheetTitle>
            <SheetDescription>
              支持每行一条的 URL、host:port、JSON/HTML 列表。缺少 scheme 时按下方默认协议补全。
            </SheetDescription>
          </SheetHeader>
          <div className="grid gap-4 px-4 pb-6">
            <div className="grid gap-2">
              <Label htmlFor="proxy-import-text">代理列表</Label>
              <Textarea
                id="proxy-import-text"
                value={importText}
                onChange={(event) => setImportText(event.target.value)}
                placeholder={"http://1.2.3.4:8080\n5.6.7.8:1080\nsocks5://user:pass@9.9.9.9:1080"}
                className="min-h-64 font-mono text-xs"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label>默认协议</Label>
                <Select value={importProtocol} onValueChange={setImportProtocol}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">自动（host:port → http）</SelectItem>
                    <SelectItem value="http">HTTP</SelectItem>
                    <SelectItem value="https">HTTPS</SelectItem>
                    <SelectItem value="socks5">SOCKS5</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="proxy-import-region">地区标记</Label>
                <Input
                  id="proxy-import-region"
                  value={importRegion}
                  onChange={(event) => setImportRegion(event.target.value)}
                  placeholder="cn / us / global（可留空）"
                />
              </div>
            </div>
            <Button onClick={() => void importProxies()} disabled={action === "import"}>
              {action === "import" && <Spinner />} 导入
            </Button>
          </div>
        </SheetContent>
      </Sheet>

      <Sheet open={sourceOpen} onOpenChange={setSourceOpen}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          <SheetHeader>
            <SheetTitle>添加采集来源</SheetTitle>
            <SheetDescription>来源是返回代理列表的 HTTP/HTTPS 文本、JSON 或 HTML 页面。</SheetDescription>
          </SheetHeader>
          <div className="grid gap-4 px-4 pb-6">
            <div className="grid gap-2">
              <Label htmlFor="source-name">名称</Label>
              <Input
                id="source-name"
                value={sourceForm.name}
                onChange={(event) => setSourceForm((current) => ({ ...current, name: event.target.value }))}
                placeholder="cn-http-list"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="source-url">来源 URL</Label>
              <Input
                id="source-url"
                value={sourceForm.url}
                onChange={(event) => setSourceForm((current) => ({ ...current, url: event.target.value }))}
                placeholder="https://example.com/proxies.txt"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="source-region">地区标记</Label>
                <Input
                  id="source-region"
                  value={sourceForm.region}
                  onChange={(event) => setSourceForm((current) => ({ ...current, region: event.target.value }))}
                  placeholder="cn / us / global"
                />
              </div>
              <div className="grid gap-2">
                <Label>默认协议</Label>
                <Select
                  value={sourceForm.protocol}
                  onValueChange={(value) => setSourceForm((current) => ({ ...current, protocol: value }))}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="http">HTTP</SelectItem>
                    <SelectItem value="https">HTTPS</SelectItem>
                    <SelectItem value="socks5">SOCKS5</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <Button onClick={() => void createSource()} disabled={action === "source"}>
              {action === "source" && <Spinner />} 添加
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function ToggleRow({
  label,
  description,
  checked,
  onCheckedChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border p-3">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="text-muted-foreground mt-0.5 text-xs">{description}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} aria-label={label} />
    </div>
  );
}

function NumberField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <div className="grid gap-2">
      <Label>{label}</Label>
      <Input
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
      />
    </div>
  );
}
