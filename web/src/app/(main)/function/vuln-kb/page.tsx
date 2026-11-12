"use client";

import * as React from "react";

import Link from "next/link";

import {
  BookOpenCheckIcon,
  CheckCircle2Icon,
  DatabaseIcon,
  ExternalLinkIcon,
  RefreshCwIcon,
  SearchIcon,
  ShieldCheckIcon,
  SparklesIcon,
} from "lucide-react";
import { toast } from "sonner";

import { TablePagination } from "@/components/table-pagination";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  VulnKnowledgeDetail,
  VulnKnowledgeItem,
  VulnKnowledgeKind,
  VulnKnowledgePage,
  VulnKnowledgeStats,
  VulnKnowledgeStatus,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const EMPTY_STATS: VulnKnowledgeStats = {
  total: 0,
  candidate: 0,
  active: 0,
  deprecated: 0,
  verified_sources: 0,
  search_uses: 0,
  successful_uses: 0,
  false_positive_uses: 0,
};

const STATUS_META: Record<VulnKnowledgeStatus, { label: string; className: string }> = {
  candidate: { label: "候选", className: "border-amber-500/50 text-amber-600 dark:text-amber-400" },
  active: { label: "已启用", className: "border-emerald-500/50 text-emerald-600 dark:text-emerald-400" },
  deprecated: { label: "已停用", className: "border-muted-foreground/40 text-muted-foreground" },
};

const KIND_META: Record<VulnKnowledgeKind, string> = {
  pattern: "漏洞模式",
  technique: "测试战术",
  negative: "负向记忆",
};

function fmtTime(value?: string) {
  if (!value) return "未验证";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("zh-CN", { hour12: false });
}

function statusBadge(status: VulnKnowledgeStatus) {
  const meta = STATUS_META[status] ?? STATUS_META.candidate;
  return (
    <Badge variant="outline" className={meta.className}>
      {meta.label}
    </Badge>
  );
}

export default function VulnKnowledgePage() {
  const [status, setStatus] = React.useState<"all" | VulnKnowledgeStatus>("all");
  const [kind, setKind] = React.useState<"all" | VulnKnowledgeKind>("all");
  const [search, setSearch] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [data, setData] = React.useState<VulnKnowledgePage>({ items: [], total: 0, page: 1, page_size: 20 });
  const [stats, setStats] = React.useState<VulnKnowledgeStats>(EMPTY_STATS);
  const [loading, setLoading] = React.useState(true);
  const [backfilling, setBackfilling] = React.useState(false);
  const [selected, setSelected] = React.useState<VulnKnowledgeDetail | null>(null);
  const [form, setForm] = React.useState<VulnKnowledgeDetail | null>(null);
  const [technology, setTechnology] = React.useState("");
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [pageData, nextStats] = await Promise.all([
        api.vulnKnowledgePage({ page, pageSize, status, kind, q: query }),
        api.vulnKnowledgeStats(),
      ]);
      setData(pageData);
      setStats(nextStats);
    } catch (error) {
      toast.error(`漏洞知识加载失败：${(error as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [kind, page, pageSize, query, status]);

  React.useEffect(() => {
    const timer = window.setTimeout(() => {
      setPage(1);
      setQuery(search.trim());
    }, 300);
    return () => window.clearTimeout(timer);
  }, [search]);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function openDetail(item: VulnKnowledgeItem) {
    setDetailLoading(true);
    setSelected(null);
    try {
      const detail = await api.vulnKnowledgeDetail(item.id);
      setSelected(detail);
      setForm(detail);
      setTechnology((detail.technology ?? []).join(", "));
    } catch (error) {
      toast.error(`加载知识详情失败：${(error as Error).message}`);
    } finally {
      setDetailLoading(false);
    }
  }

  async function save(statusOverride?: VulnKnowledgeStatus) {
    if (!form || saving) return;
    const nextStatus = statusOverride ?? form.status;
    if (
      nextStatus === "active" &&
      (!form.test_steps.trim() || !form.expected_signals.trim() || !form.false_positive_checks.trim())
    ) {
      toast.error("启用前必须填写测试步骤、预期信号和误报检查");
      return;
    }
    setSaving(true);
    try {
      const updated = await api.updateVulnKnowledge(form.id, {
        version: form.version,
        kind: form.kind,
        title: form.title,
        summary: form.summary,
        vuln_class: form.vuln_class,
        cwe: form.cwe,
        severity: form.severity,
        technology: technology
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        preconditions: form.preconditions,
        test_steps: form.test_steps,
        expected_signals: form.expected_signals,
        false_positive_checks: form.false_positive_checks,
        license: form.license,
        confidence: Number(form.confidence) || 0,
        status: nextStatus,
      });
      setForm(updated);
      setSelected(updated);
      setTechnology((updated.technology ?? []).join(", "));
      toast.success(nextStatus === "active" ? "知识已启用，后续 agent 可检索" : "知识条目已保存");
      await load();
    } catch (error) {
      toast.error(`保存失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function backfill() {
    if (backfilling) return;
    setBackfilling(true);
    try {
      const result = await api.backfillVulnKnowledge();
      toast.success(`已扫描已验证漏洞，处理 ${result.processed} 条来源`);
      await load();
    } catch (error) {
      toast.error(`补扫失败：${(error as Error).message}`);
    } finally {
      setBackfilling(false);
    }
  }

  const canActivate =
    Boolean(form?.test_steps.trim() && form?.expected_signals.trim() && form?.false_positive_checks.trim());
  const sheetOpen = detailLoading || selected !== null;
  const statCards = [
    { label: "知识条目", value: stats.total, icon: DatabaseIcon, tone: "text-foreground" },
    {
      label: "待审核候选",
      value: stats.candidate,
      icon: SparklesIcon,
      tone: "text-amber-600 dark:text-amber-400",
    },
    {
      label: "已启用",
      value: stats.active,
      icon: ShieldCheckIcon,
      tone: "text-emerald-600 dark:text-emerald-400",
    },
    {
      label: "已验证来源",
      value: stats.verified_sources,
      icon: CheckCircle2Icon,
      tone: "text-sky-600 dark:text-sky-400",
    },
  ];

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">漏洞知识库</h1>
          <p className="text-muted-foreground text-sm">
            只沉淀经过确定性验证的漏洞模式。候选条目审核启用后，planner 与 worker 才能检索复用。
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={backfill} disabled={backfilling}>
          {backfilling ? <Spinner data-icon="inline-start" /> : <RefreshCwIcon />}
          {backfilling ? "扫描中" : "补扫已验证漏洞"}
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
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

      <div className="flex flex-wrap items-center gap-2">
        <Tabs value={status} onValueChange={(value) => setStatus(value as "all" | VulnKnowledgeStatus)}>
          <TabsList>
            <TabsTrigger value="all">全部</TabsTrigger>
            <TabsTrigger value="candidate">候选</TabsTrigger>
            <TabsTrigger value="active">已启用</TabsTrigger>
            <TabsTrigger value="deprecated">已停用</TabsTrigger>
          </TabsList>
        </Tabs>
        <Select value={kind} onValueChange={(value) => setKind(value as "all" | VulnKnowledgeKind)}>
          <SelectTrigger size="sm" className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部类型</SelectItem>
            <SelectItem value="pattern">漏洞模式</SelectItem>
            <SelectItem value="technique">测试战术</SelectItem>
            <SelectItem value="negative">负向记忆</SelectItem>
          </SelectContent>
        </Select>
        <InputGroup className="w-full sm:w-80">
          <InputGroupInput
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="检索标题、CWE、测试步骤或误报检查"
            aria-label="检索漏洞知识"
          />
          <InputGroupAddon>
            <SearchIcon />
          </InputGroupAddon>
        </InputGroup>
        <span className="ml-auto text-muted-foreground text-xs tabular-nums">
          检索使用 {stats.search_uses} · 成功 {stats.successful_uses} · 误报 {stats.false_positive_uses}
        </span>
      </div>

      <Card className="gap-0 overflow-hidden py-0">
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-64">知识条目</TableHead>
                <TableHead className="w-28">状态</TableHead>
                <TableHead className="w-28">类型</TableHead>
                <TableHead className="w-36">漏洞类别</TableHead>
                <TableHead className="w-24">置信度</TableHead>
                <TableHead className="w-36">使用 / 成功</TableHead>
                <TableHead className="w-44">更新时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-40 text-center">
                    <Spinner />
                  </TableCell>
                </TableRow>
              ) : data.items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-48 text-center">
                    <div className="mx-auto flex max-w-md flex-col items-center gap-2 text-muted-foreground">
                      <BookOpenCheckIcon className="size-8" />
                      <p className="font-medium text-foreground">暂无匹配知识</p>
                      <p className="text-xs leading-relaxed">
                        先完成漏洞确定性验证，再点「补扫已验证漏洞」生成候选；候选需要人工补全测试步骤后才能启用。
                      </p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                data.items.map((item) => (
                  <TableRow
                    key={item.id}
                    className="cursor-pointer"
                    onClick={() => void openDetail(item)}
                  >
                    <TableCell>
                      <div className="flex min-w-0 flex-col gap-1">
                        <span className="font-medium">{item.title}</span>
                        <span className="line-clamp-2 max-w-3xl text-muted-foreground text-xs">
                          {item.summary || "尚未补充摘要"}
                        </span>
                        {item.technology.length > 0 && (
                          <span className="truncate text-muted-foreground text-xs">
                            {item.technology.join(" · ")}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>{statusBadge(item.status)}</TableCell>
                    <TableCell>{KIND_META[item.kind]}</TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-0.5 text-xs">
                        <span>{item.vuln_class || "未分类"}</span>
                        <span className="text-muted-foreground">{item.cwe || "无 CWE"}</span>
                      </div>
                    </TableCell>
                    <TableCell className="tabular-nums">{item.confidence}%</TableCell>
                    <TableCell className="tabular-nums">
                      {item.usage_count} / {item.success_count}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">{fmtTime(item.updated_at)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <TablePagination
        page={data.page}
        pageSize={data.page_size}
        total={data.total}
        onPageChange={setPage}
        onPageSizeChange={(nextSize) => {
          setPageSize(nextSize);
          setPage(1);
        }}
        pageSizeOptions={[10, 20, 50]}
      />

      <Sheet
        open={sheetOpen}
        onOpenChange={(open) => {
          if (!open && !saving) {
            setSelected(null);
            setForm(null);
          }
        }}
      >
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <BookOpenCheckIcon className="size-5" />
              {form?.title || "知识详情"}
            </SheetTitle>
            <SheetDescription>
              {form
                ? `来源 ${selected?.sources.length ?? 0} 条 finding · 版本 v${form.version}`
                : "正在加载知识详情"}
            </SheetDescription>
          </SheetHeader>

          {detailLoading || !form ? (
            <div className="flex min-h-64 items-center justify-center">
              <Spinner />
            </div>
          ) : (
            <div className="flex flex-col gap-5 px-4 pb-6">
              <div className="flex flex-wrap items-center gap-2">
                {statusBadge(form.status)}
                <Badge variant="outline">{KIND_META[form.kind]}</Badge>
                <Badge variant="outline">{form.confidence}% 置信度</Badge>
                {form.license && <Badge variant="outline">{form.license}</Badge>}
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="标题">
                  <Input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} />
                </Field>
                <Field label="类型">
                  <Select
                    value={form.kind}
                    onValueChange={(value) => setForm({ ...form, kind: value as VulnKnowledgeKind })}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="pattern">漏洞模式</SelectItem>
                      <SelectItem value="technique">测试战术</SelectItem>
                      <SelectItem value="negative">负向记忆</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="漏洞类别">
                  <Input
                    value={form.vuln_class}
                    onChange={(event) => setForm({ ...form, vuln_class: event.target.value })}
                    placeholder="ssti / idor / ssrf"
                  />
                </Field>
                <Field label="CWE">
                  <Input
                    value={form.cwe}
                    onChange={(event) => setForm({ ...form, cwe: event.target.value })}
                    placeholder="CWE-1336"
                  />
                </Field>
                <Field label="严重度">
                  <Input
                    value={form.severity}
                    onChange={(event) => setForm({ ...form, severity: event.target.value })}
                    placeholder="critical / high / medium / low"
                  />
                </Field>
                <Field label="技术栈">
                  <Input
                    value={technology}
                    onChange={(event) => setTechnology(event.target.value)}
                    placeholder="Django, Python, Jinja2"
                  />
                </Field>
                <Field label="置信度">
                  <Input
                    type="number"
                    min={0}
                    max={100}
                    value={form.confidence}
                    onChange={(event) => setForm({ ...form, confidence: Number(event.target.value) || 0 })}
                  />
                </Field>
                <Field label="许可证 / 来源许可">
                  <Input
                    value={form.license}
                    onChange={(event) => setForm({ ...form, license: event.target.value })}
                    placeholder="internal / Apache-2.0 / MIT"
                  />
                </Field>
              </div>

              <Field label="摘要">
                <Textarea
                  value={form.summary}
                  onChange={(event) => setForm({ ...form, summary: event.target.value })}
                  rows={3}
                />
              </Field>
              <Field label="前置条件">
                <Textarea
                  value={form.preconditions}
                  onChange={(event) => setForm({ ...form, preconditions: event.target.value })}
                  rows={3}
                  placeholder="适用版本、鉴权状态、参数位置、所需权限等"
                />
              </Field>
              <Field label="测试步骤">
                <Textarea
                  value={form.test_steps}
                  onChange={(event) => setForm({ ...form, test_steps: event.target.value })}
                  rows={6}
                  placeholder="可复用的检测流程。只写步骤，不粘贴客户敏感数据。"
                />
              </Field>
              <Field label="预期信号">
                <Textarea
                  value={form.expected_signals}
                  onChange={(event) => setForm({ ...form, expected_signals: event.target.value })}
                  rows={4}
                  placeholder="状态码、响应差异、流量特征、文件产物等"
                />
              </Field>
              <Field label="误报检查">
                <Textarea
                  value={form.false_positive_checks}
                  onChange={(event) => setForm({ ...form, false_positive_checks: event.target.value })}
                  rows={4}
                  placeholder="启用前必须验证的排除条件"
                />
              </Field>

              <div className="flex flex-col gap-2 border-t pt-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-medium text-sm">来源证据</p>
                    <p className="text-muted-foreground text-xs">知识条目只能引用已验证 finding，不保存原始流量正文。</p>
                  </div>
                  <span className="text-muted-foreground text-xs tabular-nums">{selected?.sources.length ?? 0} 条</span>
                </div>
                {selected?.sources.length ? (
                  selected.sources.map((source) => (
                    <div
                      key={source.finding_id}
                      className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-sm"
                    >
                      <span className="min-w-0 flex-1 truncate">
                        #{source.finding_id} · {source.finding_name || source.vuln_class || "未命名漏洞"}
                      </span>
                      <span className="text-muted-foreground text-xs">
                        {source.task_name || source.task_description || (source.task_id ? `任务 #${source.task_id}` : "无任务")}
                      </span>
                      <Button size="sm" variant="ghost" asChild>
                        <Link href={`/function/findings/detail?id=${source.finding_id}`}>
                          查看
                          <ExternalLinkIcon data-icon="inline-end" />
                        </Link>
                      </Button>
                    </div>
                  ))
                ) : (
                  <p className="text-muted-foreground text-sm">暂无来源记录。</p>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 border-t pt-4">
                <Select
                  value={form.status}
                  onValueChange={(value) => setForm({ ...form, status: value as VulnKnowledgeStatus })}
                >
                  <SelectTrigger className="w-36">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="candidate">候选</SelectItem>
                    <SelectItem value="active">已启用</SelectItem>
                    <SelectItem value="deprecated">已停用</SelectItem>
                  </SelectContent>
                </Select>
                <Button className="ml-auto" onClick={() => void save()} disabled={saving}>
                  {saving && <Spinner data-icon="inline-start" />}
                  保存
                </Button>
                {form.status !== "active" && (
                  <Button variant="outline" onClick={() => void save("active")} disabled={saving || !canActivate}>
                    <ShieldCheckIcon />
                    审核并启用
                  </Button>
                )}
                {form.status === "active" && (
                  <Button variant="outline" onClick={() => void save("deprecated")} disabled={saving}>
                    停用
                  </Button>
                )}
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-2">
      <Label className="text-sm">{label}</Label>
      {children}
    </div>
  );
}
