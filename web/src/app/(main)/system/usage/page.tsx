"use client";

import * as React from "react";
import { Loader2Icon, RefreshCwIcon } from "lucide-react";

import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type { UsageBucket, UsageSummary } from "@/lib/types";

// 用量成本页（P1-5 的前端缺口）。
//
// 这一页刻意同时显示三列：名义输入、缓存命中率、全价等价。
// 只看第一列会把成本算反——实测同一个模型在不同供应商上 cache 命中率从 0% 到 98.8%，
// 名义 token 高的那个可能反而更便宜（见 docs/toolface-trim-2026-10-30.md §5）。

function fmtTok(n: number): string {
  if (!n) return "0";
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
}

function Metric({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <Card className="p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {hint ? <div className="mt-1 text-[11px] text-muted-foreground">{hint}</div> : null}
    </Card>
  );
}

function BucketTable({
  title,
  rows,
  keyLabel,
  taskKeys = false,
}: {
  title: string;
  rows: UsageBucket[];
  keyLabel: string;
  taskKeys?: boolean;
}) {
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div className="text-sm font-medium">{title}</div>
        <div className="text-xs text-muted-foreground">{rows.length} 项</div>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[28%]">{keyLabel}</TableHead>
            <TableHead className="text-right">调用</TableHead>
            <TableHead className="text-right">输入</TableHead>
            <TableHead className="text-right">输出</TableHead>
            <TableHead className="text-right">缓存命中</TableHead>
            <TableHead className="text-right">全价等价</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                没有数据
              </TableCell>
            </TableRow>
          ) : (
            rows.map((b) => (
              <TableRow key={b.key || "(empty)"}>
                <TableCell className="font-mono text-xs">
                  {b.key ? (taskKeys ? `#${b.key}` : b.key) : "（主泳道）"}
                </TableCell>
                <TableCell className="text-right tabular-nums">{b.calls}</TableCell>
                <TableCell className="text-right tabular-nums">{fmtTok(b.input_tokens)}</TableCell>
                <TableCell className="text-right tabular-nums">{fmtTok(b.output_tokens)}</TableCell>
                <TableCell
                  className={cn(
                    "text-right tabular-nums",
                    b.cache_pct >= 80 && "text-emerald-600 dark:text-emerald-400",
                    b.cache_pct > 0 && b.cache_pct < 30 && "text-amber-600 dark:text-amber-400",
                  )}
                >
                  {b.cache_pct.toFixed(1)}%
                </TableCell>
                <TableCell className="text-right font-medium tabular-nums">{fmtTok(b.full_price_equiv)}</TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </Card>
  );
}

export default function UsagePage() {
  const [days, setDays] = React.useState(7);
  const [data, setData] = React.useState<UsageSummary | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState("");

  const load = React.useCallback(async (d: number) => {
    setLoading(true);
    setErr("");
    try {
      setData(await api.usageSummary(d));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load(days);
  }, [days, load]);

  const total = data?.total;

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">用量成本</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            全价等价 = （输入 − 缓存命中）+ 缓存命中 × 0.1。用于横向比较，不是账单金额。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={String(days)} onValueChange={(v) => setDays(Number(v))}>
            <SelectTrigger className="h-9 w-[120px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1">最近 1 天</SelectItem>
              <SelectItem value="7">最近 7 天</SelectItem>
              <SelectItem value="30">最近 30 天</SelectItem>
              <SelectItem value="90">最近 90 天</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => void load(days)} disabled={loading}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            <span className="ml-1.5">刷新</span>
          </Button>
        </div>
      </div>

      {err ? (
        <Card className="border-destructive/40 p-4 text-sm text-destructive">加载失败：{err}</Card>
      ) : null}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="模型调用" value={total ? String(total.calls) : "—"} />
        <Metric label="名义输入 token" value={total ? fmtTok(total.input_tokens) : "—"} hint="供应商 usage 口径" />
        <Metric
          label="缓存命中率"
          value={total ? `${total.cache_pct.toFixed(1)}%` : "—"}
          hint="低命中意味着同样的活更贵"
        />
        <Metric label="全价等价" value={total ? fmtTok(total.full_price_equiv) : "—"} hint="缓存按 1/10 计价" />
      </div>

      {loading && !data ? (
        <Card className="flex items-center gap-2 p-6 text-sm text-muted-foreground">
          <Loader2Icon className="size-4 animate-spin" /> 加载中…
        </Card>
      ) : null}

      {data ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <BucketTable title="按角色（agent_type）" rows={data.by_agent_type} keyLabel="角色" />
          <BucketTable title="按泳道（worker）" rows={data.by_worker} keyLabel="泳道" />
          <div className="xl:col-span-2">
            <BucketTable title="按任务（Top 15）" rows={data.by_task} keyLabel="任务" taskKeys />
          </div>
        </div>
      ) : null}
    </div>
  );
}
