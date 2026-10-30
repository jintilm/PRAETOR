"use client";

import * as React from "react";
import Link from "next/link";
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
import type { CtfBoard, CtfBoardRow } from "@/lib/types";

// CTF 逐题进度看板（P2-6 的可见面）。
//
// 数据来自 `ctf_progress`（worker 的 ctf_board 工具读同一张表），这里只是只读出口。
// spent_tokens 是**判题通过那一刻**的快照，不是实时值 —— 所以列名叫"判题时消耗"，
// 避免被当成"这道题现在花了多少"。

function fmtTok(n: number): string {
  if (!n) return "—";
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
}

function fmtTime(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("zh-CN", { hour12: false });
}

function StateBadge({ state }: { state: string }) {
  const solved = state === "solved";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs",
        solved
          ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
          : "bg-muted text-muted-foreground",
      )}
    >
      {solved ? "已解出" : state || "未知"}
    </span>
  );
}

export default function CtfBoardPage() {
  const [data, setData] = React.useState<CtfBoard | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState("");
  const [filter, setFilter] = React.useState("all");

  const load = React.useCallback(async () => {
    setLoading(true);
    setErr("");
    try {
      setData(await api.ctfProgressBoard());
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const rows: CtfBoardRow[] = React.useMemo(() => {
    const all = data?.items ?? [];
    if (filter === "all") return all;
    return all.filter((r) => r.state === filter);
  }, [data, filter]);

  const s = data?.summary;
  const rate = s && s.challenges > 0 ? (s.solved * 100) / s.challenges : 0;

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">CTF 看板</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            逐题进度来自 <code>ctf_progress</code>；「判题时消耗」是判题通过那一刻的快照，不是实时值。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={filter} onValueChange={setFilter}>
            <SelectTrigger className="h-9 w-[130px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部状态</SelectItem>
              <SelectItem value="solved">已解出</SelectItem>
              <SelectItem value="active">进行中</SelectItem>
              <SelectItem value="new">未开始</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
            <span className="ml-1.5">刷新</span>
          </Button>
        </div>
      </div>

      {err ? <Card className="border-destructive/40 p-4 text-sm text-destructive">加载失败：{err}</Card> : null}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Card className="p-4">
          <div className="text-xs text-muted-foreground">题目记录</div>
          <div className="mt-1 text-2xl font-semibold tabular-nums">{s ? s.challenges : "—"}</div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-muted-foreground">已解出</div>
          <div className="mt-1 text-2xl font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
            {s ? s.solved : "—"}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-muted-foreground">解出率</div>
          <div className="mt-1 text-2xl font-semibold tabular-nums">{s ? `${rate.toFixed(0)}%` : "—"}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">按记录条数算，不是按题目去重</div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-muted-foreground">判题时消耗合计</div>
          <div className="mt-1 text-2xl font-semibold tabular-nums">{s ? fmtTok(s.tokens) : "—"}</div>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[80px]">任务</TableHead>
              <TableHead>题目</TableHead>
              <TableHead className="w-[90px]">状态</TableHead>
              <TableHead className="text-right">判题时消耗</TableHead>
              <TableHead className="w-[150px]">更新时间</TableHead>
              <TableHead>目标</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && !data ? (
              <TableRow>
                <TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">
                  <Loader2Icon className="mr-2 inline size-4 animate-spin" />
                  加载中…
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">
                  没有记录
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => (
                <TableRow key={`${r.task_id}-${r.challenge_id}`}>
                  <TableCell className="font-mono text-xs">
                    <Link className="underline-offset-2 hover:underline" href={`/function/tasks/detail?id=${r.task_id}`}>
                      #{r.task_id}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{r.challenge_id || "—"}</TableCell>
                  <TableCell>
                    <StateBadge state={r.state} />
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{fmtTok(r.spent_tokens)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{fmtTime(r.updated_at)}</TableCell>
                  <TableCell className="max-w-[420px] truncate text-xs text-muted-foreground" title={r.task_goal}>
                    {r.task_goal || "—"}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}
