"use client";

import * as React from "react";

import { CheckCircle2Icon, RefreshCwIcon, SaveIcon, TrophyIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

import { api } from "@/lib/api";

// CTF 面板：题面/判分配置 + 竞速看板（P2-6「先做哪题、何时放弃」）+ 提交记录。
// 只对 domain=ctf 的任务显示（详情页按 task.domain 决定是否注册此 tab）。
//
// 数据全部来自后端同一份计算（board 与 agent 的 ctf_board 工具同源），面板不做二次推断——
// 否则"人以为它在做 A、其实它在磨 B"这种偏差没法解释。

type CTFConfig = {
  task_id: string;
  challenge_dir?: string;
  expected_flag?: string;
  challenge_ready: boolean;
  submitter_ready: boolean;
};

type BoardEntry = {
  id: string;
  name?: string;
  category?: string;
  points: number;
  state: string;
  action: string;
  est_tokens?: number;
  spent_tokens?: number;
  reason?: string;
};

type Board = {
  strategy: string;
  recommend?: string;
  note?: string;
  token_left?: number;
  exhausted?: boolean;
  todo?: BoardEntry[];
  give_up?: { id: string; name?: string; points: number; reason?: string }[];
  solved?: string[];
};

type Submission = { flag: string; verdict: string; challenge_id?: string; created_at?: string };

const VERDICT_TONE: Record<string, string> = {
  accepted: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  duplicate: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  wrong: "bg-rose-500/15 text-rose-600 dark:text-rose-400",
};

const STATE_TONE: Record<string, string> = {
  new: "bg-slate-500/15 text-slate-600 dark:text-slate-300",
  active: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  solved: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  abandoned: "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400",
};

export function CtfTab({ taskId }: { taskId: string }) {
  const [cfg, setCfg] = React.useState<CTFConfig | null>(null);
  const [board, setBoard] = React.useState<Board | null>(null);
  const [subs, setSubs] = React.useState<Submission[]>([]);
  const [solved, setSolved] = React.useState(false);
  const [dir, setDir] = React.useState("");
  const [flag, setFlag] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const [c, b, s] = await Promise.all([
        api.taskCTFConfig(taskId),
        api.ctfBoard(taskId).catch(() => null),
        api.ctfSubmissions(taskId).catch(() => null),
      ]);
      setCfg(c);
      setDir(c.challenge_dir ?? "");
      setFlag(c.expected_flag ?? "");
      setBoard(b);
      if (s) {
        setSubs(s.submissions ?? []);
        setSolved(s.solved);
      }
    } catch (e) {
      toast.error("读取 CTF 配置失败：" + (e as Error).message);
    } finally {
      setLoaded(true);
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 15000); // 看板随任务推进变化，轻轮询
    return () => clearInterval(t);
  }, [load]);

  async function save() {
    setSaving(true);
    try {
      await api.saveTaskCTFConfig(taskId, { challengeDir: dir, expectedFlag: flag });
      toast.success("CTF 配置已保存");
      await load();
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (!loaded) {
    return (
      <div className="grid gap-3">
        <Skeleton className="h-24" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      {/* 配置 */}
      <Card>
        <CardContent className="grid gap-3 p-4">
          <div className="flex items-center gap-2 text-sm font-medium">
            题面与判分配置
            {cfg?.challenge_ready && (
              <Badge variant="outline" className="text-emerald-600 dark:text-emerald-400">
                题面就绪
              </Badge>
            )}
            {solved && (
              <Badge className="gap-1 bg-emerald-500 text-white">
                <TrophyIcon className="size-3" /> 已解出
              </Badge>
            )}
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="grid gap-1.5">
              <label className="text-xs text-muted-foreground" htmlFor="ctf-challenge-dir">
                题面目录（离线题库路径；在线 CTFd 留空）
              </label>
              <Input
                id="ctf-challenge-dir"
                value={dir}
                onChange={(e) => setDir(e.target.value)}
                placeholder="如 E:/corpus/ctf/very-easy-delulu"
              />
            </div>
            <div className="grid gap-1.5">
              <label className="text-xs text-muted-foreground" htmlFor="ctf-expected-flag">
                正确 flag（形如 flag{"{"}...{"}"}；留空=不判分）
              </label>
              <Input
                id="ctf-expected-flag"
                value={flag}
                onChange={(e) => setFlag(e.target.value)}
                placeholder="flag{...}"
              />
            </div>
          </div>
          <div>
            <Button size="sm" onClick={save} disabled={saving}>
              {saving ? <RefreshCwIcon className="size-4 animate-spin" /> : <SaveIcon className="size-4" />}
              保存配置
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 竞速看板 */}
      <Card>
        <CardContent className="grid gap-3 p-4">
          <div className="flex flex-wrap items-center gap-2 text-sm font-medium">
            竞速看板
            {board?.strategy && <Badge variant="outline">{board.strategy === "value-first" ? "分值优先" : "易题优先"}</Badge>}
            {typeof board?.token_left === "number" && (
              <span className="text-xs text-muted-foreground">剩余预算 {board.token_left.toLocaleString()} tokens</span>
            )}
            {board?.exhausted && <Badge className="bg-rose-500 text-white">预算耗尽</Badge>}
          </div>
          {board?.recommend && (
            <p className="rounded-md bg-muted px-3 py-2 text-xs">
              <span className="font-medium">建议：</span>
              {board.recommend}
              {board.note ? ` — ${board.note}` : ""}
            </p>
          )}
          {board?.todo && board.todo.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>题目</TableHead>
                  <TableHead className="w-20">分值</TableHead>
                  <TableHead className="w-24">状态</TableHead>
                  <TableHead className="w-24">建议动作</TableHead>
                  <TableHead className="w-28">预估/已耗 tokens</TableHead>
                  <TableHead>原因</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {board.todo.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="max-w-56 truncate font-medium">{e.name || e.id}</TableCell>
                    <TableCell>{e.points}</TableCell>
                    <TableCell>
                      <span className={`rounded-sm px-1.5 py-0.5 text-xs ${STATE_TONE[e.state] ?? ""}`}>{e.state}</span>
                    </TableCell>
                    <TableCell className="text-xs">{e.action}</TableCell>
                    <TableCell className="text-xs tabular-nums">
                      {e.est_tokens ?? 0} / {e.spent_tokens ?? 0}
                    </TableCell>
                    <TableCell className="max-w-72 truncate text-xs text-muted-foreground" title={e.reason}>
                      {e.reason}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {board?.give_up && board.give_up.length > 0 && (
            <div className="grid gap-1 text-xs text-muted-foreground">
              <span className="font-medium text-foreground">已建议放弃：</span>
              {board.give_up.map((e) => (
                <span key={e.id}>
                  {e.name || e.id}
                  {e.reason ? `（${e.reason}）` : ""}
                </span>
              ))}
            </div>
          )}
          {board?.solved && board.solved.length > 0 && (
            <div className="flex flex-wrap items-center gap-1 text-xs">
              <CheckCircle2Icon className="size-3.5 text-emerald-500" />
              {board.solved.map((id) => (
                <Badge key={id} variant="outline">
                  {id}
                </Badge>
              ))}
            </div>
          )}
          {!board && (
            <p className="text-xs text-muted-foreground">
              看板不可用：需先配置题面来源（离线 challenge_dir 或在线 CTFd），且任务领域必须是 ctf。
            </p>
          )}
        </CardContent>
      </Card>

      {/* 提交记录 */}
      <Card>
        <CardContent className="grid gap-2 p-4">
          <div className="text-sm font-medium">提交记录（{subs.length}）</div>
          {subs.length === 0 ? (
            <p className="text-xs text-muted-foreground">还没有提交过 flag。</p>
          ) : (
            <div className="grid gap-1.5">
              {subs.map((s, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className={`rounded-sm px-1.5 py-0.5 font-medium ${VERDICT_TONE[s.verdict] ?? "bg-muted"}`}>
                    {s.verdict}
                  </span>
                  <code className="max-w-96 truncate rounded bg-muted px-1.5 py-0.5">{s.flag}</code>
                  {s.created_at && <span className="text-muted-foreground">{s.created_at}</span>}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
