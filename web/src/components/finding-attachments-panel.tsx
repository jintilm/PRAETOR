"use client";

import * as React from "react";

import { ArrowDownIcon, ArrowUpIcon, DownloadIcon, EyeIcon, ImagePlusIcon, PencilIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { FindingAttachment, FindingAttachmentKind, TrafficEvidenceRole } from "@/lib/types";

const KINDS: Record<"screenshot" | "burp_screenshot", string> = {
  screenshot: "页面截图",
  burp_screenshot: "Burp 截图",
};

const ROLES: Record<TrafficEvidenceRole, string> = {
  baseline: "正常对照",
  proof: "漏洞证明",
  verification: "补充验证",
  supporting: "辅助证据",
};

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function FindingAttachmentsPanel({
  findingId,
  contextTask,
  readOnly,
  evidenceVersion,
  onChanged,
}: {
  findingId: string;
  contextTask?: string;
  readOnly?: boolean;
  evidenceVersion?: number;
  onChanged: () => void;
}) {
  const [items, setItems] = React.useState<FindingAttachment[] | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [reload, setReload] = React.useState(0);
  const [file, setFile] = React.useState<File | null>(null);
  const [kind, setKind] = React.useState<"screenshot" | "burp_screenshot">("screenshot");
  const [role, setRole] = React.useState<TrafficEvidenceRole>("proof");
  const [caption, setCaption] = React.useState("");
  const [preview, setPreview] = React.useState<FindingAttachment | null>(null);
  const [editing, setEditing] = React.useState<FindingAttachment | null>(null);
  const [editCaption, setEditCaption] = React.useState("");
  const [editRole, setEditRole] = React.useState<TrafficEvidenceRole>("supporting");
  const [previews, setPreviews] = React.useState<Record<number, string>>({});
  const fileRef = React.useRef<HTMLInputElement>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: retry token intentionally reloads the list.
  React.useEffect(() => {
    let active = true;
    setItems(null);
    setError("");
    api
      .findingAttachments(findingId, contextTask)
      .then((value) => {
        if (active) setItems(value);
      })
      .catch((e: Error) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [findingId, contextTask, reload]);

  React.useEffect(() => {
    let active = true;
    const urls: string[] = [];
    const next: Record<number, string> = {};
    if (!items?.length) {
      setPreviews({});
      return;
    }
    void Promise.all(
      items.map(async (item) => {
        try {
          const blob = await api.findingAttachmentBlob(findingId, item.id, contextTask);
          const url = URL.createObjectURL(blob);
          urls.push(url);
          next[item.id] = url;
        } catch {
          // The list still renders; the card shows a stable unavailable state.
        }
      }),
    ).then(() => {
      if (active) setPreviews(next);
    });
    return () => {
      active = false;
      for (const url of urls) URL.revokeObjectURL(url);
    };
  }, [items, findingId, contextTask]);

  async function refresh(message?: string) {
    setBusy(true);
    try {
      setItems(await api.findingAttachments(findingId, contextTask));
      onChanged();
      if (message) toast.success(message);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function upload() {
    if (!file || busy) return;
    setBusy(true);
    try {
      await api.uploadFindingAttachment(
        findingId,
        file,
        { kind, source: "manual_upload", role, caption },
        contextTask,
      );
      setFile(null);
      setCaption("");
      if (fileRef.current) fileRef.current.value = "";
      await refresh("截图已附加");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function download(item: FindingAttachment) {
    try {
      const blob = await api.findingAttachmentBlob(findingId, item.id, contextTask);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = item.filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function remove(item: FindingAttachment) {
    if (busy) return;
    setBusy(true);
    try {
      await api.deleteFindingAttachment(findingId, item.id, evidenceVersion, contextTask);
      await refresh("附件已删除");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function move(index: number, delta: number) {
    if (!items || busy) return;
    const ids = items.map((item) => item.id);
    [ids[index], ids[index + delta]] = [ids[index + delta], ids[index]];
    setBusy(true);
    try {
      const result = await api.reorderFindingAttachments(findingId, ids, evidenceVersion, contextTask);
      setItems(result.attachments ?? []);
      onChanged();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function saveEdit() {
    if (!editing || busy) return;
    setBusy(true);
    try {
      await api.updateFindingAttachment(
        findingId,
        editing.id,
        { version: evidenceVersion, caption: editCaption, role: editRole },
        contextTask,
      );
      setEditing(null);
      await refresh("附件说明已更新");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle>证据附件 {items ? `(${items.length})` : ""}</CardTitle>
            {readOnly ? <Badge variant="outline">继承证据 · 只读</Badge> : null}
          </div>
          <CardDescription>PNG / JPEG，单张不超过 20 MB {readOnly ? "" : "· 支持页面截图与 Burp 截图"}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {error ? (
            <Alert variant="destructive">
              <AlertDescription>
                {error}
                <Button variant="link" onClick={() => setReload((n) => n + 1)}>
                  重试
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}

          {!readOnly ? (
            <div className="grid gap-2 rounded-md border p-3 md:grid-cols-[minmax(0,1fr)_150px_150px_auto]">
              <div className="flex min-w-0 flex-col gap-1">
                <Input
                  ref={fileRef}
                  type="file"
                  accept="image/png,image/jpeg"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                  aria-label="选择截图"
                />
                <Input
                  value={caption}
                  onChange={(e) => setCaption(e.target.value)}
                  placeholder="说明（可选）"
                  aria-label="截图说明"
                />
              </div>
              <Select value={kind} onValueChange={(v) => setKind(v as "screenshot" | "burp_screenshot")}>
                <SelectTrigger aria-label="截图类型">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {Object.entries(KINDS).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
              <Select value={role} onValueChange={(v) => setRole(v as TrafficEvidenceRole)}>
                <SelectTrigger aria-label="证据用途">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {Object.entries(ROLES).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
              <Button disabled={!file || busy} onClick={() => void upload()}>
                <ImagePlusIcon data-icon="inline-start" />
                上传
              </Button>
            </div>
          ) : null}

          {!items ? (
            <Skeleton className="h-32 w-full" />
          ) : items.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>暂无截图附件</EmptyTitle>
                <EmptyDescription>页面截图和 Burp 截图会随报告和证据包一起导出。</EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {items.map((item, index) => (
                <div key={item.id} className="flex min-w-0 flex-col overflow-hidden rounded-md border">
                  <button
                    type="button"
                    className="flex aspect-video w-full items-center justify-center overflow-hidden bg-muted text-muted-foreground"
                    onClick={() => setPreview(item)}
                    aria-label={`预览 ${item.filename}`}
                  >
                    {previews[item.id] ? (
                      // Local authenticated blob URL; never a remote URL.
                      <img src={previews[item.id]} alt={item.caption || item.filename} className="h-full w-full object-contain" />
                    ) : (
                      <EyeIcon className="size-5" />
                    )}
                  </button>
                  <div className="flex min-w-0 flex-1 flex-col gap-1.5 p-2.5">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge variant={item.kind === "burp_screenshot" ? "secondary" : "outline"}>
                        {item.kind === "burp_screenshot" ? "Burp" : "页面"}
                      </Badge>
                      <Badge variant="outline">{ROLES[item.role] ?? item.role}</Badge>
                    </div>
                    <p className="truncate text-xs font-medium" title={item.caption || item.filename}>
                      {item.caption || item.filename}
                    </p>
                    <p className="text-[11px] text-muted-foreground">
                      {fmtBytes(item.size)} · {item.source}
                    </p>
                    <div className="mt-auto flex flex-wrap items-center gap-1">
                      <Button variant="ghost" size="icon-sm" aria-label="下载附件" onClick={() => void download(item)}>
                        <DownloadIcon />
                      </Button>
                      {!readOnly ? (
                        <>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label="编辑附件"
                            onClick={() => {
                              setEditing(item);
                              setEditCaption(item.caption);
                              setEditRole(item.role);
                            }}
                          >
                            <PencilIcon />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label="上移附件"
                            disabled={busy || index === 0}
                            onClick={() => void move(index, -1)}
                          >
                            <ArrowUpIcon />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label="下移附件"
                            disabled={busy || index === items.length - 1}
                            onClick={() => void move(index, 1)}
                          >
                            <ArrowDownIcon />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label="删除附件"
                            disabled={busy}
                            onClick={() => void remove(item)}
                          >
                            <Trash2Icon />
                          </Button>
                        </>
                      ) : null}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={preview !== null} onOpenChange={(open) => !open && setPreview(null)}>
        <DialogContent className="max-w-5xl">
          <DialogHeader>
            <DialogTitle>{preview?.caption || preview?.filename || "截图预览"}</DialogTitle>
            <DialogDescription>{preview?.filename}</DialogDescription>
          </DialogHeader>
          {preview && previews[preview.id] ? (
            <img src={previews[preview.id]} alt={preview.caption || preview.filename} className="max-h-[72vh] w-full object-contain" />
          ) : null}
          <DialogFooter>
            {preview ? (
              <Button variant="outline" onClick={() => void download(preview)}>
                <DownloadIcon data-icon="inline-start" />
                下载原图
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={editing !== null} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>编辑附件</DialogTitle>
            <DialogDescription>{editing?.filename}</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="attachment-role">用途</FieldLabel>
              <Select value={editRole} onValueChange={(v) => setEditRole(v as TrafficEvidenceRole)}>
                <SelectTrigger id="attachment-role">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {Object.entries(ROLES).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </Field>
            <Field>
              <FieldLabel htmlFor="attachment-caption">说明</FieldLabel>
              <Input id="attachment-caption" value={editCaption} onChange={(e) => setEditCaption(e.target.value)} />
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button variant="outline" disabled={busy} onClick={() => setEditing(null)}>
              取消
            </Button>
            <Button disabled={busy} onClick={() => void saveEdit()}>
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// Keep the imported union visible to TypeScript when this component is copied
// into pages that only use the kind labels.
export type { FindingAttachmentKind };
