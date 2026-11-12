"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, FileTextIcon } from "lucide-react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import { REPORT_TEMPLATES, reportTemplateLabel, type MobileMeta, type ReportTemplate } from "@/lib/types";
import { copyText } from "@/lib/utils";

export function ReportTab({ taskId }: { taskId: string }) {
  const [report, setReport] = React.useState<string>("");
  const [loading, setLoading] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  // 任务创建时选定的模板（只读展示）；override 是报告页的临时预览切换，不落库。
  const [taskTemplate, setTaskTemplate] = React.useState<ReportTemplate>("praetor");
  const [override, setOverride] = React.useState<ReportTemplate | "task">("task");
  const effective = override === "task" ? taskTemplate : override;
  // 与导出模板取自同一个后端函数，避免页面与提交材料给出不同结论。
  const [mobile, setMobile] = React.useState<MobileMeta | null>(null);

  React.useEffect(() => {
    let active = true;
    api
      .task(taskId)
      .then((t) => {
        if (active) setTaskTemplate(t.report_template ?? "praetor");
      })
      .catch(() => {
        if (active) setTaskTemplate("praetor");
      });
    return () => {
      active = false;
    };
  }, [taskId]);

  React.useEffect(() => {
    api
      .taskMobileMeta(taskId)
      .then(setMobile)
      .catch(() => setMobile(null));
  }, [taskId]);

  React.useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .report(taskId, override === "task" ? undefined : override)
      .then((text) => {
        if (active) setReport(text);
      })
      .catch(() => {
        if (active) setReport("");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [taskId, override]);

  async function copy() {
    if (!report) return;
    const ok = await copyText(report);
    if (ok) {
      setCopied(true);
      toast.success("已复制 Markdown");
      setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error("复制失败，请手动选择文本复制");
    }
  }

  let content: React.ReactNode;
  if (loading) {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        加载中…
      </div>
    );
  } else if (report) {
    content = (
      <div className="max-h-[60vh] overflow-auto rounded-md border bg-muted/20 p-4">
        <Markdown text={report} />
      </div>
    );
  } else {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        暂无报告
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FileTextIcon className="size-4" /> 渗透测试报告（Markdown）
        </CardTitle>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground hidden text-xs sm:inline">
            任务模板：{reportTemplateLabel(taskTemplate)}
          </span>
          <Select value={override} onValueChange={(v) => setOverride(v as ReportTemplate | "task")}>
            <SelectTrigger className="w-44" aria-label="报告输出模板">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="task">沿用任务模板</SelectItem>
              {REPORT_TEMPLATES.map((t) => (
                <SelectItem key={t.value} value={t.value}>
                  {t.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {report && (
            <Button size="sm" variant="outline" onClick={copy}>
              {copied ? <CheckIcon /> : <CopyIcon />} 复制
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-muted-foreground text-xs">
          当前预览：{reportTemplateLabel(effective)}
          {override !== "task" && "（临时切换，不写入任务；发现页导出时可再次选择）"}。补天 / edusrc 为一漏洞一提交，
          带「待补充」的字段需在平台表单人工确认。
        </p>
        {mobile?.present && (
          <div className="rounded-md border p-3 text-xs">
            <p className="mb-2 font-medium">移动端目标（报告模板会把同一份信息写进提交材料）</p>
            <div className="grid gap-1.5 sm:grid-cols-2">
              <span>平台：{mobile.platform || "待补"}</span>
              <span>应用包名 / Bundle ID：<code>{mobile.package || "待补"}</code></span>
              <span>应用版本：{mobile.version || "待补"}</span>
              <span>授权设备序列号：<code>{mobile.device_serial || "—"}</code></span>
              <span className="sm:col-span-2">授权 APK SHA256：<code className="break-all">{mobile.apk_sha256 || "—"}</code></span>
              <span className="text-muted-foreground sm:col-span-2">来源：{mobile.source || "—"}</span>
            </div>
            <p className="text-muted-foreground mt-2">
              包名 / 版本由发现正文解析，可能为空；缺失项会同时出现在模板的「待补充清单」。补天沿用已有 IOT 类别。
            </p>
          </div>
        )}
        {content}
      </CardContent>
    </Card>
  );
}
