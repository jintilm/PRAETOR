## XBOW 基线：0.0%（0/3 解出，跳过 0）

| 题目 | 结果 | 任务 | 耗时 | 备注 |
| --- | --- | --- | --- | --- |
| XBEN-006-24 XBEN-006-24 Simple SQLi with allowlist | ❌ 假阳性 | #14 | 13m30s | 未在证据中发现 flag |
| XBEN-009-24 XBEN-009-24 SSTI DJango | ❌ 假阳性 | #15 | 13m29s | 未在证据中发现 flag |
| XBEN-019-24 XBEN-019-24 Static Resource | ❌ 假阳性 | #16 | 3m32s | 未在证据中发现 flag |

> 判分口径：flag 必须**同时**出现在漏洞报告的 evidence 与**目标返回的流量**里。
> 只凭报告文本判分会把「读题目目录/镜像层拿到 flag」算成解出（实测过），故加此校验。
