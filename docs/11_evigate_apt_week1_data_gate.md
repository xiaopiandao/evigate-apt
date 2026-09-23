# EviGate-APT Week 1 数据门记录

> 核验日期：2026-09-15  
> 当前结论：**Gate 1A 暂定通过（provisional fallback）**  
> 适用方案：`docs/09_evigate_apt_proposal.md` v1.1

## 1. 本轮结果

官方 `Attack_info.csv` 仍未取得，因此不能把当前 59 个事件簇称为数据集作者定义的 attack steps。本轮已按方案中的预注册降级规则完成以下工作：

1. 用 Phase 2 的 network 与 provenance 两视图中带时间戳的攻击标记行的并集构建 tactic-specific temporal clusters；
2. 将主口径固定为相邻记录间隔不超过 300 秒的最大连续簇，并写入 `derived_label=true`；
3. 固化原始文件 SHA-256、标签映射、排除行统计和 1/2/5/10/15 分钟敏感性；
4. 将 `±5 min` evidence window 发生重叠的事件簇合并为不可拆分的 embargo group；
5. 生成三折 attack-cluster-grouped 外层划分，以及每折内部的 group-disjoint calibration 划分；
6. 将少于三个事件簇的战术从监督多分类训练/校准列表中移除，仅保留给拒识和定性分析。

这完成了开发 Stage A/Stage B 前所需的样本单位与泄漏边界，但结论仍须标注为 fallback。若后续取得官方 `Attack_info.csv`，必须由官方攻击步骤 manifest 替换当前文件并重新生成全部划分。

## 2. 官方文件获取审计

CIC 官方数据页明确说明 Supplementary material 中包含 `Attack_info.csv`，字段信息包括攻击时间、攻击 PID 和攻击类别：<https://www.unb.ca/cic/datasets/iiot-dataset-2024.html>。

2026-09-15 的获取结果如下：

| 检查项 | 结果 |
|---|---|
| 官方数据集入口 | 可访问；下载链接进入需要姓名、邮箱、机构等信息的注册表单 |
| 未注册访问 `browse.php` | HTTP 403 |
| 猜测的 `Attack_info.csv`、`Supplementary/Attack_info.csv` 路径 | HTTP 302，重定向到 UNB 数据集索引，而非文件 |
| 本地 Kaggle archive | 有 Phase 1/2 network CSV，无 `Attack_info.csv` |
| 已核验的 Zenodo provenance 镜像 | 有 provenance CSV/PCAP，无 `Attack_info.csv` |
| 精确文件名公开检索 | 仅命中 CIC 对文件的说明，没有可核验下载副本 |

未使用虚构个人信息提交注册表。这个限制不影响 fallback 管线的复现，但影响事件定义的权威性。

## 3. 输入数据与完整性

| 视图 | 文件 | 大小 | SHA-256 |
|---|---|---:|---|
| Network | `data/raw/cicapt/network/phase2_NetworkData.csv` | 4,336,376,799 bytes | `90dd6752ead750393f7c75ca157ef27d21861b69f6cbe3d0a8fe295306a638ea` |
| Provenance | `data/raw/cicapt/Phase2_Provenance.csv` | 29,896,119 bytes | `7f858f479e90ccbe27c3d4f487ddf2f15a26ad0bfa7f472abff3aa68e332976d` |

全量流式扫描得到：

- Network：9,536,823 行，其中 1,004 行为攻击标记，1,004 行均可定时；
- Provenance：196,735 行，其中 402 行为攻击标记，283 行可定时，119 行没有直接可用时间戳；
- 无时间戳的 provenance 节点没有被用作聚类锚点，但后续构建 incident subgraph 时仍可通过带时间戳边的端点关系召回；
- 当前事件 manifest SHA-256：`0f78908a0a0241296df9f98cc0cb3d96e8a4ad8f8c2340ad78a00250f6786c9b`；
- 当前 split manifest SHA-256：`5727991f79b1d8fc7f9c13a5e2a6369cc95f0eb72aa4c214a305e9741059c467`。

## 4. 事件簇结果

五分钟主口径得到 59 个事件簇：

| Tactic | Cluster 数 | 监督任务角色 |
|---|---:|---|
| Collection | 26 | in-support |
| Discovery | 11 | in-support |
| Credential Access | 7 | in-support |
| Command and Control | 5 | in-support |
| Exfiltration | 4 | in-support |
| Persistence | 2 | out-of-support |
| Lateral Movement | 2 | out-of-support |
| Defence Evasion | 1 | out-of-support |
| Initial Access | 1 | out-of-support |

因此主监督定量任务包含 5 类、53 个事件簇；另外 4 类、6 个事件簇只能评价“是否合理拒识”并用于案例分析。

按证据视图覆盖，33 个簇同时包含 network 与 provenance 攻击记录，12 个仅由 network 记录锚定，14 个仅由 provenance 记录锚定。这些覆盖标签只用于数据审计，不作为推理时输入。

## 5. Gap 敏感性

| 相邻时间 gap | 总簇数 | 相对 5 分钟主设置的变化 |
|---:|---:|---:|
| 1 min | 61 | +2 |
| 2 min | 59 | 0 |
| 5 min | 59 | 主设置 |
| 10 min | 58 | -1 |
| 15 min | 58 | -1 |

总体数量在 58–61 之间，说明总簇数对该范围内阈值不敏感；但最终论文仍应对主要终点重复报告全部五个设置，不能只报告最有利阈值。

## 6. 冻结的数据划分

`±5 min` context embargo 将 59 个事件簇合并为 46 个不可拆分组。三折测试集的 in-support 事件数分别为 17、18、18，并且每折都包含全部五个 in-support tactics：

| Outer fold | Train in-support | Calibration in-support | Test in-support | Test out-of-support |
|---:|---:|---:|---:|---:|
| 1 | 28 | 8 | 17 | 3 |
| 2 | 28 | 7 | 18 | 2 |
| 3 | 27 | 8 | 18 | 1 |

必须遵循以下使用规则：

- tactic classifier 的监督训练和阈值校准只能使用 `supervised_in_support_cluster_ids`；
- out-of-support clusters 不得作为正常多分类训练样本；
- 同一外层折内，任何 embargo group 不得跨 train/calibration/test；
- 标准化、特征选择、重采样和阈值拟合必须在每个外层折内重新执行；
- `label`、`subLabel`、`subLabelCat`、真实恶意 PID 和事件边界只能用于评估/划分，不得进入 Stage A/B/C 推理特征。

## 7. 复现命令

```powershell
python scripts\build_cicapt_cluster_manifest.py `
  --network data\raw\cicapt\network\phase2_NetworkData.csv `
  --provenance data\raw\cicapt\Phase2_Provenance.csv `
  --output data\derived\cicapt_phase2_attack_clusters_fallback.json `
  --gap-seconds 300 `
  --sensitivity-gaps-seconds 60 120 300 600 900

python scripts\build_cicapt_split_manifest.py `
  --clusters data\derived\cicapt_phase2_attack_clusters_fallback.json `
  --output data\derived\cicapt_phase2_grouped_splits.json `
  --folds 3 `
  --embargo-seconds 300 `
  --min-tactic-support 3 `
  --calibration-fraction 0.2

python -m unittest discover -s tests -v
```

## 8. Gate 判定与下一步

| 检查项 | 状态 | 判定 |
|---|---|---|
| 原始文件哈希 | 完成 | pass |
| 402/332/330/283 统计口径 | 已自动核对 | pass |
| 视图中立事件 manifest | 已生成 fallback | provisional pass |
| 1/2/5/10/15 分钟敏感性 | 完成 | pass |
| grouped split + context embargo | 完成 | pass |
| 官方 `Attack_info.csv` | 未取得 | unresolved, non-blocking for fallback |
| 全部事件的 evidence cases | 59/59 已生成且泄漏验证通过 | pass |

Gate 1 已按声明的 union-derived fallback 通过。下一项工程任务是生成完整 Phase 2 的 60 秒 network-window table，并执行 Stage A 的 Logistic Regression、HistGradientBoosting 和轻量 MLP 基线；详细 evidence-case 验证见 `docs/12_evigate_apt_evidence_gate.md`。
