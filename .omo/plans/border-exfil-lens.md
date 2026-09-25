# border exfil lens — 流向维审计（L4）产品化（0.6.0 波）· REV v2

Origin: AIHR 生产事故（INCIDENT-2026-09-25-env-identity-leak.md，owner 2026-09-25 裁定"A 先"）。
Repo: /home/lab/workspace/harness/border（本身公开 GitHub——一切设计先过自家镜）。
v2: 折入 Momus 轮1 六项 blocking（B1-B6 全采纳，条款号在各节尾注）。协议：R 系列。

## 事故给出的、案卷自己没写的一条（本波新增判据）

**commit message 也是公开面**。事故现场 `04b8323` 的 message 同时携带旧+新测试床地址
（树扫干净、message 会首次发布新地址）；该提交在记录当日被所有者会话重写消失
（8255206→b8e632a，msg 同步去标识）——重写本身即"message 是面"的独立佐证。案卷 §4.2
只覆盖 blob/tree。border 的门必须扫 **push 范围内一切将公开的对象**：tip 树 + 区间内
全部 message + tag 对象注释。【B6 注：教训保类，具体 sha 引用只作史实。】

## 规则核与 severity 权威（B1 折入）

T1 native 核 `src/exfil/`（纯函数：输入 {tree blobs | commit messages | tag notes}，
输出 findings）是**唯一 severity 权威**——severity 表单一之家 `src/exfil/severity.ts`
（仿 RESIDUSE_SEVERITIES 单家先例，test/residue.config.test.ts:348）。
引擎分工（B1 选项 b）：
- CRITICAL/HIGH 级（exfil-rfc1918、exfil-ssh-target）：gitleaks TOML + secretlint
  border-pattern 通道**双发孪生，id 逐字相等**（border-pattern 规则发射 id=pattern 名，
  secretlint.ts:311-320 实证——把 09-13 双命名半盲变成机械保证）。
- MEDIUM 级（exfil-home-path、exfil-cred-location、exfil-host-profile）：**仅 native 核
  单发**（gitleaks.ts:81 硬编码 CRITICAL、secretlint 无 HIGH 映射——引擎通道表达不了
  我们的分级，不硬掰）。
- 集合守卫测试（同 DOC-LIT 法）：钉"每条 exfil 规则由哪个通道发、severity 为何"全表；
  改表必须同步改守卫。
- native 腿不吃引擎健康守卫（broken.has("gitleaks") 不抑制它）：引擎降级照跑（B2）。
- src/exfil/** import-audit（照抄 test/scan.test.ts:258-265 的 grep 守卫）：不碰
  ledger/check 管道。零新依赖。

规则表（phase 1）：
| id | severity | 谓词 | 豁免（闭集） |
|----|----------|------|------|
| exfil-rfc1918 | HIGH | 10/8、172.16/12、192.168/16 字面 | loopback、RFC5737 文档段（192.0.2/198.51.100/203.0.113）、RFC1918 内 10.200.0.0/16 为**合成 fixture 专用段**（对齐证据裁定 2；废弃 v1 的 192.168.99.x 提议，B6） |
| exfil-ssh-target | HIGH | `user@host` 且 host ∈ {RFC1918 字面, rules.hosts（config.ts:102）, 闭集后缀 {.internal,.lan,.local,.corp,.intra}} | RFC2606（.example/.test/.invalid/.localhost）——README 的 `devs@acme.example` 不触（B6） |
| exfil-host-profile | MEDIUM | 保守正则表：os+版本 / "no docker" / "no passwordless sudo" 类要素 ≥2 同段 | 组合启发（语义级）落 **phase-2 ledger 行**，不在本波悬空 |
| exfil-cred-location | MEDIUM | ~/.pypirc、SSHPASS、*.env 等位置引用 | 位置暴露 ≠ 值泄漏，MEDIUM 不阻断、打印 |
| exfil-home-path | MEDIUM | /home/<user>、C:\Users\<user> | **先自家扫描（T5）后定级**；无点 hostname 的裸 `user@internal-build` 式引用：明确记为 phase-2 开放项（B6 二择一取 ledger） |

## 收集面（B2 折入）

- 树/blob 面：check 管线新 stage 骑 T2（tagScan.ts 同型工装）。
- **message 面：新 `src/check/messageScan.ts`**——扫描对象 = 将公开区间
  （`trackingEndpoint`+`rev-list endpoint..ref`，identity.ts:140-180 现成教义；endpoint
  不可解析 ⇒ 整 ref 视为将公开）+ tag 注释。message-hit finding 用**独立 rule id**
  （`exfil-*:message` 后缀族），使 file-scoped allow 永远打不穿 blob 面（allow.ts:13-14
  的 pathless 盲区因此不适用——message 归因带 commit sha 作为 path 域值，规则 id 分面）。

## S2 `border exfil <ref|url> [ref...]`（B3/B4 折入）

只读快面，审"世界现在看到的"：
- 默认范围 = **tip 树 + tag 注释**；`--deep` = reachable history（复用 historyRefRange
  "reachable from refSet, NOT --all" 教义，check.ts:100-103），分批 rev-list
  （REV_BATCH=200 式，identity.ts:88）绕 git 60s 硬帽（context.ts:35）；超时 =
  **exit 2 不可作答**（响亮，非静默非 1）。
- URL 模式 = 临时 fetch 指定 ref 到 tmp → 扫 → 销毁。这正是落地核验与事故真值复验的
  同一件武器。
- 退出合同（措辞修正，Note-4）：0 = 无阻断级命中（MEDIUM 打印放行）；1 = **阻断级命中**；
  2 = 不可达/超时/坏参数。插件 allowlist 本波不加 exfil（边界：不动插件；ledger 记
  follow-up：agent 会话要用此面时单独波裁）。

## S3 push 腿与落地核验（B5 折入）

- 执行前：将公开区间跑 T1 核（含 messageScan）→ 阻断级命中则 gate 红（同 check 语义）。
  dry-run 零 fetch 零 mutation（AC4）。
- 执行后**落地核验**：fetch 远端 ref 重扫 tip。诚实合同（钉死）：
  - 不可达 ⇒ 已执行 push 的成功记录**原样不动**，另加 exit 2 + 文案
    "landed, verification unavailable — PASS 不背书公开面"；
  - 命中 ⇒ exit 1 + "ALREADY PUBLIC; border detects, never erases"（identity.ts:276
    句式），永不伪装回滚、永不回改记录；
  - ledger 新增 `t:"landing"` 记录（构造点校验仿 buildRoundtripRecord，records.ts:123-142;
    旧版解析对未知 t WARNING 跳行，records.ts:285，兼容已证）。
- 案卷 §4.4 步骤 0（"已处置"以公开对象绿为准）= 本腿的产品化。真值锚（B3）：
  **红锚 = 公开仓 main + v0.4.0（URL 模式，2026-09-25 实测仍在漏）**；
  **绿锚 = hr 本机 purge 后 HEAD（现 b8e632a——sha 随所有者会话重写浮动，验收脚本按
  "本机 purge 后 main HEAD"取，不钉死 sha）**。

## 任务分解

- [ ] T1 `src/exfil/` 核 + severity 单家表 + import-audit 守卫。
- [ ] T2 check stage（树/blob 面）+ 报告/suppression 走现机制。
- [ ] T3 `src/check/messageScan.ts`（:message 规则族 + sha 归因）+ 双发孪生 id 相等守卫测试。
- [ ] T4 CLI `border exfil`（SUBCOMMANDS+usage+--json）；范围语义如上（tip 默认/--deep/URL）。
- [ ] T5 **自家扫描先行**（先于 fixture 工作）：border@main 全历史 tip+message 跑核——
  Momus 预验：blob 面既有 `.omo/**`、`test/**` 通配 allow 可吸收、message 面零命中；
  正式报告落证据并定 home-path 终级（不许白墙）。
- [ ] T6 golden 回归：合成 fixture 三发必红（10.200.x 合成 IP / `synthuser@10.200.30.40`
  / 画像组合段）+ message 面单测（合成 IP 进 message、树干净 ⇒ 必红）+ URL 模式真值
  （红锚公开 main/v0.4.0 三文件全中；绿锚 purge 后 HEAD 零中）；证据中地址一律占位符。
- [ ] T7 push 腿 + landing 记录（含诚实退出合同全套）。
- [ ] T8 文档/版本：README exfil 节 + changelog 0.6.0 + bump 链照 90baf50 stat 逐项
  （package.json/lock/plugin marker/UA/R4-DOC）。
- [ ] T9 发布：commit → check PASS（此时 exfil 已自门——dogfood）→ tag v0.6.0 → 人类
  push（CI + 新礼仪步首次实弹）。

## 边界（不做）

不动插件运行时/allowlist；LLM 组合启发 = phase 2；不改任何他仓文件；history rewrite
能力一律不做（border 只检测、只披露、只留证——擦除永远是人类在别处做的事）。

## 验收硬标准

1. T5 自家扫描报告入证据，校准后 border 自己 check 全绿（无白墙式豁免）；
2. 三合成 fixture 必红 + message 面单测必红 + URL 真值：公开红锚 3 文件全中、绿锚 0 中；
3. 孪生 id 逐字相等守卫 + 通道/severity 全表守卫测试在场；
4. landing 腿：dry-run 零 fetch；unreachable 与命中两条退出路径各有单测且不回改记录；
5. 全套件绿（基线+新增，C5 对不变）+ typecheck/build RC0 + border check（含 exfil）PASS。
