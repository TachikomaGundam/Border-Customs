# border exfil lens — 流向维审计（L4）产品化（0.6.0 波）· REV v3

Origin: AIHR 生产事故（案卷 INCIDENT-2026-09-25-env-identity-leak.md；owner 裁定"A 先"，
处置面 owner 亲理——border 对其仓只读取真值锚）。协议：R 系列（委托执行+读盘复验+lead 盘验）。
v3 折入 Momus 轮2 三 blocker（R1 rulesHash / R2 分面契约 / R3 真值腿 opt-in）+ 全部 NOTES。

## 判据（保留轮 2 已验真部分）

**commit message 也是公开面**（事故 exhibit `04b8323` 已被所有者重写消失，教训保类）。
门扫 **push 范围内一切将公开的对象**：tip 树 + 区间 commit messages + tag 注释。

## 分面契约（R2 折入——全计划的地基，守卫测试钉全表）

(rule × facet × channel × observed-severity) 矩阵，**单一之家 `src/exfil/severity.ts`**，
README 规则表按通道如实标注（R4-DOC 先例 test/residue.config.test.ts:348）：

| facet | 通道 | 规则与观测 severity |
|-------|------|---------------------|
| blob / tree / history | **孪生引擎**（gitleaks vendored TOML + secretlint border-pattern，**id 逐字相等**） | exfil-rfc1918、exfil-ssh-target → 顶格 **CRITICAL**（gitleaks.ts:81 硬编码；secretlint.ts:299-309 无 HIGH 映射——不硬掰，如实表）；MEDIUM 族（home-path、cred-location、host-profile）由 **native 树扫**同面补发 MEDIUM |
| commit messages（将公开区间） | **native 独占**，`exfil-*:message` id 族 | 五规则全族：rfc1918/ssh-target=HIGH、其余=MEDIUM；归因 path=commit sha（已验真：sha 经 toRepoRelative 原样透传 exclusions.ts:20-25，`file:"<sha>"` 可逐-commit 豁免） |
| tag 注释 | **引擎既有腿**（tagScan stdin 骑 vendored TOML → 命中发 `tag-message-secret` CRITICAL，tagScan.ts:26,101） | native **不再重扫** tag notes（消除双发）；`:message` 族只覆盖 commit messages |

- **撤销 v2 的 native 树/blob 双发 stage**：native 在树面只跑 MEDIUM 族；HIGH 族树面归孪生。
  三通道重叠发射在源头消除。
- 隔离守卫（双向各一条）：blob 面 `{rule:"exfil-rfc1918"}` 豁免**不穿透** `:message` 族，
  反向亦不（allow.ts:38 精确匹配已验）。
- messageScan 枚举复用 REV_BATCH=200 分批（identity.ts:88），`git log --no-walk` 分块读
  message——**首推全历史场景**也压在 60s/调用硬帽内（context.ts:35）；native 腿不吃
  引擎健康守卫（broken.has 不抑制）。
- import-audit（照抄 test/scan.test.ts:258-265 法）：`src/exfil/**` 不碰 ledger/check 内部。

## rulesHash 随动（R1 折入——红线归位）

新增 `EXFIL_FINGERPRINT_SOURCES`（平行 `RELEASE_FINGERPRINT_SOURCES` 先例，
rulesHash.ts:74-76）：`src/exfil/severity.ts` + 全部规则源文件，走 resolveAsset/seam 双路
进 `computeCheckRulesHash`（rulesHash.ts:126-135）。守卫测试钉死：**每个 `src/exfil/*.ts`
必须出现在清单中**（漏挂 = 测试红，杜绝"只改了 native 表没人知道"漂移形态）。

## 规则语义表（意图级；观测 severity 以上表分面为准）

| id | 意图 severity | 谓词 | 豁免（闭集） |
|----|----------|------|------|
| exfil-rfc1918 | HIGH | 10/8、172.16/12、192.168/16 字面 | loopback；RFC5737 三段；**10.200.0.0/16 = 合成 fixture 专用段**（对齐证据裁定 2；v1 的 192.168.99.x 提议作废） |
| exfil-ssh-target | HIGH | `user@host` 且 host ∈ {RFC1918 字面, rules.hosts(config.ts:102), 闭后缀 {.internal,.lan,.local,.corp,.intra}} | RFC2606（.example/.test/.invalid/.localhost） |
| exfil-home-path | MEDIUM | /home/<user>、C:\Users\<user> | 先自家扫描（T5）后定级，不许白墙 |
| exfil-cred-location | MEDIUM | ~/.pypirc、SSHPASS、*.env 位置引用 | 位置 ≠ 值 |
| exfil-host-profile | MEDIUM | os+版本/无docker/无passwordless-sudo 要素 ≥2 同段（保守正则表） | 语义组合启发 = phase-2 ledger 行；裸 `user@hostname`（无点）同记 phase-2，不悬空 |

## S2 `border exfil <ref|url> [ref...]`（只读快面）

- 默认 = tip 树 + tag 注释；`--deep` = reachable history（historyRefRange 教义
  check.ts:100-103，NOT --all）；分批绕 60s 帽；超时 = exit 2 响亮不可作答。
- URL 模式 = 临时 fetch 指定 ref → 扫 → 销毁。
- 退出：0 无阻断级命中（MEDIUM 打印放行）；1 阻断级命中；2 不可达/超时/坏参。
- SUBCOMMANDS 闭集加 `exfil` 一处枚举（cli/types.ts:16）+ usage + `--json`。
- 插件 allowlist **不加**（边界：不动插件；ledger 记 follow-up 单独波裁）。

## S3 push 腿与落地核验

- 执行前：将公开区间跑核（含 messageScan；endpoint 不可解析 ⇒ 整 ref，identity.ts:144-146）。
  dry-run 零 fetch 零 mutation。
- 执行后 landing：**范围 = git targets only**（registry 发布字节核验 = 点名 follow-up，
  不随坡扩面）。fetch 远端 ref 重扫 tip。诚实合同：
  - 不可达 ⇒ 成功记录原样不动 + exit 2 "landed, verification unavailable — PASS 不背书公开面"；
  - 命中 ⇒ exit 1 + "ALREADY PUBLIC; border detects, never erases"；
  - 永不伪装回滚、永不回改已执行记录；
  - ledger 新 `t:"landing"`（构造点校验仿 buildRoundtripRecord records.ts:123-142；
    旧版解析 records.ts:257 throw → :285 WARNING 跳行，兼容已验）。
- README **退出码合同表显式修订**（landing 两行语义）+ `--json` 行 `(check, scan)` →
  `(check, scan, exfil)`——表不动即合同说谎。

## 真值腿（R3 折入：opt-in，CI 无涉）

- `BORDER_EXFIL_TRUTH=1` 门控（先例 BORDER_ROUNDTRIP_DOCKER/BORDER_PACK_TEST），
  **人类/lead 手动跑、结果进证据**；CI 默认套件只含合成 fixture。
- 红锚 = 公开 AIHR main + v0.4.0（URL 模式，3 文件必中）；绿锚 = hr 本机 purge 后
  main HEAD（按语义取不钉 sha——**红锚预期寿命 = H-1 落地前；落地后本腿改由证据存档背书**，
  届时翻绿不算套件失败）。

## 任务分解

- [ ] T1 `src/exfil/` 核 + `severity.ts` 单家表 + **EXFIL_FINGERPRINT_SOURCES 接线**（含漏挂守卫）。
- [ ] T2 check 管线：孪生 TOML+secretlint 规则（树面 HIGH 族）+ native 树面 MEDIUM 族；
  孪生 id 逐字相等守卫 + (rule×facet×channel×severity) 全表守卫 + 双向隔离守卫。
- [ ] T3 `src/check/messageScan.ts`（:message 族、sha 归因、REV_BATCH 分批、不吃引擎降级）。
- [ ] T4 CLI `border exfil`（枚举/usage/--json/tip 默认/--deep/URL；exit 三态）。
- [ ] T5 **自家扫描先行**：border@main tip+全历史 message 跑核（Momus 预验：blob 面既有
  `.omo/**`、`test/**` 通配可吸收；message 面零命中）→ 校准报告入证据 → home-path 终级定案。
- [ ] T6 golden 回归（合成，CI 内）：10.200.x 合成 IP / `synthuser@10.200.30.40` /
  画像 ≥2 组合 / message 面带合成 IP 树干净 ⇒ 各必红；孪生面 MEDIUM 打印不阻断 ⇒ 必绿面。
  **真值腿 opt-in 单列**（上节），手动验收跑。
- [ ] T7 push 腿 + landing（含全部诚实退出合同）+ 首推全历史分批实测（大 ref 冒烟）。
- [ ] T8 README exfil 节（按通道如实 severity）+ **退出码合同表修订** + `--json` 行 +
  changelog 0.6.0 + bump 链照 90baf50 stat 逐项。
- [ ] T9 发布：commit → check PASS（exfil 已自门 dogfood）→ tag v0.6.0 → 人类 push
  （CI + 礼仪步实弹）。

## 边界（不做）

不动插件运行时/allowlist；LLM 组合启发 phase-2；不改任何他仓文件（真值腿纯只读 fetch
tmp 副本）；history rewrite 能力不做——border 只检测、只披露、只留证；registry 发布字节
landing 核验 = follow-up；首推全历史 message 若超时按 exit 2 处理不做静默截断。

## 验收硬标准

1. T5 报告入证据、校准后自家 check 全绿（无白墙豁免）；
2. 合成 fixture 全红 + 绿面 + 双向隔离守卫 + 全表守卫在场（CI 内闭环，零网络）；
3. `BORDER_EXFIL_TRUTH=1` 手动腿：红锚 3 文件中、绿锚 0 中，输出占位符化入证据；
4. landing：dry-run 零 fetch；unreachable/命中两条退出各有单测、不回改记录；
5. rulesHash 守卫：改一行 exfil 正则 → 旧 PASS 缓存必失效（实测翻面）；
6. 全套件绿（基线+新增，C5 对不变）+ typecheck/build RC0 + border check（含 exfil）PASS。
