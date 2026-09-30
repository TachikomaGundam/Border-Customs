# border opencode inspect — 装载面自审计表面（0.8.0 波）

Origin: 2026-09-24 冒充波收口，用户批准立项（"1 done；2 开始吧"）。
Repo: /home/lab/workspace/harness/border。协议沿用 R 系列：产品工作委托执行，
每个 DONECLAIM 由只读盘的新会话复验；lead 逐交付物盘验。

**v2 修订记录（2026-09-30）**：本稿折入 Momus 权威新审（bg_e0ed1228 / ses_f0e5e9128ffe，
判词 REVISE，B1-B4 blocking + M1-M4 + minors 全采纳）；前轮 2b 台账所欠"4 项 blocking 折进
v2"自此偿清。B3 裁定=**声明盲区而非覆盖 V2**；B1 判定版本号 0.5.2→**0.8.0**（新向后兼容
CLI 表面=minor，本线史 0.6.0/0.7.0 同例）。

## 动机（本案由，全部有实证；史实数字保留原样）

本波挖出的两个缺陷都在**装载/投递面**：
1. 工具冒充（process.execPath 宿主）→ 已由 v0.5.1 握手修复，但握手只在插件运行时生效，
   机器上"现在装的到底是谁"无命令可查；
2. dist-tag 静默陈旧（opencode 1.18.32 按字符串缓存、冷启动不重解析；@latest 钉死
   0.5.0 十一日）→ 临时防线是 tools/plugin-drift-watch.mjs + cron（2026-09-24 装）。

现状散件：handshake 在插件里、漂移比对在 tools 脚本里、装载探针是测试文件、Route A
校验在 installer status 里。**本波把它们制度化成一个门禁自有表面。**

## 命名决定（偏离 ledger 预名，理由如下）

Follow-up ledger 原预名 `border inspect opencode`。改为 **`border opencode inspect`**：
- `border opencode` 已有 install|status|uninstall 子命令组（src/commands/opencode.ts 的
  runOpencode 解析）；inspect 是同族第四个动词，语义自足。
- 新顶层 SUBCOMMANDS（src/cli/types.ts:16 冻结表，行号 2026-09-30 实测仍准）爆炸半径大
  （cli.ts usage、plugin allowlist、COMMAND_TEMPLATE、border-command.md 镜像、README 表、
  cli.test.ts 面全链动）。T3 同步点：usage 行在 src/cli.ts:38（opencode 行内追加 inspect）。

## 表面契约

`border opencode inspect [--json]` —— 检查**这台机器 V1 装载面**上 border 插件装载的六个方面，
每方面 verdict ∈ {PASS, FAIL, CANNOT}：

| # | aspect | 检查 | FAIL 条件 | CANNOT 条件 |
|---|--------|------|-----------|-------------|
| 1 | cache-version | 枚举 `$XDG_CACHE_HOME/opencode/packages/border-customs@*`，逐目录读包内 package.json version + plugin/border.ts 首行 marker | 目录版本 ≠ spec 应有版本；marker 与 package.json 版本不一致 | 目录不存在且配置声明了插件（=声称装载却无缓存；rc 映射见 T4 特判） |
| 2 | spec-freshness | 配置 spec（global+project 两处 opencode.jsonc 的 plugin 数组；project=当前 cwd 的 ./opencode.jsonc）：exact pin → 比对版本号 vs 缓存；dist-tag → 问 registry `<pkg>/<tag>` 现值比对缓存 | 缓存落后于"应有版本" | registry 不可达（仅当 spec 是 dist-tag 时该方面才 CANNOT） |
| 3 | identity-handshake | 按插件同一候选序解析二进制（BORDER_BIN → 包内 dist shebang 直exec → PATH node + dist → PATH border），对首个可达候选跑 `--help`，用与插件逐字相同的判定（首行 `border` 开头 + 含 `usage: border`） | 候选解析成功但握手不过（= 冒充形态回归） | 全部候选不可达 |
| 4 | route-a-parity | 复用 installer 的 sha 逻辑：投放文件在位时 `installed=<sha> packaged=<sha>` 比对（本包自带的 packaged 值） | 在位但 sha ≠ packaged（陈旧投放） | —（无投放文件则 PASS-not-installed） |
| 5 | dual-route | 统计注册来源数：配置 plugin 行（B）+ Route A 投放文件（A）。**两者同时在位 = FAIL**（双注册窗口正是蓝图 §7 门禁项防的；单条 Record 去重只是 opencode 侧兜底，不是我们的许可） | A ∧ B 同时在位 | 配置不可读 |
| 6 | scope | 常量声明行（B3 裁定）：本次裁决只覆盖 **v1-load-surface**；未覆盖面逐字列出：V2 项目本地 `.opencode/plugins/`、V2 的 npm-prefix/node_modules 安装、V2 懒激活态 | —（永不 FAIL；它是证书边界） | —（永不 CANNOT） |

聚合退出码（fail-closed 优先序）：任一 FAIL → **1**；无 FAIL 但有 CANNOT → **2**；全 PASS → **0**。
--json：`{schemaVersion:1, scope:"v1", verdict, aspects:[{id, verdict, detail}...]}`——scope 字段
是消费方的合同面值（B3：PASS 不得被读成"全机装载干净"）。
README/T6 的 boundary-honesty 段同一句话：inspect 只审计 V1 装载面；V2 装载枚举单独立项
（V2 布局仍 beta、投递 API 未定形，把审计尺钉在漂移靶上会复发尺伤——Momus 裁定原文）。

## 交付分解

- [x] T1 core：新 `src/opencode/inspect.ts`（+ 小 `aspects/` 拆分若超 250 LOC 上限），
  纯函数 + 注入缝（fs 根、env、fetcher——fetcher 复用 src/scan/fetch.ts 的
  ScanFetcher 型 src/scan/fetch.ts:42；registry base URL 可注入）+ **runner 注入缝**
  `runner(candidate, argv) => Promise<{status, stdout, stderr}>`（M2：aspect 3 的握手探测经缝，
  单测不真 spawn 冒充体也能判；ScanFetcher 同风）。零 ledger 写入、零 check 管道依赖
  （scan 的 import-audit 合同照抄）。
- [x] T2 握手判定共享：插件 plugin/border.ts 内的判定串与 inspect 的判定串
  **镜像钉死测试**（运行时 import COMMAND 已有先例——同法导出/常量比对，防两处漂移）。
- [x] T3 CLI 接线：runOpencode 子命令 parse + usage 行（src/cli.ts:38）+ 错误路径（未知子命令
  仍 exit 2）。实现要点（MINOR）：runOpencode 现对任何 `rest.length>0` 抛错
  （src/commands/opencode.ts:230）——须先剥 `--json` flag 再判子命令。
- [x] T4 tools/plugin-drift-watch.mjs **退役为薄壳**：内部 spawn
  `border opencode inspect --json`，**逐 aspect 映射**（取 aspects[1..2]，非顶层 verdict——
  aspect-3 identity FAIL 不得触发 cron purge）→ 原三态 rc。**映射定案（B2，不留现场裁量）**：
  aspect-1 之"无缓存"CANNOT **特判回落 rc 0（NOT-CACHED，向后兼容现状**：现脚本 :84/:103 就是
  NOT-CACHED→0**）**；仅 registry/解析类 CANNOT 映射 rc 2。crontab 行零改动
  （`[ $rc -eq 1 ] && purge` 守卫只对 DRIFT 动作；rc=2 明令不动缓存）。
  **`--purge` 留在壳内本地实现（rmSync 缓存目录）——inspect 保持纯只读**（发布投递礼仪具名
  依赖 --purge：opencode.jsonc:52 注释 + 订单 5/7 收口记录）。
  **解析路径决定（M4）**：本机 `border` 不在 PATH（实测 command not found）——壳头注释写明
  候选序与后果：cron 落点将是 repo dist（可变工作树）。裁定：接受但具名——壳优先用
  `BORDER_BIN`（cron 行可带）或 repo dist 绝对路径，并在 F-INSPECT 证据里记录当次落点。
  脚本头部注明 verdict 单源=inspect。
- [x] T5 测试：逐 aspect 单测（HOME/XDG/registry-seam 全注入，离线默认；活网络 E2E 走
  env 开关门，同 scan 家风）；聚合优先序矩阵（F×C×P 组合）；cli 面（子命令表 + exit 2
  路径）；T2 镜像测试；T4 rc-mapping 单测含 NOT-CACHED→0 特判案例。**尺伤防复发条款（M2）**：
  任何 side-channel 计数断言必须走注入缝或同步屏障，**禁读异步日志行数**（verdaccio 6!==2
  事故同款，.omo/evidence/F-I4-RULER-RACE-2026-09-30.md）。typecheck+build RC0；
  **基线数字（M3）**：全套件 = 现网基线 **794 / 779 pass / 2 恰 C5-1+C5-4 / 13 skips** + 新增，
  fail-set 不变；CI 口径 skips=12（runner-only 覆盖面已知差）——新增红或 skip 计数漂移 =
  publish.yml sanctioned-failure 闭集直接拒发。
- [x] T6 文档+dogfood：README opencode 节 + changelog **0.8.0**（版本单源纪律：
  package.json 为源，UA/测试钉随动 R4-DOC 同法：test/residue.config.test.ts:348 +
  test/releaseCoherence.test.ts；README 示例钉 `@0.7.1` 与插件 marker 行由该编舞自动轮转）；
  本机制真输出贴进 `.omo/evidence/F-INSPECT-0.8.0.md`；wiki 适配层页 follow-up ledger 勾账
  （`border opencode inspect` 替代预名，偏离已在本文档记账）。
- [ ] T7 发布（B4：按发布轮律重排——人类 2026-09-30 批准，律文 /home/lab/.config/opencode/
  agent/abathur.md:156-165；顺序违律会被 pre-push 钩子机械拒绝，禁绕钩）：
  ① `scripts/release-lease.sh acquire 0.8.0 <seat>`（租约先行）→
  ② `border check --force` 产 gate:PASS 收据入 `docs/release/0.8.0.md` →
  ③ commit → ④ tag `v0.8.0` → ⑤ **人类 push**（pre-push 校验收据+租约配对）→
  ⑥ tag CI 全绿、npm 落地后 lease release。
  （Consumer-refresh ritual 步**非首次实弹**——2026-09-24 已入 publish.yml（3419998），
  0.7.1 CI run 36686422413 已过；该句自旧稿删除。）

## 边界（明确不做）

- **插件 ALLOWED_COMMANDS 零改动（M1，有意且声明）**：实测名单（check/push/status/
  llm-request/llm-ingest/scan/roundtrip/--help）不含 `opencode` ⇒ 会话内
  `border opencode inspect` 会被插件本地拒绝——这是本波决定，不是遗漏。inspect 是否入
  插件面并入 owner 待裁的 exfil 入册单（订单 10，F-EXFIL-ALLOWLIST-RULING-2026-09-30.md
  四问判据一并裁），本波不碰、执行者不得"顺手加白"。
- 不查 registry provenance/attestation（npm audit signatures 需要 spawn npm，面外；
  发布线 CI 已产 provenance，消费验证归 scan/roundtrip 已有表面）。
- 不动插件运行时代码（握手已在 0.5.1 立好；inspect 是离线量尺，不重写门）。
- 不引新依赖；不改全局配置内容（只读）。
- crontab 不动（T4 的 NOT-CACHED→0 特判就是 rc 合同向后兼容的保证，验收项）。
- V2 装载面枚举不做（B3 裁定：本版声明盲区；单独立项随 V2 稳定后进 follow-up ledger）。

## 验收硬标准（用户视角）

1. 本机上 `border opencode inspect` 返回 **V1 装载面**全 PASS、exit 0，`--json` 六方面齐全
   （scope:"v1" 在位）；
2. 人为破坏场景三发实测（贴证据）：registry seam 谎报更新版 → spec-freshness FAIL 1；
   BORDER_BIN 指冒充体 → identity FAIL 1；A+B 双路线同装 → dual-route FAIL 1；
3. drift-watch 在 inspect 化后 cron 语义回归测试过（rc 映射单测，含 NOT-CACHED→0 特判案例
   与 --purge 本地留存案例）；
4. 全套件绿（基线 794/779/2/13 + 新增，C5 对不变）；border check PASS 收据入 docs/release/
   0.8.0.md；发布走 T7 轮律序（租约+收据+人类 push）。
