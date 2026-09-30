# border opencode inspect — 装载面自审计表面（0.5.2 波）

Origin: 2026-09-24 冒充波收口，用户批准立项（"1 done；2 开始吧"）。
Repo: /home/lab/workspace/harness/border。协议沿用 R 系列：产品工作委托执行，
每个 DONECLAIM 由只读盘的新会话复验；lead 逐交付物盘验。

## 动机（本案由，全部有实证）

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
- 新顶层 SUBCOMMANDS（src/cli/types.ts:16 冻结表）爆炸半径大：cli.ts usage、plugin
  allowlist、COMMAND_TEMPLATE、border-command.md 镜像、README 表、cli.test.ts 面——全链动。
- 探测对象是 opencode 适配器装载态本身，挂在 opencode 组下比通用 inspect 组更诚实
  （目前没有第二个 inspect 目标；等有了再抽组，避免空架子）。

## 表面契约

`border opencode inspect [--json]` —— 检查**这台机器**上 border 插件装载的五个方面，
每方面 verdict ∈ {PASS, FAIL, CANNOT}：

| # | aspect | 检查 | FAIL 条件 | CANNOT 条件 |
|---|--------|------|-----------|-------------|
| 1 | cache-version | 枚举 `$XDG_CACHE_HOME/opencode/packages/border-customs@*`，逐目录读包内 package.json version + plugin/border.ts 首行 marker | 目录版本 ≠ spec 应有版本；marker 与 package.json 版本不一致 | 目录不存在且配置声明了插件（=声称装载却无缓存） |
| 2 | spec-freshness | 配置 spec（global+project 两处 opencode.jsonc 的 plugin 数组）：exact pin → 比对版本号 vs 缓存；dist-tag → 问 registry `<pkg>/<tag>` 现值比对缓存 | 缓存落后于"应有版本" | registry 不可达（仅当 spec 是 dist-tag 时该方面才 CANNOT） |
| 3 | identity-handshake | 按插件同一候选序解析二进制（BORDER_BIN → 包内 dist shebang 直exec → PATH node + dist → PATH border），对首个可达候选跑 `--help`，用与插件逐字相同的判定（首行 `border` 开头 + 含 `usage: border`） | 候选解析成功但握手不过（= 冒充形态回归） | 全部候选不可达 |
| 4 | route-a-parity | 复用 installer 的 sha 逻辑：投放文件在位时 `installed=<sha> packaged=<sha>` 比对（本包自带的 packaged 值） | 在位但 sha ≠ packaged（陈旧投放） | —（无投放文件则 PASS-not-installed） |
| 5 | dual-route | 统计注册来源数：配置 plugin 行（B）+ Route A 投放文件（A）。**两者同时在位 = FAIL**（双注册窗口正是蓝图 §7 门禁项防的；单条 Record 去重只是 opencode 侧兜底，不是我们的许可） | A ∧ B 同时在位 | 配置不可读 |

聚合退出码（fail-closed 优先序）：任一 FAIL → **1**；无 FAIL 但有 CANNOT → **2**；全 PASS → **0**。
--json：`{schemaVersion:1, verdict, aspects:[{id, verdict, detail}...]}`，机器消费稳定面。

## 交付分解

- [ ] T1 core：新 `src/opencode/inspect.ts`（+ 小 `aspects/` 拆分若超 250 LOC 上限），
  纯函数 + 注入缝（fs 根、env、fetcher——fetcher 复用 src/scan/fetch.ts 的
  ScanFetcher 型；registry base URL 可注入）。零 ledger 写入、零 check 管道依赖
  （scan 的 import-audit 合同照抄）。
- [ ] T2 握手判定共享：插件 plugin/border.ts 内的判定串与 inspect 的判定串
  **镜像钉死测试**（运行时 import COMMAND 已有先例——同法导出/常量比对，防两处漂移）。
- [ ] T3 CLI 接线：runOpencode 子命令 parse + usage 行 + 错误路径（未知子命令仍 exit 2）。
- [ ] T4 tools/plugin-drift-watch.mjs **退役为薄壳**：内部 spawn
  `border opencode inspect --json`，映射 cache-version/spec-freshness → 原三态 rc
  （FRESH 0 / DRIFT 1 / CANNOT 2）。**crontab 行零改动**（rc 语义保持；已装的
  `[ $rc -eq 1 ] && purge` 守卫继续只对 DRIFT 动作）。脚本头部注明 verdict 单源=inspect。
- [ ] T5 测试：逐 aspect 单测（HOME/XDG/registry-seam 全注入，离线默认；活网络 E2E 走
  env 开关门，同 scan 家风）；聚合优先序矩阵（F×C×P 组合）；cli 面（子命令表 + exit 2
  路径）；T2 镜像测试。typecheck+build RC0；全套件 = 现网基线 + 新增，fail-set 不变
  （仅受许 C5 对）。
- [ ] T6 文档+dogfood：README opencode 节 + changelog **0.5.2**（版本单源纪律：
  package.json 为源，UA/测试钉随动 R4-DOC 同法）；本机制真输出贴进
  `.omo/evidence/F-INSPECT-0.5.2.md`；wiki 适配层页 follow-up ledger 勾账
  （`border opencode inspect` 替代预名，偏离已在本文档记账）。
- [ ] T7 发布：commit → 本地 tag `v0.5.2` → border check PASS 盖指纹 → **人类 push**
  （tag 触发 CI，新加的 Consumer-refresh ritual 步首次实弹——dogfood 闭环）。

## 边界（明确不做）

- 不查 registry provenance/attestation（npm audit signatures 需要 spawn npm，面外；
  发布线 CI 已产 provenance，消费验证归 scan/roundtrip 已有表面）。
- 不动插件运行时代码（握手已在 0.5.1 立好；inspect 是离线量尺，不重写门）。
- 不引新依赖；不改全局配置内容（只读）。
- crontab 不动（T4 保证 rc 合同向后兼容是验收项）。

## 验收硬标准（用户视角）

1. 本机上 `border opencode inspect` 返回全 PASS、exit 0，`--json` 五方面齐全；
2. 人为破坏场景三发实测（贴证据）：registry seam 谎报更新版 → spec-freshness FAIL 1；
   BORDER_BIN 指冒充体 → identity FAIL 1；A+B 双路线同装 → dual-route FAIL 1；
3. drift-watch 在 inspect 化后 cron 语义回归测试过（rc 映射单测）；
4. 全套件绿（基线+新增，C5 对不变）；border check PASS；发布走人类闸门。
