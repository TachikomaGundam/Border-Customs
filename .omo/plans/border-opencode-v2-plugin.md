# border 插件适配 OpenCode V2 —— 双形状默认导出（0.7.0 波）· REV v2

Origin: 用户订单 6（"确保插件能够适用于Opencode V2"）。
v2 折入 Momus 轮1 三 blocker（B1 版本钉/B2 装载链三级信任分级/B3 探针真空绿）。
协议 R 系列；本文档零访谈可执行：每个未知量要么有当场事实，要么有具名 spike 任务+预授权修复路径。

## 事实基线（当场核实，标 E 级）

- **E1** npm `opencode-ai` latest=1.18.33，无 2.x。V2 宿主 = `@opencode-ai/cli`：
  **beta tag = 0.0.0-beta-19271**（本波钉死此版；其 next=0.0.0-beta-17823 是旧车 — 轮1 实错），
  dev=0.0.0-dev-19272；**bin 名 = `opencode2`**（cli package.json bin 实证 + 平台包文件名实证）。
  ⚠ dev 通道 bin 名是 `opencode`（非 opencode2）——本波不混用 dev。
- **E2** 平台包 `@opencode-ai/cli-linux-x64@0.0.0-beta-19271` tarball≈90.2MB，
  内含真二进制 `bin/opencode2`（postinstall.mjs 仅做 link/copy，无二次网络——源码已读）。
  registry 参照值（T0 直接比对，免再查）：**`dist.shasum` = `613a73b0b23a5a18640abeeccbdc9223b6c84f63`**
  （sha1，判据 `sha1sum plat.tgz` 对齐之；**不是** dist.integrity——那是 sha512-SRI，
  sha1sum 永不可对其，轮2 唯一 blocker 已此改）。完整第二判据 = tar 可解出
  `package/bin/opencode2` 且 ELF 可执行位。本机→npm CDN 当前 ~28-90KB/s，spike 用
  断点续传循环（已在途：/tmp/v2p/plat.tgz）。T0 附带产物：dump `opencode2 api` 路由表
  进证据文件，T3 的 execute 调用点由此零猜测。
- **E3** V2 插件契约（beta-19271 SDK `.d.ts` + 官方 migrate-v1 文档，轮1 逐行验）：
  默认导出须 `{id, setup}`（promise）或 `{id, effect}`；**V1 函数/形状不被接受且 loader
  `Effect.ignoreCause` 静默吞失败**（issue #42878/#39345——只 WARN 进日志文件）。
  `define()` 恒等（dist/promise/plugin.js 源码实证）⇒ 手写对象合法。
  promise 入口 `ToolEditor.add(Info)`，`Info.execute → Promise<Tool.Result>`（非 Effect）；
  `ValueSchema` 接受纯 JSON Schema ⇒ 零新运行时依赖成立。transform 回调契约=同步可重放
  （类型 `=>void` 拦不住 async——纪律靠 T2 结构测试 + T3 活体探针兜，T1 注释点名）。
  `CommandInvocation = {sessionID, prompt, delivery}`，delivery 本地类型
  `Literals["steer","queue"]`；输出回投机制无文档 = D3 分支实测。
- **E4** 官方双形状 = `{...define({id,setup}), async server(){...}}`；**V1 对象入口下限
  ≥1.18.29**（官方文档句）。本机活体 1.18.32 正在跑今日 `{id,server}` 形状（实证）。
  现码 border.ts:9 注释 ">= 1.14" 为**错标**（早于对象入口形状的存在）——T1 一并更正，
  支持矩阵只印 ≥1.18.29，单源。
- **E5** 本机 PATH 现状（B3 实据）：`~/.local/bin/opencode` 悬空符号链接、
  `~/.npm-global/bin/opencode` 缺失、lib 树 1.18.33 vs 活体宿主 1.18.32——一次半途全局
  安装裂口。V1 探针（test/opencode.probe.test.ts:61-75）找不到 bin 即 `t.skip`。

## 未知量——信任分级（B2 折入）

| # | 问题 | 级别 | 归属 |
|---|------|------|------|
| U1 | V2 package-plugin 装载读 exports 的哪个入口（`.`=CLI bundle 无插件 default 导出？`./server`？） | 未证实 | **T0 spike 答**，修复预授权 R1/R2 |
| U2 | 顶层 `import { tool } from "@opencode-ai/plugin"` 在 V2 宿主（bun 直载 .ts）解析链是否成立（Route B arborist 同置；file-drop 路径无 node_modules 时？） | 未证实 | T0 spike 答，修复预授权 R3 |
| U3 | V2 对**全局** `$XDG/opencode/plugins/` 与 `commands/` 的发现是否保留（文档只承诺项目本地 `.opencode/plugins/`） | 未证实 | T0 spike 答；**答不了前 README 对 Route A×V2 不承诺**（D4 收窄默认） |

预授权修复路径（T0 结果 → 动作，无需再问）：
- **R1**（U1=读 `.`）：`exports["."]` 改指插件模块或新增双出口；`bin.border` 直指
  dist/index.js 不经 exports，CLI 消费面不破——改后跑 exports 卫生测试全套。
- **R2**（U1=读 `./server` 或显式 subpath 可配）：现结构零改动，探针断言即可。
- **R3**（U2=file-drop 场景 SDK 不可解析）：border.ts 的运行时 import 改**惰性**
  （`tool()` 仅在 server() 体内 dynamic import；V2 setup() 本就不需要它）——
  类型 import 天然擦除不动；既有 16 测试缝保持（server() 零参可调用、COMMAND_TEMPLATE
  具名导出、字节镜像、execPath 禁令——全部照旧过）。

## 设计决定（轮1 批准项维持）

**D1** 零新运行时依赖（手写 {id,setup}，本地结构类型注 spike-for-types 免责 + T3 活体钉）。
**D2** 安全语义随迁：resolveBin+握手体抽出为 `buildToolResult(argv)` 双路共享；
`context.metadata()`（V1-only, border.ts:298）与返回信封留各路边界；
**verified 缓存共享维持**（两形状永不同进程；键控 BORDER_BIN + 负不缓存已隔离多调用点）；
T2 注明：同 env 双路 parity 测试第二路吃缓存 → 握手解析的 V2 侧覆盖归 T3 活体。
**D3** 命令面两步走：T4 实测 delivery 回投；不行则 0.7.0 只带 tool + ledger 行，
V1 的 cfg.command ??= 注入模板**严禁**搬进 setup()。
**D4** Route A：默认收窄为"V2 支持 package-route"；T0 若证实全局发现则放开并加断言。
**D5** 版本矩阵如实：V1 宿主 ≥1.18.29（对象入口），V2 = beta 线钉 beta-19271；
beta API 漂移声明 + 每 drop 重验义务印 README。0.7.0；bump 链单源纪律照旧。

## 任务分解（顺序即依赖）

- [ ] **T0 装载链 spike**（兼容性声称的闸门：T0 红=停波；但 T1/T2 的**不变核**——setup+buildToolResult+parity——与 R1/R2/R3 判定无关，可并行先行，R-路径增量等 T0 结论（lead  amendment, 2026-09-28））：
  解包 → `opencode2 --version` 自证 → 沙箱（独立 HOME/XDG；FULL-env spawn 教训沿用）：
  (a) 项目本地 `.opencode/plugins/spike.ts`（手写 {id,setup,server} 双形状最小插件，
  含顶层 SDK import 与不含 两变体）→ serve → `opencode2 api get /api/plugin`
  **正向断言在场**（防静默吞——在场是唯一绿标）；
  (b) package-route 用 `plugins:[{"package":"file:/tmp/v2p/pkg", ...}]` 或 verdaccio
  （devDeps 现成）本地源——0.7.0 未发布的鸡生蛋由 file 路径/本地源解；
  (c) 全局目录发现探测（U3）；
  (d) 结论逐字进 `.omo/evidence/F-V2-SPIKE-<date>.md`，U1-U3 各标 答/未答+R 路径落点。
  **T0 红 = 本波停在 spike，不进门。**
- [ ] T1 重构 plugin/border.ts：补 `setup`；共享 buildToolResult；R 路径按 T0 结论落；
  border.ts:9 下限注释更正（E4）；transform 同步纪律注释点名（E3）。
- [ ] T2 单测：双形状结构断言（loader 最小键集 {id,setup} + server 在场）；
  execute-parity（mock BORDER_BIN 两路渲染逐字等）；allowlist/--yes 拒在 V2 路同样
  spawn 前；V1 既有 16 测试+探针零回归。
- [ ] T3 V2 活体探针 `test/opencode.v2.probe.test.ts`（opt-in `BORDER_OPENCODE_V2_PROBE=1`，
  钉 cli@beta-19271，解析序：BORDER_OPENCODE2_BIN env → spike 落盘路径）：
  插件在场 → tool 列表含 border → **真实 execute 一次**拿 border banner →
  BORDER_BIN=冒充体 → cannot-answer。
- [ ] **T3b 反真空条款**（B3）：两个探针测试（V1+V2）当 opt-in env=1 而 bin/dist 缺失时
  **FAIL 并点名补救，不再 t.skip**；默认（env 未设）仍 skip 供 CI。V1 探针 bin 解析加
  `BORDER_OPENCODE_BIN` env 覆盖（可指活体 1.18.32 exe 或修复后的全局 bin——
  修复悬空 symlink 属机器卫生，另行报告 owner，不混入本波）。
- [ ] T4 delivery 实测（T3 同沙箱）→ D3 分支落定，结论入 spike 证据文件续篇。
- [ ] T5 文档/矩阵/0.7.0 bump 链 + `border check --force` 绿。
- [ ] T6 发布：commit→tag→人类 push→CI→本机 purge→双宿主通道内复验→台账+wiki。

## 边界（不做）

不引 effect/zod4 运行时依赖；不赌 delivery 细节（T4 实测）；不追 effect-Plugin 形状；
beta-17823/dev 通道不混用；机器 PATH 裂口修复不混入本波（单独报 owner）。

## 验收硬标准

1. T0 证据文件在场，U1-U3 各有 答/未答 + R 路径执行记录；
2. V2 活体探针全链绿（在场断言 + execute 真 banner + 冒充 cannot-answer），逐字入证据；
3. T3b 生效：`BORDER_OPENCODE_PROBE=1`+缺 bin ⇒ FAIL 非 skip（有单测/断言为证）；
   V1 探针本轮**实际执行**通过（输出含真实 HTTP 断言行）；
4. execute-parity 与 V1 全测试绿；
5. README 矩阵只印 E1-E4 级事实；beta 漂移义务在文；
6. 全套件基线（789/774/2受许/13+新增）+ typecheck/build RC0 + 门禁 PASS。
