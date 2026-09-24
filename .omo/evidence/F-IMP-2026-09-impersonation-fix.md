# F-IMP-2026-09: border opencode tool impersonation — fix + verification (v0.5.1 wave)

日期：2026-09-24（Asia/Shanghai）
来源订单：`/home/lab/abathur-operator/HANDOFF-border-opencode-tool.md`（2026-09-22，发现会话 Abathur 进化编排，去向 border 维护会话）
验收标准（订单原词归纳）：工具通道要么真的运行 border，要么 fail-closed 报 exit 2 cannot-answer；绝不回落执行任何其他二进制；有 parity 测试锁定。

## Root cause（已实证定位）

`plugin/border.ts` 0.5.0 `resolveBin()`（原 :62-68）：Route B 打包同侧候选以
`{ bin: process.execPath, prefix: [distEntry] }` spawn。opencode 是 bun 编译的单一
可执行文件，插件在宿主进程内加载 ⇒ `process.execPath` = **opencode 本体**。
症状与 HANDOFF 完全一致：`--help` → opencode banner exit 0；其余命令 → opencode
unknown-command usage error exit 1（yargs 对多余位置参数+全局 --help 的行为）。

测试盲区（第三次同型事故，前两次：aihr Windows PATHEXT 盲区 wiki/opencode/aihr-windows-npm-spawn-incident；silent-bin shim 盲区 src/index.ts:27-39 注释）：
`node --test` 里 `process.execPath === node`，dist 自 spawn 测试（test/opencode.test.ts 原 :214）
天然通过；Route B consumer-verify 只断言了装载面（HTTP 的 tool id / command 表），从未执行过工具。

## Fix（本波改动，全部落盘于 /home/lab/workspace/harness/border）

1. `plugin/border.ts`（v0.5.1 marker）：
   - 候选链：`BORDER_BIN`（独占，坏了 loud error 绝不静默回退）→ 包内
     `../dist/index.js` shebang 直接 exec → 同文件 PATH `node` 承载 → PATH `border`。
     **`process.execPath` 从代码中移除**（头注释保留事故说明，卫生测试 strip 注释后源码级钉死）。
   - 身份握手 `isBorderHelp()`：候选必须先以 `["--help"]` 应答（exit 0 + 首行 `border` 前缀 +
     含 `usage: border`，20s 上限）才被接受；通过之前任何用户 argv 不投递。
   - 不可答映射：spawn 失败（ENOENT/EACCES/ENOEXEC）与握手全败 → `exit: 2` cannot-answer +
     候选逐条理由 + 补救三选项；原 127 类归并进 2，对齐 CLI 退出码合同（README:“2 = gate could not answer”）。
   - 正向握手按 BORDER_BIN 键缓存于宿主进程生命周期；负向不缓存（会话中途安装即恢复）。
2. `test/fixtures/opencode/echo-argv.mjs`：`--help` 单独应答 border 身份签名（probe 腿与
   verdict 腿分离，FAKE_EXIT 不再污染握手）。
3. 新夹具 `test/fixtures/opencode/opencode-impostor.mjs`：复刻事故形态（--help 回
   opencode 式 banner、exit 0），IMPOSTOR_LOG 记录每次被调 argv。
4. `test/opencode.test.ts`：
   - 原 ENOENT 测试重写为 cannot-answer exit 2（并断言不回退跑打包 dist）。
   - 新增 impostor 拒绝测试：exit 2 + `impostor?` 文案 + 日志证明只有 `--help` 探针到达、
     `status` 从未投递。
   - 卫生测试加 execPath 源码钉；dist 测试加 allowlist 七命令 parity 断言
     （HANDOFF 建议 5 的 command-set 打到真 dist 上验证输出特征串）。
5. 版本一致性链：package.json/package-lock.json → 0.5.1；`src/scan/fetch.ts`
   SCAN_USER_AGENT → `border-customs/0.5.1`；`test/residue.config.test.ts` R4-DOC 波次钉更新；
   README 插件节+changelog 0.5.1+中文概要同步。

## Verification（全部本轮实测，2026-09-24）

- `npm run typecheck` 干净；`npm run build` OK。
- `test/opencode.test.ts`：16/16 pass。
- 全量 `npm test`：**725 tests / 711 pass / fail 2 / skipped 12**；仅存 fail = sanctioned
  C5-1/C5-4 对（基线不变）。
- 自身门禁 `border check`：**PASS 0 findings**，ledger key `87d3649e`，ts
  2026-09-24T08:26:16.336Z（`.border/ledger.jsonl` 末行）。
  - 过程注记：初版 `usage:\s*border` 正则被 border 自己的 `path-pattern:[A-Za-z]:\\`
    secretlint 规则命中（字母+冒号+反斜杠 形态）——dogfood 即时生效，改用纯字符串判定。
- **原事故活体复现关闭**：以真实 `/home/lab/.local/bin/opencode` 为 BORDER_BIN 执行工具
  → `$ border status` / `exit: 2` / `note: cannot-answer — … impostor? …`，无任何东西被冒充执行。
- Happy path：无 BORDER_BIN 时经包内 dist 握手 → `--help` 应答 border banner exit 0。
- 真实宿主装载探针 `BORDER_OPENCODE_PROBE=1 test/opencode.probe.test.ts`：pass（36.9s）。

## Honest boundary

握手挡的是错认（宿主二进制、PATH 意外、缺失），不挡蓄意伪造 banner 的 PATH 投毒——
后者超出低成本防线，README/工具描述已如实标注。allowlist 仍是防呆非安全边界（既有教义不变）。

## Open（人工闸门项，非本会话可关）

1. ~~commit + tag~~ **DONE 2026-09-24（本会话，经用户批准"1同意"）**：commit `90baf50`（11 files, +327/−48）+ annotated tag `v0.5.1` 已落本地 main；随后 `border check` 对新指纹 PASS（ledger key `766070ea`）。**剩余人类步骤**：`cd /home/lab/workspace/harness/border && git push origin main v0.5.1`（origin 为 SSH URL `git@github.com:TachikomaGundam/Border-Customs.git`，不受 https gh-proxy insteadOf 影响，无需 GIT_CONFIG_GLOBAL——已核实本仓 border.yaml `remotes: []` 为刻意的 repo-local 范围，border push 于此仓本就是 NO-OP，v0.5.0 波同样由此 SSH 推送）→ tag 触发 publish.yml OIDC trusted-publish。HANDOFF 里的 `GIT_CONFIG_GLOBAL=/home/lab/.gitconfig-noghproxy` 配方服务于 **Abathur sync 线**（`/home/lab/abathur-operator/sync-v025`，https gh-proxy remote），本会话已备好该替代 gitconfig 文件。
2. **正规渠道更新即 debug（用户裁定 2026-09-24）——构件侧 CLOSED**：人类 push 完成（main→`cc590b8`、tag→`v0.5.1`）；CI run `35984303118` 全绿，`+ border-customs@0.5.1`，OIDC provenance sigstore `logIndex=2936073692`，shasum **三方一致**（CI 日志 = registry 元数据 = 下载 tarball）= `683e2c69388053294e6496bd3e86c0710c801403`。registry 安装沙箱（`npm i border-customs@0.5.1`，@opencode-ai/plugin 同目录落位再证依赖分水岭）对**已发布构件**跑双场景：A) 真 opencode 为 BORDER_BIN → `exit: 2` cannot-answer "impostor?"、用户 argv 零投递；B) Route B 自 spawn `--help` → border banner + `exit: 0`（0.5.0 会在 B 答出宿主 banner 的同一路径）。运维注记：npm 发布后有版本端点 404 的处理窗口（"may take a few minutes"），聚合文档先行可见——轮询需两路都查。**0.5.0 会话内活体对照（同日，修复发布后、重启前）**：本会话 `border {command:"--help"}` 仍答出 opencode ASCII banner + 宿主 usage + exit 0——与 2026-09-22 原症状逐字节同型；证明装载面按服务启动定格、修复不热更旧会话，属预期行为而非修复失效。 剩余：**用户重启会话**（@latest 冷启动取 0.5.1）后在通道内跑同两命令作最终关闭。建议（所有者决定）：opencode.jsonc 从 `border-customs@latest` 改钉 `border-customs@0.5.1`（蓝图 §7 反 @latest）。
3. ~~wiki 内容页追加待确认~~ **DONE 2026-09-24**：用户令"让史官记录"。en 页 926 / zh 页 927 各落"Status update 2026-09-24 — v0.5.1"全量记录；设计决策 1/3 就地加 SUPERSEDED 指针。过程教训：`historian_page_append` 双侧都**只落了标题、正文丢失**（孪生节尤甚）——修复走 page_update 全量 RMW；追加长正文后必须回读校验，此坑值得进 historian 插件的 bug 账。

—— Abathur（border 维护会话）

## 交付面第二缺陷（2026-09-24 追加）：@latest 缓存永不重取，安全修复静默不传播

重启后复测仍答宿主 banner → 排查装载面事实：`~/.cache/opencode/packages/border-customs@latest/`
建于 09-13 23:04(+0800)、内容恒为 0.5.0；0.5.1 发布于 09-24 18:00(+0800)，其后冷启动
**从未重解析 @latest**（opencode 1.18.32）。结论：dist-tag spec 按字符串缓存、无重解析/TTL，
`@latest` 静默钉死首次解析的版本——插件类**安全修复经 @latest 渠道不会传播**。全局配置注释里
"冷启动恒取最新发布"的假设就此证伪；蓝图 §7 "钉 exact 版本、绝不用 @latest" 首次获得实证理由。

处置（正规渠道，经用户"发布后本机用正规渠道更新"订单授权）：`~/.config/opencode/opencode.jsonc`
border 行 `@latest` → **`@0.5.1`**（exact pin = 新缓存键 → arborist 冷启动从 registry 全新拉取；
同文件 historian 插件本就是 exact-pin 家风），改动含理由注释两行。
**开放警示（所有者决定面）**：同文件仍有 `opencode-fastdraw@latest` 等 @latest 条目，同陷静默钉死风险。
最终关闭条件：重启后 `border {command:"--help"}` 应答 border banner；届时 wiki 双语页补 published stamp。
