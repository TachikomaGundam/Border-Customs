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

1. commit + `git tag v0.5.1` + border push（终端，`GIT_CONFIG_GLOBAL` 绕 gh-proxy insteadOf，见 HANDOFF 末节）→ tag 触发 OIDC trusted-publish。
2. 本机 opencode 插件缓存仍是 0.5.0（`~/.cache/opencode/packages/border-customs@*`）；发布后重启会话取 0.5.1，或经批准临时以修复件覆盖缓存以提前恢复 `border` 工具通道。当前会话边检仍走 node 直调。
3. wiki 内容页 `opencode/border-opencode-adapter`（en/zh）的“设计决策 1”已被证伪再修复，待确认后追加 status update（reading-loop 台账义务）。

—— Abathur（border 维护会话）
