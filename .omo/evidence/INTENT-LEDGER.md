# INTENT-LEDGER — border 维护会话

订单登记格式：订单原词 / 验收标准（用户自己的话）/ 交付物 / 关闭判定。每次轮次边界复审未关项。

| # | 日期 | 订单（原词） | 验收标准 | 交付 | 状态 |
|---|------|-------------|----------|------|------|
| 1 | 2026-09-24 | “根据 /home/lab/abathur-operator/HANDOFF-border-opencode-tool.md 进化边检系统” | HANDOFF 五条建议逐条有交代：①根因定位到 tool handler 的二进制解析 ②解析不到⇒exit 2 cannot-answer 绝不回落 ③运行时身份断言 ④安装面收敛（不依赖宿主 execPath/全局 bin）⑤parity 测试 | `.omo/evidence/F-IMP-2026-09-impersonation-fix.md`（根因、修复、5 层验证含真实 opencode 冒充体复现关闭） | **代码+验证+commit(`90baf50`)+tag(`v0.5.1`)+wiki 记录全部完成**；未关项=人类 `git push origin main v0.5.1` + 发布后正规渠道关闭验证（订单补充语 2026-09-24：“1同意；2发布后本机用正规渠道更新，这也是debug的一部分；3让史官记录”） |
| 2 | 2026-09-24 | “1同意；2发布后本机用正规渠道更新，这也是debug的一部分；3让史官记录” | ①发布线放行到人类 push 前 ②不做缓存 hack，发布后经 registry 正规更新并以事故复现步骤复验工具通道 ③史官记录事故与修复 | ①commit+tag 已落、检查重放 PASS `766070ea` ②复验清单已入证据文件 Open-2 ③wiki 926/927 双语更新完成（en: http://localhost:3000/en/opencode/border-opencode-adapter / zh: http://localhost:3000/zh/opencode/border-opencode-adapter） | ②**开放**——待人类 push + npm 0.5.1 上架后，在新会话跑 `border --help`/`status` 复验方可关闭 |

注：本订单是 HANDOFF（2026-09-22）的正式闭环。此前会话对该通道的判定“不可信，直到修复”——修复已完成，通道可信性要到 0.5.1 实际装载进会话后成立。
