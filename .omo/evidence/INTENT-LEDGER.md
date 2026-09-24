# INTENT-LEDGER — border 维护会话

订单登记格式：订单原词 / 验收标准（用户自己的话）/ 交付物 / 关闭判定。每次轮次边界复审未关项。

| # | 日期 | 订单（原词） | 验收标准 | 交付 | 状态 |
|---|------|-------------|----------|------|------|
| 1 | 2026-09-24 | “根据 /home/lab/abathur-operator/HANDOFF-border-opencode-tool.md 进化边检系统” | HANDOFF 五条建议逐条有交代：①根因定位到 tool handler 的二进制解析 ②解析不到⇒exit 2 cannot-answer 绝不回落 ③运行时身份断言 ④安装面收敛（不依赖宿主 execPath/全局 bin）⑤parity 测试 | `.omo/evidence/F-IMP-2026-09-impersonation-fix.md`（根因、修复、5 层验证含真实 opencode 冒充体复现关闭） | **代码侧已交付并验证**；未关项=人工闸门：commit/tag/push/publish、缓存 shim 决定、wiki 内容页追加确认（见证据文件 Open 节） |

注：本订单是 HANDOFF（2026-09-22）的正式闭环。此前会话对该通道的判定“不可信，直到修复”——修复已完成，通道可信性要到 0.5.1 实际装载进会话后成立。
