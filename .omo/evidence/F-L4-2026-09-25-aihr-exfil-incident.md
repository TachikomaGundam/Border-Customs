# F-L4 — AIHR 外泄事故：边检复证与公开面活体探测（2026-09-25）

案卷：/home/lab/workspace/AIHR/.omo/audit/INCIDENT-2026-09-25-env-identity-leak.md（owner 转呈进化输入）。

## 复证结果（本机只读取证，全部命令可重放）

- 事发仓 = `harness/hr`（GitHub 名 TachikomaGundam/AIHR）；AIHR 工作区 = 案卷库（无 remote）。
- v0.4.0 tag 树泄漏 3 文件与案卷 §1 表逐字吻合（docs/PUSH.md、scripts/README-build.md、opencode_plugin/install-cli.js）。
- `3a5fadc`(09-08 15:31, 最早入镜) 原样存在 ✓。案卷引用 `919b6ef/44b7ca1/e44716b` 本机不可解析（指针漂移）；内容对应物在 hr@main 上为：`04b8323`(=迁移误修，new addr 写入 PUSH.md)、`0b5b91d`(=脱钩前修)、`8255206`(HEAD, de-nickname)。hr@HEAD 对旧/新标识符均零命中（git grep rc=1）。
- **探针自纠**：首轮 `git grep <bad-ref> || echo "0 hits"` 产生了一次假绿（fatal 被 || 吞）——正是本案卷 §4.5 同族的"回执说谎"类；复证结论全部改用显式 rc 打印重跑。

## 公开面活体状态（2026-09-25 09:5x UTC, gh-proxy → raw.githubusercontent, per-ref-per-file counts）

| ref | PUSH.md | README-build.md | install-cli.js | 判定 |
|---|---|---|---|---|
| main | old191=1 | old191=2 + **lab@=2** | old191=1 | **仍在泄漏** |
| v0.4.0 | 同上 | 同上 | 同上 | **仍在泄漏** |

新地址 TESTBED-NEW-ADDR 公开面命中 0（远端 main 停在 09-25 本地工作之前，缓解事实）。
**关键升级：前修 `0b5b91d+8255206` 从未推送——"已处置"在本地为真、在世界为假。**
两 hr/AIHR 克隆均无 remote；推送须从持有推送位的那台/那份克隆走人类终端。

## 边检自判（失职机理坐实）

现行 border 规则面 = secret **值**类（gitleaks/secretlint 全家 + residue）。对 RFC1918、`user@host` ssh 式、`/home/<acct>`、机器画像组合、以及"该 token 是否属于公共空间"这一**流向维**：零覆盖。案卷 §3 的四条缺失（无流向透镜/只审本地树/消费视角/凭证边界过窄）对 border 产品逐条成立。

## 对案卷 §5 开放决策点的闸门侧裁定（待 owner 终审）

1. L4 = **独立 exfil 规则族 + 独立扫描腿**（审"将公开之物"），不并入 L2 值扫描——采案卷立场。
2. 本地证据原文保留 + 引用发布面用占位符——采案卷立场；**并加自反条款：border 的 L4 测试 fixture 必须用合成标识符**（10.200.x.x TEST 段 + synthuser@），泄漏原文不得进 border 自己的发布面。
3. 处置协议增补 **步骤 0 = 前修落地核验**（fetch 公开 ref 重跑扫描，绿了才许写"已处置"）；tag 重写/重建归人类。
4. abathur-self bench 拟题×2：`fix-reproduces-leak`（04b8323 型：迁移类 sed 提交再生产耦合）+ `claimed-fix-never-published`（本案：修复停摆本地）。

## 待人类两判

- H-1 推送前修到 GitHub main（从有推送位的克隆）；H-2 v0.4.0 tag 处置（接受+披露注记 vs 撤 tag——撤/换 tag = 历史重写类，纯人类闸门）。
