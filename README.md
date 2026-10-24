# Mandate

AI agent 授權鏈：人 → 交易 agent → 子 agent，每層只縮不放；第一個戰場是 Hyperliquid。

- 專案計畫：`../plan.md`（v0.2）
- 不變量：`docs/invariants.md` ← agent 動手前必讀
- 決策紀錄：`docs/adr/`
- 範圍語意：`spec/scope-semantics.md`（Phase 0 寫）
- 威脅模型：`spec/threat-model.md`

## 結構

```
packages/core      雜湊、tag、正規序列化、Merkle、承諾、簽名介面
packages/chain     Mandate / Order 型別、issue / delegate / verifyChain、scope ⊆
packages/verifier  政策驗證器：nonce 帳本、撤銷、累計狀態、verifyOrder
examples/          leader → A → B → C 的端到端範例
bench/             效能量測
```

## 開發

```
pnpm i
pnpm test
```

v0 範圍：簽章版、三種簡單 scope（資產白名單 / 數值上限 / 時間窗）、記憶體 nonce 帳本。
不在 v0：ZK、累計型 scope（每日虧損）、Hyperliquid 接入、撤銷的 non-membership。
