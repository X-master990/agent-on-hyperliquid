# Scope Semantics（v0.1 — 2026-10-28 拍板；累計型設計見 ADR-0004）

## 1. 什麼是 scope
授權裡「允許做什麼、做到多大」的那組限制。兩條規則：訂單 ⊆ scope；子 scope ⊆ 父 scope。

## 2. 範圍型態
| 型態 | 表示 | ⊆ 定義 | 累計？ | v0？ |
|---|---|---|---|---|
| 資產白名單 | Merkle root | root 相等（不支援葉子證明真子集；真子集判定留給 ZK 版） | 否 | 是（簡化） |
| 最大名目 | 整數（最小單位，bigint） | ≤ | 否 | 是 |
| 最大槓桿 | 整數 bps（×100） | ≤ | 否 | 是 |
| 時間窗 | [notBefore, notAfter] 閉區間 | 區間包含 | 否 | 是 |
| 每日累計名目 | `dailyNotional`（bigint） | ≤ | **是** | C3a — 設計已拍板（ADR-0004），未實作 |
| 每日虧損 | `dailyLoss`（bigint） | ≤ | **是** | C3b — 依賴成交回報，Phase 1 後期 |
| 訂單類型 | 集合 | 子集 | 否 | 否 |
| 類別式白名單 | TODO | TODO | 否 | 否 |

## 3. 組合
- 多欄位 AND：逐欄位 ⊆。
- OR：不支援——偏序在 OR 下不保證成立；若要支援需新 ADR。

## 4. 時間語意（2026-10-28 拍板）
- 時間窗為閉區間，且**兩者都檢**：`order.issuedAt ∈ window` 且驗證當下 `now ∈ window`。window 的語意是「只准在這段期間交易」，執行時刻在窗外就不該執行；從嚴改寬容易，反向難。
- 時鐘偏移容忍：只放寬 issuedAt（`issuedAt ≤ now + CLOCK_SKEW_S`）；expiresAt 嚴格判。放寬過期判定等於延長授權壽命（安全語意變差）；放寬 issuedAt 只是吞發行方的時鐘誤差。
- 子授權的 issuedAt **不**要求 ≥ 父授權 issuedAt：issuedAt 僅供審計，不參與授權判定（有效性一律以 now 判）。加此檢查會引入發行方之間的時鐘耦合，收益只有審計美觀。

## 5. 協定參數（v0 拍板）
| 參數 | 值 | 理由 |
|---|---|---|
| `CLOCK_SKEW_S` | 30 | 只放寬 issuedAt（§4）；JWT 等業界慣例量級 |
| `MAX_CHAIN_LENGTH` | 16 | 鏈輸入有界（審計上可直接宣稱的 DoS 性質） |
| nonce 帳本鍵 | `(subject, nonce)` | 防跨 subject 惡意佔用（偷看在途 nonce 用自己的合法單搶燒）；對齊 per-wallet nonce 語意 |
| 訂單 `notional` / `leverageBps` 值域 | ≥ 1 | 零名目單無經濟意義卻消耗 nonce；scope 側 `maxNotional` 可為 0，作「關閘」語意 |

## 6. 明確不支援（v0）
- 真子集資產白名單：root 不相等一律不算 ⊆，即使集合上真的是子集。
- OR 組合、類別式白名單、`orderTypes`。
- 累計型判定：C3a 落地前，`dailyLoss` / `dailyNotional` 僅檢型別、不判定、不參與 ⊆。

## 7. 電路可證性備註
- v0 四種 ⊆ 都是等值比較／大小比較／區間包含，電路成本低。
- 累計型 = 狀態差值證明（`prev + order ≤ limit ∧ new = prev + order`），對齊 Phase 3 k=4 電路的「累計狀態差值」預留。
