# ADR-0004: 累計型 scope 的設計（C3）

- 日期：2026-10-28
- 狀態：採納（設計）；C3a 未實作

## 背景
單筆限額擋不住一萬筆小單——plan.md 把累計型標為 MVP 關鍵。spec 原本整列 TODO：度量什麼、起算點、重置、誰記、以什麼為鍵。

## 決定
1. **度量拆兩步**：C3a 先做 `dailyNotional`（每日累計名目）——簽名器自己加總即可，不依賴交易所；`dailyLoss`（每日虧損）為 C3b，需要成交回報與標記價，Phase 1 後期再做。
2. **起算點與重置**：UTC 日界（可預測、電路友善）；不採滾動 24h。
3. **記帳鍵**：`(mandateId, UTC 日)`；一張被接受的單入帳**鏈上每一層**（c0、c1、c2 的額度各自扣）。只記 leaf 的話，中間層發兩張子授權就能把自己的額度翻倍。
4. **⊆ 定義**：`child.dailyNotional ≤ parent.dailyNotional`，進 `isSubset`。
5. **記帳時機**：簽名器在 accept 之後記；被拒的單不入帳（與 nonce 同哲學，INV-13）。Phase 1 需要持久化。
6. **不變量升格**：C3a 實作與負面測試落地後，新增 **INV-14**：「同一 UTC 日內，經某 mandate 放行的訂單 Σnotional ≤ 該 mandate 的 `dailyNotional`，鏈上每層各自成立。」
7. **電路**：累計 = 狀態差值證明；對齊 Phase 3 k=4 電路的預留。

## 實作前提（待提議的型別變更）
verifyOrder 要對鏈上每一層記帳，需要讀到每層的 `(mandateId, scope)`——但 `verifyChain` 目前只回傳 leaf 的 `VerifiedMandate`。需要型別變更（例如回傳全層的 `VerifiedMandate` 陣列），依 CLAUDE.md「要改型別先提議」，實作前另行提議。

## 選項與取捨
| 選項 | 優點 | 缺點 |
|---|---|---|
| 直接做 dailyLoss | 一步到位 | 簽名器算不出虧損（無成交回報管道），Phase 1 會卡住 |
| C3a dailyNotional 先行（採納） | 簽名器自含、Phase 1 直接可用 | 名目 ≠ 風險，只是代理指標 |
| 滾動 24h 窗 | 無日界突變 | 需要逐筆時間戳帳本，狀態大、電路貴 |

## 後果
- `Scope` 於 C3a 增 `dailyNotional?: bigint`；`dailyLoss` 欄位保留給 C3b。
- `packages/verifier/src/state.ts` 的 `CumulativeState` 以 `(mandateId, UTC 日)` 為鍵實作。
- 關聯不變量：INV-10b、未來 INV-14。
