# ADR-0001: v0 只支援三種 scope 型態

- 日期：2026-10-21
- 狀態：採納

## 背景
完整的 scope 語意（類別式白名單、累計型限額、OR 組合）是模組 C3 的題目，尚未學完也未寫 spec。但 chain v0 需要一個能運作的 `isSubset()`。

## 決定
v0 的 `Scope` 只含三類、⊆ 關係顯而易見的欄位：
1. 資產白名單：Merkle root；子集關係在 v0 以「子層 root 必須等於父層 root，或子層提供整棵樹且為父層子集」判定
2. 數值上限：`maxNotional`、`maxLeverage`，⊆ 即 ≤
3. 時間窗：`window.notBefore/notAfter`，⊆ 即區間包含

累計型（`dailyLoss`）保留欄位但不在 v0 判定；`orderTypes`、類別式白名單不在 v0。

## 選項與取捨
| 選項 | 優點 | 缺點 |
|---|---|---|
| 等 C3 寫完 spec 再做 chain | 一次做對 | 兩三週沒有可跑的東西 |
| v0 三種簡單型態（採納） | 本週能跑；C3 回來只改 `scope.ts` | 之後要遷移 Scope 型別 |

## 後果
- `packages/chain/src/scope.ts` 是唯一會因 C3 而重寫的檔案。
- 關聯不變量：INV-10a、INV-10b。
