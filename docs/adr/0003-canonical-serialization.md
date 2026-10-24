# ADR-0003: 被簽內容的正規序列化用 RFC 8785 (JCS)

- 日期：2026-10-21
- 狀態：採納

## 背景
簽章覆蓋的是 bytes。同一個物件兩種 JSON 序列化（鍵順序、空白、數字格式）會產生不同 bytes，造成「驗不過」或更糟的「兩份不同內容同一簽章」的歧義。

## 決定
v0：`tag ‖ JCS(body)`，JCS 用 `canonicalize` 套件（RFC 8785）。數值一律以字串形式的十進位整數（最小單位）表示，避免浮點。
ZK 階段改為固定欄位順序的二進位編碼（電路友善），屆時另開 ADR。

## 後果
- `packages/core/src/canonical.ts` 是唯一的序列化入口；chain/verifier 不得自行 `JSON.stringify`。
- 關聯不變量：INV-1。
