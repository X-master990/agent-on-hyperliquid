# 給 agent 的規則（Mandate repo）

這個 repo 賣的是「信任」。一個驗證器少一個 if、一個電路少一個約束，不會報錯，只會讓假授權通過。所以：

## 動手前
1. 讀 `docs/invariants.md`（全部）、`docs/adr/`（相關的）、`spec/`（相關的）。
2. 讀你要改的 package 的 `src/types.ts`。型別是合約，不要改型別來遷就實作；要改型別先提議。

## 寫程式時
- 驗證器裡每一個檢查都要註解對應的不變量編號：`// INV-5: audience must equal self`。
- 指不到不變量的檢查，停下來問；不變量沒有對應檢查的，停下來說。
- 讀 scope、root、expiry 等欄位時，只能從 `VerifiedMandate` 讀（INV-6）。型別不允許從 `Mandate` 讀。
- 不新增依賴，除非有 ADR。
- 不自己決定規格沒寫的事（例如時鐘偏移容忍、累計型 scope 的語意）——寫 `// TODO(spec): ...` 並在交付時列出。
- `spec/` 和 `docs/` 只能提議修改，不能直接改。

## 測試
- 每條不變量至少一個負面測試（構造一個應該被拒的輸入，確認被拒）。沒有負面測試的檢查視為不存在。
- 測試名稱以 `INV-n` 開頭。
- 攻擊測試放 `test/attacks.test.ts`，正常路徑放 `test/<module>.test.ts`。

## 交付時附「走讀」
- 做了什麼、改了哪些檔
- 每個新檢查對應哪條不變量
- 假設了哪些規格沒寫的事
- 哪些情境沒測

## 現階段邊界（v0）
- 只做簽章版，不碰 `circuits/`、不碰 ZK。
- scope 只做三種：資產白名單（Merkle）、數值上限、時間窗。累計型留 TODO(C3)。
- 簽名用 ed25519，但一律透過 `Signer` 介面，不直接 import noble 到 chain/verifier。
- 不接 Hyperliquid 真實 API。
