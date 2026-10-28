# Invariants — 永遠必須成立的規則

> 驗證器裡每個檢查都要能指到這裡的一條；這裡每一條都要有至少一個負面測試。
> 格式：編號｜規則（必須／不得）｜防什麼。
> v0.2，2026-10-28。範圍：簽章版、v0 scope。協定參數（時鐘偏移、鏈長上限等）見 spec/scope-semantics.md。

## 密碼學層

**INV-1** 所有被簽的訊息必須以 domain tag + 版本開頭（`MANDATE/v1`、`ORDER/v1`、`REVOKE/v1`）。在 `{body, sig}` 資料模型下，tag 由驗證者於驗簽時自行綁定：tag 混淆（如 ORDER 簽章冒充授權）表現為 `sig` 步驟拒絕；`tag` 步驟檢查的是 body 存在與版本欄位（`body.v`）。若要 wire-level 的 tag 檢查，需要 envelope 格式的新 ADR。
— 防型別混淆：同一把鑰匙簽的訂單被重新解析成授權；舊版格式被新 parser 誤讀。

**INV-2** Merkle 葉子與內節點必須用不同前綴雜湊（葉 `0x00`、內節點 `0x01`）。
— 防第二原像：把內節點的 `左‖右` 當葉子宣稱，偽造 membership proof（CVE-2012-2459）。

**INV-3** 任何會被對方看到的承諾，輸入必須附 ≥32 bytes 隨機 salt；salt 與 nonce 不得共用。
— 防窮舉：上限是小範圍整數，無 salt 時可暴力撞出（hiding 壞掉）。

**INV-11** 驗證者不得持有任何發行者的簽名私鑰；授權與訂單一律用非對稱簽章，不用 MAC。
— 防驗證者偽造授權；保留不可否認性（事後可向第三方證明是誰簽的）。

## 授權層

**INV-4** 每張授權必須包含 `mandateId`、`issuer`、`subject`、`audience`、`issuedAt`、`expiresAt`、`maxDepth`、`parentId`、完整 `scope`；缺任何一個，驗證者拒收。鏈本身必須是非空陣列且長度 ≤ MAX_CHAIN_LENGTH（16），輸入有界。
— 防：撤銷無從指（無 id）、鏈接不上（無 issuer/subject）、永久有效（無 expiry）、跨驗證者使用（無 audience）、無限轉包（無 maxDepth）。

**INV-5** 驗證者只接受 `audience` 等於自己的授權與訂單。
— 防跨驗證者重放：給簽名器 X 的拿去 Y 用。

**INV-6** 驗證者只從驗簽通過的授權（`VerifiedMandate`）讀取 scope、root 等欄位；不得從訂單或請求的任何欄位讀取授權內容。
— 防請求方自填 root / scope 繞過授權。

**INV-7** 資產 membership proof 必須對照所屬授權內的 `assetsRoot` 驗證。
— 防換樹：agent 自備一棵含未授權資產的樹。

**INV-10a** 每一層授權的 scope 必須 ⊆ 上一層的 scope；`maxDepth` 必須等於上一層減一且 ≥ 0；`issuer` 必須等於上一層的 `subject`；`parentId` 必須等於上一層的 `mandateId`。
— 防中間層放大授權、鏈拼接、無限轉包。

**INV-12** 根授權（c₀）的 `issuer` 必須在驗證者事先信任的根源集合內。
— 防自簽根授權：攻擊者自生鑰匙簽一張「leader 授權」。

## 訂單層

**INV-8** 每筆訂單必須包含 `nonce`、`issuedAt`、`expiresAt`、`audience`、`mandateId`，且全部在簽章覆蓋範圍內；訂單簽章必須以所屬授權的 `subject` 公鑰驗過。`notional`、`leverageBps` 必須為正（≥ 1）：零名目的單無經濟意義，卻會消耗 nonce。
— 防重放、跨驗證者使用、冒用他人授權。

**INV-9** 簽名器必須維護「未過期 nonce」帳本，以 `(subject, nonce)` 為鍵；同一 subject 的 nonce 重複或訂單過期一律拒絕；此帳本獨立於交易所的 nonce 狀態。
— 防重放；防 Hyperliquid API wallet 註銷後 nonce 狀態被清而導致舊單重放。鍵含 subject 防惡意佔用：看見他人在途 nonce 的攻擊者，無法用自己的合法單搶先燒掉它。

**INV-10b** 訂單的每個範圍值必須 ⊆ 所屬授權的 scope（資產 ∈ 白名單、notional ≤ maxNotional、leverage ≤ maxLeverage、時間 ∈ window）；累計型 scope（每日虧損等）由簽名器狀態判定。
— 防超額、超槓桿、交易未授權資產、窗外交易。

## 流程層

**INV-13** 驗證順序必須是：tag → 欄位 → 簽章 → 鏈接與根源 → audience → 時間 → 撤銷 → 深度與 scope ⊆ →（訂單側：membership → scope → 累計）→ nonce。任何一步失敗立即拒絕，不繼續讀後續欄位。欄位先於簽章：畸形輸入不做簽章運算。nonce 必須最後：被拒的單不消耗 nonce。
— 防在未驗簽的資料上做決定。

---

### 尚未定義（寫進 spec 後再升格為不變量）
- 撤銷的傳播與生效時間（TODO C4）

### 已拍板（2026-10-28）
- 時鐘偏移容忍值：issuedAt 容忍 +30 秒、expiresAt 嚴格 → spec/scope-semantics.md §4。
- 累計型 scope：設計採納於 ADR-0004（C3a dailyNotional、UTC 日界、每層 mandateId 記帳）；C3a 實作與負面測試落地後升格為 **INV-14**：「同一 UTC 日內，經某 mandate 放行的訂單 Σnotional ≤ 該 mandate 的 dailyNotional，鏈上每層各自成立。」
