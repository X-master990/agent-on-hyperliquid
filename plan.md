# Mandate — AI Agent 授權鏈 × Hyperliquid 交易（專案計畫 v0.2）

> 工作名稱：Mandate（產品名不放 ZK；ZK 只出現在技術文件）
> 一句話：讓交易 agent 能安全地把交易授權轉給**不是自己的**子 agent（外部策略 agent、跟單 agent、市集雇來的執行者），每一層只縮不放、對方看不到上限、可撤銷、可追責；第一個戰場是 Hyperliquid。
> 版本：v0.2，2026-10-21（v0.1 為通用 A2A 版，本版收斂到交易垂直；核心協定不變）

---

## 1. 問題

交易 agent 正在變成多 agent 系統：組合 agent 把工作拆給各市場的執行 agent、研究 agent、跟單 agent，而且越來越多子 agent **不是自己寫的**——外部策略提供者、agent 市集裡雇來的執行者。

現況（2026-10）：
- **Hyperliquid 原生 API wallet 是二元開關**：主帳戶批准 agent 代簽，無按資產／金額的範圍、無子 agent；有過期但文件模糊；agent 註銷後 nonce 狀態可能被清掉而導致重放。
- **單層政策錢包已是紅海**：Cobo Agentic Wallet（2026-05）在 MPC 簽名層強制倉位上限、槓桿上限、每日虧損、強制停損、資產白名單、自動過期、一鍵凍結；MetaMask Agent Wallet（2026-08）花費上限＋協定白名單；Binance Agent OS（2026-08）隔離子帳戶。三者**都沒有子 agent 委派**。
- 子 agent 不是自己的時候，需要的東西沒人做：每層授權只能縮不能放、子 agent 看不到上層的限額（底價）、整條鏈可驗證、可撤銷、出事可追責。

## 2. 這個專案是什麼 / 不是什麼

**是：**
- 一條交易授權鏈的格式：人 → 交易 agent → 子 agent → …，每層只縮不放
- 一個強制點：政策簽名器（v0）→ HyperEVM 金庫合約（v1）→ 對第三方的 ZK 證明（v2）
- 兩種驗證：簽章版（同組織內）、ZK 版（跨組織、對存款人／審計方）

**不是：**
- 不是交易策略、不是交易機器人
- 不做單層「人 → agent」政策錢包（Cobo、MetaMask 已做）
- 不做身份（ERC-8004、Binance Agent ID）、不做交易所
- 不證明 LLM 推理、不做 zkTLS
- 不發幣

定位：單層政策錢包之上、交易所之下的**多層授權層**。

## 3. 核心敘述

### 3.1 範圍（scope）型態——交易版

| 型態 | 範例 | ⊆ 關係 | 累計？ |
|---|---|---|---|
| 資產白名單 | {BTC, ETH} | 子集 | 否 |
| 最大名目倉位 | ≤ 50,000 USDC | ≤ | 否（單筆）／是（總倉位） |
| 最大槓桿 | ≤ 3x | ≤ | 否 |
| 每日虧損上限 | ≤ 1,000 USDC/日 | ≤ | **是** |
| 訂單類型 | {limit, reduce-only} | 子集 | 否 |
| 時間窗 | 2026-11-01 ~ 11-30 | 區間包含 | 否 |
| 可再委派深度 | ≤ 2 | ≤ | 否 |

累計型範圍（每日虧損、總倉位）是 C3 最難的一類，在本垂直是 **MVP 必做**——沒有它就輸給 Cobo。累計狀態由強制點維護（v0 簽名器、v1 合約讀 HyperCore precompile）。

### 3.2 ZK 版證明的敘述

公開輸入：根源發行者 Merkle root（或 KYC 發行者公鑰）、本次訂單承諾 `H(asset, notional, leverage, side, ts, nonce)`、鏈長上限 k、政策 ID、累計狀態承諾。

私密輸入：整條鏈 c₀ … cₙ、各層簽名、各層範圍、持鑰證明。

證明：n ≤ k；c₀ 由有效根源簽發；每個 cᵢ 由 cᵢ₋₁ 持有者簽給 cᵢ；每層範圍 ⊆ 上層；本次訂單 ⊆ cₙ 範圍；訂單後累計狀態仍在 cₙ 限額內；證明者持有 cₙ 私鑰且綁定 nonce。

驗證者得到：有效／無效。看不到：根源是誰、中間幾層、各層上限、策略。

## 4. 架構

```
委託人（金庫 leader / 交易團隊）
   │ 根授權 c₀
   ▼
交易 agent ──c₁──▶ 外部策略 agent A ──c₂──▶ 執行 agent A1
           └──c₁'─▶ 外部策略 agent B
                                   │ 訂單 + 授權鏈（或 π）
                                   ▼
          ┌────────────────────────────────────────────┐
          │ 強制點                                       │
          │ v0 政策簽名器：驗鏈 → 更新累計狀態 → 用主帳戶  │
          │    API wallet 簽 → 送 Hyperliquid（builder fee）│
          │ v1 HyperEVM 金庫合約：驗鏈/證明 → CoreWriter   │
          │    下單（precompile 讀倉位/價格算累計限額）     │
          │ v2 ZK 證明對外：存款人/審計方/保險驗 π          │
          └────────────────────────────────────────────┘
                                   │
                                   ▼
                         Hyperliquid HyperCore
```

### 4.1 三個強制點的取捨

| | v0 政策簽名器 | v1 HyperEVM 金庫 | v2 ZK 對外 |
|---|---|---|---|
| 延遲 | 毫秒 | CoreWriter 延遲數秒 | 離線 |
| 信任 | 信任簽名器（或 MPC 分片） | 合約 | 數學 |
| 成本 | 無 gas | ~47k gas + 驗證 | 證明幾秒 |
| 適合 | 所有頻率 | 中低頻 | 存款人／審計 |
| 監管 | 可能構成託管（台灣 VASP 要查） | 非託管 | — |

v0 先做；v1 在監管或去信任需求明確時做；v2 在有金庫存款人或審計需求時做。

### 4.2 原生收費軌道
Hyperliquid builder code：`approveBuilderFee` 讓 builder 對經手訂單收費；CoreWriter 支援此動作。政策簽名器即 builder，每筆經驗證的訂單抽 bp。

## 5. 技術選型

| 元件 | 選擇 | 理由 |
|---|---|---|
| 鏈格式 | 自定 JSON + caveat 風格 | 參考 Biscuit、AIP |
| 簽名（v0） | ed25519，signer 抽介面 | 之後 ZK 內層換 Baby Jubjub EdDSA |
| Hyperliquid 接入 | `@nktkas/hyperliquid`（TS SDK）、API wallet、subaccount | 每個子 agent 流程一個 API wallet（官方建議） |
| 累計狀態 | v0 簽名器內記憶體＋持久化；v1 HyperCore read precompile | — |
| 電路語言 | Noir（Barretenberg） | 不用 Rust |
| 範圍證明 | 電路內比較；累計狀態用承諾＋差值證明 | — |
| 鏈長 | 固定 k=4 補空層 | 遞迴延後 |
| 撤銷 | 短效期＋簽名器即時黑名單 | v1 用 SMT non-membership |
| 鏈上驗證器 | Noir 匯出 Solidity → HyperEVM；gas 高則 Groth16 | — |
| SDK | TypeScript；MCP tool 介面 | 配合 agent 框架 |

## 6. 開發階段

### Phase 0 — 規格與簽章版（對應模組 B、C）
- `spec/scope-semantics.md`：3.1 的七種範圍、⊆ 定義、累計狀態語意、不支援項
- `docs/invariants.md`、`docs/adr/0001-v0-scopes.md`
- `packages/chain`：issue / delegate / verify（n 層）
- `packages/verifier`：簽章版
- 對抗測試：超額、超槓桿、不在白名單、日虧損累計超限、過期、重放、換 audience、別人鑰匙、中間層放大、Merkle 第二原像
- 產出：可跑的簽章鏈 + 測試

### Phase 1 — 政策簽名器 + Hyperliquid testnet（對應模組 G 的 Hyperliquid 部分）
- `packages/signer`：收訂單＋鏈 → 驗 → 更新累計 → 以 API wallet 簽 → 送 testnet
- builder fee 接入
- 子 agent 用 MCP tool 送單（`place_order` 附鏈）
- 產出：兩層委派在 testnet 真實下單；壞鏈被擋

### Phase 2 — Demo：金庫 leader 雇兩個外部策略 agent
- leader agent 發 c₁、c₁' 給策略 A、B（限額不同，互相看不到）
- A 再委派 A1；B 試圖 5x 超槓桿被擋；A1 試圖在 nonce 重放被擋
- 儀表板：鏈、每筆驗證結果、累計狀態；明確標示 testnet
- 60 秒影片
- 產出：demo、`bench/`（簽名器延遲）

### Phase 3 — ZK 電路（對應模組 E、F）
- k=4 電路：驗簽 ×4、範圍 ⊆、訂單 ⊆、累計狀態差值、nonce
- benchmark；arXiv 技術報告「ZK delegation chains for agent trading」
- 產出：`circuits/mandate_k4`、報告

### Phase 4 — 企業線（並行）
- 「交易團隊的 agent 授權管理」：簽發根授權、看鏈、撤銷、稽核、累計風險報表
- 客群：跑 agent 艦隊的交易者、金庫經理、策略市集

### Phase 5 — v1 金庫合約 + v2 對外證明
- HyperEVM 合約：持資金、驗鏈／證明、CoreWriter 下單、precompile 算累計
- 「可證明受限的金庫」：存款人驗 π
- 外部審計；設計夥伴：Hyperliquid 金庫 leader、策略市集

## 7. 學習地圖對應

模組順序不變（B → C → A → E → F → D → G → H → I → J），調整：
- C3 累計型範圍升為 MVP 必修
- G 新增：Hyperliquid API（nonce、API wallet、subaccount、builder fee）、HyperEVM precompile、CoreWriter；x402 延後
- I2 託管與爭議改為：金庫存款人保護、策略 agent 的押金
- H2 新增：API wallet 註銷後的 nonce 重放（Hyperliquid 文件自述的坑）

## 8. 宣傳

- 第一週同時出：repo、demo 影片（金庫 leader 雇兩個外部策略 agent）、技術報告
- 場域：Hyperliquid 開發者社群、HyperEVM builder 生態、ethresear.ch、X crypto-dev
- 標準：zk-attach slot（2608.30083）用於訂單訊息；向 Hyperliquid 社群提「scoped agent wallet」討論
- Grant：EF ESP（委派 RFP）、HyperEVM 生態 grant、ETHGlobal
- 命名：產品名不放 ZK；買方搜尋 agent authorization / sub-agent / risk limits

## 9. 商業模式（順序）

1. **Builder fee**：每筆經簽名器驗證的訂單抽 bp（協定原生、交易量今天就存在）
2. **簽名器訂閱**：交易團隊按席位／按 agent 數
3. **可證明受限金庫**：金庫 leader 付費取得「存款人可驗證」標章；存款人端免費
4. **授權與履約歷史 → 信用／保險**：子 agent 的可驗證紀錄賣給保險核保、策略市集評級
5. 不發幣

## 10. 風險與對策

| 風險 | 對策 |
|---|---|
| Cobo 加子 agent | 先定義多層語意與標準；主攻「子 agent 不是自己的」場景；對第三方可驗證（封閉託管無動機做） |
| Hyperliquid 原生加範圍權限 | 單層被商品化對本專案有利；多層與對外證明仍在 |
| 政策簽名器構成託管（台灣 VASP） | Phase 1 前查清；必要時 MPC 分片由客戶自持，或直接跳 v1 非託管 |
| Hyperliquid 單一平台依賴 | 鏈格式與簽名器與交易所無關；第二個交易所介面保留 |
| API wallet 註銷後 nonce 重放 | 每個子 agent 流程獨立 API wallet、不重用地址、簽名器自己記 nonce |
| CoreWriter 數秒延遲 | v1 只服務中低頻；高頻留 v0 |
| 策略洩漏 | 子 agent 只看到自己的範圍；ZK 版對外不揭露 |
| 末端 agent 被 prompt injection | 本專案只管授權層；累計限額是最後防線；文件明寫 |
| 學習進度 | repo 進度 = 理解進度；電路不早於模組 F |

## 11. 成功指標

- Phase 0：簽章鏈 + 十種對抗測試全擋
- Phase 1：testnet 上兩層委派真實下單；簽名器驗證 < 10 ms
- Phase 2：demo 影片；一個 Hyperliquid 金庫 leader 或策略團隊願意試用
- Phase 3：k=4 電路證明 < 10 s、驗證 < 50 ms；arXiv 報告上線
- 第 6 個月：一個付費交易團隊；builder fee 有真實收入（哪怕很小）
- 第 12 個月：HyperEVM 金庫合約上線；一個「可證明受限金庫」有外部存款人

## 12. 參考

**本垂直**
- Hyperliquid — Nonces and API wallets — https://hyperliquid.gitbook.io/Hyperliquid-docs/for-developers/api/nonces-and-api-wallets
- Hyperliquid — Interacting with HyperCore (CoreWriter) — https://hyperliquid.gitbook.io/Hyperliquid-docs/for-developers/hyperevm/interacting-with-hypercore
- Chainstack — Hyperliquid CoreWriter — https://docs.chainstack.com/docs/hyperliquid-corewriter
- `@nktkas/hyperliquid` TS SDK — https://jsr.io/@nktkas/hyperliquid
- Cobo Agentic Wallet for Hyperliquid（2026-05）— https://www.cobo.com/post/agentic-wallet-hyperliquid-ai-trading
- MetaMask Agent Wallet（2026-08）— https://coinpaprika.com/news/metamask-turns-ai-agents-loose-crypto-trading/
- Binance Agent OS / Agent ID（2026-08 / 2026-10）— https://crypto.news/binance-agent-id-ai-wallet-names/

**協定與論文（同 v0.1）**
- ZK Predicate Proofs Between AI Agents — arXiv 2608.30083 — github.com/45h0kg/zk-proof-gateway
- AIP — arXiv 2603.24775 — github.com/sunilp/aip
- Authenticated Delegation — arXiv 2501.09674
- BAID — arXiv 2512.17538
- Behavioral Privacy Leakage in Negotiation — arXiv 2607.06815
- ERC-8004 empirical — arXiv 2606.26028
- Tool Receipts, Not ZK — arXiv 2603.10060
- EF ESP PhD RFP（Delegation）— https://esp.ethereum.foundation/rounds/phdfp26/phdfp-rfpd3
- Noir — https://noir-lang.org
- 完整論文地圖：reports/ZK crypto agent 論文商業化.md

---

*給 Claude / 協作者：本文件為專案單一事實來源；v0.1 的通用 A2A 版本保留在 git 歷史。*
