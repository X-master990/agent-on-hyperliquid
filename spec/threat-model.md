# Threat Model（v0.0 — 骨架）

## 參與者與能力
| 參與者 | 能做什麼 | 想做什麼壞事 |
|---|---|---|
| 委託人 / leader | 簽根授權 | — |
| 中間層 agent | 轉授權、下單 | 放大授權、轉給不該轉的人 |
| 末端 agent | 下單 | 超額、重放、換樹 |
| 政策簽名器 | 驗證、簽 API wallet | （v0 被信任）偽造？洩漏？ |
| 交易所 | 執行 | nonce 狀態被清（已知） |
| 外部攻擊者 | 攔截訊息 | 重放、拼接鏈 |

## 攻擊清單 → 對應不變量 → 對應測試
| 攻擊 | INV | 測試 |
|---|---|---|
| 訂單簽章當授權用 | 1 | attacks: INV-1 |
| 內節點當葉子 | 2 | attacks: INV-2 |
| 窮舉承諾 | 3 | attacks: INV-3 |
| 缺欄位授權 | 4 | attacks: INV-4 |
| 跨驗證者 | 5 | attacks: INV-5 |
| 訂單自帶 root | 6 | attacks: INV-6 |
| 錯 root 的 proof | 7 | attacks: INV-7 |
| 訂單缺 nonce | 8 | attacks: INV-8 |
| 重放 / 過期 | 9 | attacks: INV-9 |
| 中間層放大 | 10a | attacks: INV-10a |
| 超額 / 超槓桿 / 窗外 | 10b | attacks: INV-10b |
| 自簽根授權 | 12 | attacks: INV-12 |
| 鏈拼接（issuer ≠ 上層 subject） | 10a | attacks: linkage |
| 深度耗盡後再轉 | 10a | attacks: depth |

## 尚未處理（明寫）
- 時鐘偏移：TODO 決定容忍值
- 末端 agent 被 prompt injection：授權層不解，累計限額是最後防線
- 簽名器本身被攻陷：v0 信任假設；v1 合約化
