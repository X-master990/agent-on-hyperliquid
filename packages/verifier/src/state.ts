import type { Hex } from "@mandate/core";

/**
 * 累計型 scope 的狀態（INV-10b 後半）。v0 只定義介面，不判定。
 * 設計已拍板（ADR-0004）：C3a 做 dailyNotional、UTC 日界重置、以 (mandateId, UTC 日) 為鍵、
 * 一張被接受的單入帳鏈上每一層。實作需 verifyChain 回傳全層（型別變更，先提議再動）。
 */
export interface CumulativeState {
  /** 回傳該授權今日已實現虧損（最小單位） */
  dailyLoss(mandateId: Hex, now: number): bigint;
  record(mandateId: Hex, pnlDelta: bigint, at: number): void;
}

export class NoopCumulativeState implements CumulativeState {
  dailyLoss(): bigint { return 0n; }
  record(): void {}
}
