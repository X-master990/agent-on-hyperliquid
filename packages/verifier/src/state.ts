import type { Hex } from "@mandate/core";

/**
 * 累計型 scope 的狀態（INV-10b 後半）。v0 只定義介面，不判定。
 * TODO(C3)：起算點、重置、以 mandateId 為 key 還是以整條鏈為 key。
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
