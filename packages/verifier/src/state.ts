import type { Hex } from "@mandate/core";

/** UTC 日索引：floor(unix 秒 / 86400)（ADR-0004：UTC 日界重置，不採滾動 24h）。 */
export function utcDay(nowSec: number): number {
  return Math.floor(nowSec / 86_400);
}

/**
 * 累計型 scope 的狀態（INV-14，ADR-0004）。鍵為 (mandateId, UTC 日)。
 * 檢查在 verifyOrder 第 8 步（usedOn），入帳在 nonce 之後（charge）——
 * 被拒的單不入帳，與 nonce 同哲學（INV-13）。
 * 第 8 步到 charge 之間沒有 await，JS 單執行緒下 check→charge 原子；
 * 換持久化後端時必須保留這個語意。dailyLoss（C3b）之後擴充此介面。
 */
export interface CumulativeState {
  /** 該授權在該 UTC 日已入帳的累計名目（無記錄 → 0n）。 */
  usedOn(mandateId: Hex, day: number): bigint;
  /** accept 後入帳（一張單入帳鏈上每一層，ADR-0004）。 */
  charge(mandateId: Hex, day: number, notional: bigint): void;
  /** 清掉 day < beforeDay 的記錄。 */
  prune(beforeDay: number): void;
}

/** 記憶體版。Phase 1 落地持久化時替換，語意見介面註解。 */
export class MemoryCumulativeState implements CumulativeState {
  readonly #used = new Map<string, bigint>();

  usedOn(mandateId: Hex, day: number): bigint {
    return this.#used.get(`${mandateId}:${day}`) ?? 0n;
  }

  charge(mandateId: Hex, day: number, notional: bigint): void {
    const key = `${mandateId}:${day}`;
    this.#used.set(key, (this.#used.get(key) ?? 0n) + notional);
  }

  prune(beforeDay: number): void {
    for (const key of this.#used.keys()) {
      const day = Number(key.slice(key.lastIndexOf(":") + 1));
      if (day < beforeDay) this.#used.delete(key);
    }
  }
}
