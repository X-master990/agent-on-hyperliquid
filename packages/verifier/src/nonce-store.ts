import type { Hex } from "@mandate/core";

/**
 * 未過期 nonce 集合（INV-9）。獨立於交易所。
 * seenOrRecord() 必須原子：檢查 + 記錄一次完成，避免並發重放。
 * TODO(spec): nonce 命名空間——v0 為全域（nonce 是 32 bytes 隨機值，跨 subject 撞到視為不可能）。
 */
export interface NonceStore {
  /** 已見過 → true；否則記錄並回 false */
  seenOrRecord(nonce: Hex, expiresAt: number): boolean;
  /** 清掉 expiresAt < now 的 nonce */
  prune(now: number): void;
  size(): number;
}

/**
 * 記憶體版。JS 單執行緒 + 同步方法 ⇒ seenOrRecord 天然原子；
 * 換成持久化後端時必須保留「check-and-set 一次完成」的語意（INV-9）。
 * 尚未 prune 的過期 nonce 仍視為「已見過」（較保守）。
 */
export class MemoryNonceStore implements NonceStore {
  readonly #seen = new Map<Hex, number>();

  seenOrRecord(nonce: Hex, expiresAt: number): boolean {
    if (this.#seen.has(nonce)) return true; // INV-9
    this.#seen.set(nonce, expiresAt);
    return false;
  }

  prune(now: number): void {
    for (const [nonce, exp] of this.#seen) {
      if (exp < now) this.#seen.delete(nonce);
    }
  }

  size(): number {
    return this.#seen.size;
  }
}
