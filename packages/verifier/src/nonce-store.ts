import type { Hex, PubKey } from "@mandate/core";

/**
 * 未過期 nonce 帳本（INV-9）。獨立於交易所。
 * 鍵為 (subject, nonce)（spec §5 拍板）：防跨 subject 惡意佔用——
 * 看見他人在途 nonce 的攻擊者，無法用自己的合法單搶先燒掉它。
 * seenOrRecord() 必須原子：檢查 + 記錄一次完成，避免並發重放。
 */
export interface NonceStore {
  /** 同一 (subject, nonce) 已見過 → true；否則記錄並回 false */
  seenOrRecord(subject: PubKey, nonce: Hex, expiresAt: number): boolean;
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
  readonly #seen = new Map<string, number>();

  seenOrRecord(subject: PubKey, nonce: Hex, expiresAt: number): boolean {
    const key = `${subject}:${nonce}`;
    if (this.#seen.has(key)) return true; // INV-9
    this.#seen.set(key, expiresAt);
    return false;
  }

  prune(now: number): void {
    for (const [key, exp] of this.#seen) {
      if (exp < now) this.#seen.delete(key);
    }
  }

  size(): number {
    return this.#seen.size;
  }
}
