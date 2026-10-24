import type { Hex } from "@mandate/core";

/** v0：記憶體黑名單。v1：SMT non-membership（TODO C4）。 */
export interface RevocationList {
  revoke(mandateId: Hex, at: number): void;
  isRevoked(mandateId: Hex): boolean;
}

/**
 * 記憶體版。`at` 先記下但 v0 不用（撤銷即時生效，無「生效時間」語意，TODO C4）。
 * 撤銷不可撤回：再呼叫 revoke 不會覆蓋第一次的 at。
 */
export class MemoryRevocationList implements RevocationList {
  readonly #revoked = new Map<Hex, number>();

  revoke(mandateId: Hex, at: number): void {
    if (!this.#revoked.has(mandateId)) this.#revoked.set(mandateId, at);
  }

  isRevoked(mandateId: Hex): boolean {
    return this.#revoked.has(mandateId);
  }
}
