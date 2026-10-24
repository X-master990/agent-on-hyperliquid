import type { Hash, Hex, PubKey, Sig } from "@mandate/core";
import type { MerkleProof } from "@mandate/core";

/* ---------- Scope（ADR-0001：v0 三種型態） ---------- */

export interface TimeWindow { notBefore: number; notAfter: number } // unix seconds

export interface Scope {
  /** 資產白名單 Merkle root（INV-7） */
  assetsRoot: Hash;
  /** 單筆名目上限，最小單位整數（例如 USDC 6 位小數） */
  maxNotional: bigint;
  /** 槓桿 ×100（3x = 300），避免浮點 */
  maxLeverageBps: number;
  window: TimeWindow;
  /** 累計型，v0 不判定（TODO C3） */
  dailyLoss?: bigint;
}

/* ---------- Mandate ---------- */

export interface MandateBody {
  v: 1;
  mandateId: Hex;          // 隨機 32 bytes
  parentId: Hex | null;    // 根授權為 null（INV-10a 鏈接）
  issuer: PubKey;          // 簽這張的人；非根時 = 上層 subject
  subject: PubKey;         // 拿到這張的人
  audience: string;        // 給哪個驗證者用（INV-5）
  issuedAt: number;
  expiresAt: number;
  maxDepth: number;        // 從這張往下還能轉幾層；0 = 不能再轉
  scope: Scope;
}

export interface Mandate {
  body: MandateBody;
  sig: Sig;                // Sign(issuer, tagged(TAG.MANDATE, canonical(body)))
}

/**
 * 驗簽 + 語意檢查都通過的授權（INV-6）。
 * 只有 verifyChain() 能產生；讀 scope 的函式只接受這個型別。
 */
declare const VERIFIED: unique symbol;
export type VerifiedMandate = Readonly<Mandate> & {
  readonly [VERIFIED]: true;
  readonly depth: number;  // 0 = 根
};

/** c₀ … cₙ，由根到末端 */
export interface Chain { mandates: Mandate[] }

/* ---------- Order ---------- */

export type Side = "buy" | "sell";

export interface OrderBody {
  v: 1;
  mandateId: Hex;          // 所屬（末端）授權（INV-8）
  audience: string;        // INV-5
  nonce: Hex;              // INV-8/9
  issuedAt: number;
  expiresAt: number;
  asset: string;           // 例如 "BTC"
  assetProof: MerkleProof; // 對照 VerifiedMandate.scope.assetsRoot（INV-7）
  notional: bigint;
  leverageBps: number;
  side: Side;
}

export interface Order {
  body: OrderBody;
  sig: Sig;                // Sign(subject of mandateId, tagged(TAG.ORDER, canonical(body)))
}

/* ---------- 驗證上下文 ---------- */

export interface VerifyContext {
  /** 我是誰（INV-5） */
  audience: string;
  now: number;
  /** 事先信任的根源公鑰（INV-12） */
  trustedRoots: ReadonlySet<PubKey>;
  isRevoked(mandateId: Hex): boolean;
}

export type Reject =
  | { ok: false; step: "tag" | "sig" | "link" | "root" | "fields" | "audience" | "time" | "revoked" | "scope" | "depth" | "nonce"; reason: string; at?: number };
export type Accept<T> = { ok: true; value: T };
export type Result<T> = Accept<T> | Reject;
