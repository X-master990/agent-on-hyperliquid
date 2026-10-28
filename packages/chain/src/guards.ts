import { isHexBytes } from "@mandate/core";
import type { Reject, Result } from "./types.js";

/* ---------- Result 建構 ---------- */

export function reject(step: Reject["step"], reason: string, at?: number): Reject {
  return at === undefined ? { ok: false, step, reason } : { ok: false, step, reason, at };
}

export function accept<T>(value: T): Result<T> {
  return { ok: true, value };
}

/* ---------- 基本型別守衛 ---------- */

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
export function isSafeInt(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v);
}
export function isNonNegInt(v: unknown): v is number {
  return isSafeInt(v) && v >= 0;
}
export function isNonNegBigint(v: unknown): v is bigint {
  return typeof v === "bigint" && v >= 0n;
}

/**
 * 防禦性快照：structuredClone 會呼叫每個 getter 一次並產生 plain data，
 * 之後所有檢查都讀同一份副本，避免「驗簽時讀到 A、讀 scope 時讀到 B」。
 * 函式 / symbol / 非 plain 物件會丟錯，由呼叫端轉成 Reject。
 */
export function snapshot<T>(v: T): T {
  return structuredClone(v);
}

/* ---------- 欄位檢查（回 null 表示合格；否則回缺陷描述） ---------- */

/** INV-4 的 scope 部分：三種 v0 欄位齊全且型別正確。 */
export function scopeProblem(s: unknown): string | null {
  if (!isPlainObject(s)) return "scope: not an object";
  if (!isHexBytes(s.assetsRoot, 32)) return "scope.assetsRoot: expected 32-byte hex";
  if (!isNonNegBigint(s.maxNotional)) return "scope.maxNotional: expected non-negative bigint";
  if (!isNonNegInt(s.maxLeverageBps)) return "scope.maxLeverageBps: expected non-negative integer";
  const w = s.window;
  if (!isPlainObject(w) || !isNonNegInt(w.notBefore) || !isNonNegInt(w.notAfter)) {
    return "scope.window: expected {notBefore, notAfter} integers";
  }
  if (w.notBefore > w.notAfter) return "scope.window: notBefore > notAfter";
  if (s.dailyNotional !== undefined && !isNonNegBigint(s.dailyNotional)) {
    return "scope.dailyNotional: expected non-negative bigint"; // INV-4（C3a，ADR-0004）
  }
  if (s.dailyLoss !== undefined && !isNonNegBigint(s.dailyLoss)) {
    return "scope.dailyLoss: expected non-negative bigint"; // TODO(C3b): 只檢型別，不判定
  }
  return null;
}

/** INV-4：授權必要欄位齊全且型別正確（不含 v，v 在 'tag' 步驟檢）。 */
export function mandateBodyProblem(b: unknown): string | null {
  if (!isPlainObject(b)) return "body: not an object";
  if (!isHexBytes(b.mandateId, 32)) return "mandateId: expected 32-byte hex";        // INV-4
  if (b.parentId !== null && !isHexBytes(b.parentId, 32)) return "parentId: expected null or 32-byte hex"; // INV-4
  if (!isHexBytes(b.issuer, 32)) return "issuer: expected 32-byte pubkey";           // INV-4
  if (!isHexBytes(b.subject, 32)) return "subject: expected 32-byte pubkey";         // INV-4
  if (typeof b.audience !== "string" || b.audience.length === 0) return "audience: expected non-empty string"; // INV-4
  if (!isNonNegInt(b.issuedAt)) return "issuedAt: expected integer";                 // INV-4
  if (!isNonNegInt(b.expiresAt)) return "expiresAt: expected integer";               // INV-4
  if (!isNonNegInt(b.maxDepth)) return "maxDepth: expected non-negative integer";    // INV-4
  const sp = scopeProblem(b.scope);                                                   // INV-4
  return sp;
}

/** Merkle proof 的形狀（內容正確與否由 verifyProof 判定，INV-7）。 */
export function merkleProofProblem(p: unknown): string | null {
  if (!isPlainObject(p)) return "assetProof: not an object";
  if (!Array.isArray(p.siblings) || !Array.isArray(p.path)) return "assetProof: siblings/path must be arrays";
  if (p.siblings.length !== p.path.length) return "assetProof: siblings/path length mismatch";
  if (!p.siblings.every((s) => isHexBytes(s, 32))) return "assetProof.siblings: expected 32-byte hex";
  if (!p.path.every((b) => b === 0 || b === 1)) return "assetProof.path: expected 0|1";
  return null;
}

/** INV-8：訂單必要欄位齊全且型別正確（不含 v，v 在 'tag' 步驟檢）。 */
export function orderBodyProblem(b: unknown): string | null {
  if (!isPlainObject(b)) return "body: not an object";
  if (!isHexBytes(b.mandateId, 32)) return "mandateId: expected 32-byte hex";          // INV-8
  if (typeof b.audience !== "string" || b.audience.length === 0) return "audience: expected non-empty string"; // INV-8
  if (!isHexBytes(b.nonce, 32)) return "nonce: expected 32-byte hex";                  // INV-8
  if (!isNonNegInt(b.issuedAt)) return "issuedAt: expected integer";                   // INV-8
  if (!isNonNegInt(b.expiresAt)) return "expiresAt: expected integer";                 // INV-8
  if (typeof b.asset !== "string" || b.asset.length === 0) return "asset: expected non-empty string";
  const pp = merkleProofProblem(b.assetProof);
  if (pp) return pp;
  // 拍板（spec §5）：訂單側 notional / leverageBps 必須 ≥ 1；scope 側上限可為 0（關閘語意）。
  if (typeof b.notional !== "bigint" || b.notional < 1n) return "notional: expected positive bigint";  // INV-8
  if (!isSafeInt(b.leverageBps) || b.leverageBps < 1) return "leverageBps: expected positive integer"; // INV-8
  if (b.side !== "buy" && b.side !== "sell") return "side: expected 'buy' | 'sell'";
  return null;
}
