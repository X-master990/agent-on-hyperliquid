import { randomBytes, toHex, type Signer } from "@mandate/core";
import { mandateSigningBytes } from "./bytes.js";
import { isNonNegInt } from "./guards.js";
import { isSubset } from "./scope.js";
import type { Mandate, MandateBody, Scope, VerifiedMandate } from "./types.js";

export interface DelegateParams {
  subject: Mandate["body"]["subject"];
  expiresAt: number;
  scope: Scope;
  /** 未給時用系統時鐘（unix 秒）。測試與重放需要可指定。 */
  issuedAt?: number;
}

/**
 * 持有 parent 的 agent 轉授權給 subject。
 * 必須：signer.publicKey === parent.body.subject；
 *       scope ⊆ parent.scope；expiresAt ≤ parent.expiresAt；
 *       parent.maxDepth ≥ 1，新 maxDepth = parent.maxDepth − 1；
 *       audience 繼承；parentId = parent.mandateId。
 * 只接受 VerifiedMandate（INV-6）。違反任一條直接丟錯（簽發端不該產出壞鏈）。
 */
export async function delegate(signer: Signer, parent: VerifiedMandate, p: DelegateParams): Promise<Mandate> {
  const pb = parent.body;
  if (signer.publicKey !== pb.subject) {
    throw new Error("delegate: signer is not the parent's subject"); // INV-10a（issuer = 上層 subject）
  }
  if (pb.maxDepth < 1) {
    throw new Error("delegate: parent maxDepth exhausted"); // INV-10a（maxDepth − 1 ≥ 0）
  }
  if (!isSubset(p.scope, pb.scope)) {
    throw new Error("delegate: scope is not a subset of parent scope"); // INV-10a（scope ⊆）
  }
  const issuedAt = p.issuedAt ?? Math.floor(Date.now() / 1000);
  if (!isNonNegInt(issuedAt) || !isNonNegInt(p.expiresAt) || p.expiresAt <= issuedAt) {
    throw new Error("delegate: expiresAt must be > issuedAt");
  }
  if (p.expiresAt > pb.expiresAt) {
    throw new Error("delegate: expiresAt exceeds parent expiresAt");
  }
  const body: MandateBody = {
    v: 1,
    mandateId: toHex(randomBytes(32)),
    parentId: pb.mandateId,         // INV-10a（鏈接）
    issuer: signer.publicKey,       // INV-10a（= 上層 subject）
    subject: p.subject,
    audience: pb.audience,          // INV-5（繼承）
    issuedAt,
    expiresAt: p.expiresAt,
    maxDepth: pb.maxDepth - 1,      // INV-10a
    scope: p.scope,
  };
  const sig = await signer.sign(mandateSigningBytes(body));
  return { body, sig };
}
