import { isHexBytes, type Sig, type SigVerifier } from "@mandate/core";
import { mandateSigningBytes } from "./bytes.js";
import { accept, isPlainObject, mandateBodyProblem, reject, snapshot } from "./guards.js";
import { isSubset } from "./scope.js";
import type { Chain, Mandate, MandateBody, Result, VerifiedMandate, VerifyContext } from "./types.js";

/**
 * 驗整條鏈，回傳末端的 VerifiedMandate（INV-13 順序）：
 * 對每個 cᵢ：
 *   0. 快照（structuredClone）：之後所有檢查只讀這份 plain data
 *   1. tag / 版本：body.v === 1（INV-1）
 *   2. 欄位齊全（INV-4）
 *   3. 簽章：Verify(cᵢ.issuer, bytes, sig)
 *   4. i == 0：issuer ∈ trustedRoots（INV-12）且 parentId == null
 *      i  > 0：issuer == cᵢ₋₁.subject && parentId == cᵢ₋₁.mandateId（INV-10a）
 *   5. audience == ctx.audience（INV-5）
 *   6. issuedAt < expiresAt；issuedAt ≤ now + CLOCK_SKEW_S；now < expiresAt；expiresAt ≤ 上層 expiresAt
 *   7. !isRevoked(mandateId)
 *   8. i > 0：maxDepth == 上層 − 1（INV-10a）；isSubset(cᵢ.scope, cᵢ₋₁.scope)（INV-10a）
 * 任一步失敗 → Reject{step, at: i}；不繼續。
 *
 * 關於 'tag' 步驟：資料模型是 {body, sig}，驗證者自己綁 tag 再驗簽，
 * 所以「用 ORDER tag 簽的東西冒充授權」會在 'sig' 步驟被擋（簽章對不上 MANDATE tag）；
 * 'tag' 步驟能擋的是版本不符（body.v ≠ 1）與沒有 body 的輸入。
 */
/** 時鐘偏移容忍（秒）：只放寬 issuedAt，expiresAt 嚴格（spec/scope-semantics.md §4-§5）。 */
export const CLOCK_SKEW_S = 30;
/** 鏈長上限：輸入有界（spec §5）。 */
export const MAX_CHAIN_LENGTH = 16;

export async function verifyChain(chain: Chain, ctx: VerifyContext, sigv: SigVerifier): Promise<Result<VerifiedMandate>> {
  if (!isPlainObject(chain) || !Array.isArray(chain.mandates) || chain.mandates.length === 0) {
    return reject("fields", "chain.mandates must be a non-empty array");
  }
  if (chain.mandates.length > MAX_CHAIN_LENGTH) {
    return reject("fields", `chain too long (> ${MAX_CHAIN_LENGTH})`); // INV-4：鏈輸入有界
  }
  let prev: VerifiedMandate | null = null;
  for (let i = 0; i < chain.mandates.length; i++) {
    const r = await verifyOne(chain.mandates[i], i, prev, ctx, sigv);
    if (!r.ok) return r;
    prev = r.value;
  }
  return accept(prev as VerifiedMandate);
}

async function verifyOne(
  raw: unknown,
  i: number,
  prev: VerifiedMandate | null,
  ctx: VerifyContext,
  sigv: SigVerifier,
): Promise<Result<VerifiedMandate>> {
  // 0. 快照
  let m: unknown;
  try {
    m = snapshot(raw);
  } catch {
    return reject("fields", "mandate is not plain data", i);
  }

  // 1. tag / 版本（INV-1）
  if (!isPlainObject(m) || !isPlainObject(m.body)) return reject("tag", "mandate has no body", i); // INV-1
  if (m.body.v !== 1) return reject("tag", "expected MANDATE/v1 body (v=1)", i);                   // INV-1

  // 2. 欄位（INV-4）
  const fp = mandateBodyProblem(m.body);
  if (fp) return reject("fields", fp, i);                                                           // INV-4
  if (!isHexBytes(m.sig, 64)) return reject("fields", "sig: expected 64-byte hex", i);              // INV-4
  const body = m.body as unknown as MandateBody;
  const sig = m.sig as Sig;

  // 3. 簽章（只用 body 自己宣稱的 issuer；issuer 是否可信在第 4 步）
  let sigOk = false;
  try {
    sigOk = await sigv.verify(body.issuer, mandateSigningBytes(body), sig);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return reject("sig", "signature does not verify under issuer", i);

  // 4. 根源 / 鏈接
  if (prev === null) {
    if (!ctx.trustedRoots.has(body.issuer)) return reject("root", "root issuer not in trustedRoots", i); // INV-12
    // 假設：根授權必須 parentId = null；帶 parentId 的子授權不得當根提交（否則可跳過上層的撤銷）。
    if (body.parentId !== null) return reject("link", "root mandate must have parentId null", i);        // INV-10a
  } else {
    if (body.issuer !== prev.body.subject) return reject("link", "issuer != parent.subject", i);         // INV-10a
    if (body.parentId !== prev.body.mandateId) return reject("link", "parentId != parent.mandateId", i); // INV-10a
  }

  // 5. audience（INV-5）
  if (body.audience !== ctx.audience) return reject("audience", "audience is not this verifier", i);    // INV-5

  // 6. 生命週期。時鐘偏移只放寬 issuedAt（+CLOCK_SKEW_S），expiresAt 嚴格（spec §4）。
  if (!(body.issuedAt < body.expiresAt)) return reject("time", "issuedAt >= expiresAt", i);
  if (!(body.issuedAt <= ctx.now + CLOCK_SKEW_S)) return reject("time", "issuedAt is in the future", i);
  if (!(ctx.now < body.expiresAt)) return reject("time", "mandate expired", i);
  if (prev !== null && body.expiresAt > prev.body.expiresAt) {
    return reject("time", "child expiresAt exceeds parent expiresAt", i);
  }
  // 拍板（spec §4）：子授權 issuedAt 不要求 ≥ 父授權；issuedAt 僅供審計，不參與授權判定。

  // 7. 撤銷（撤銷清單出錯視為已撤銷：fail closed）
  let revoked = true;
  try {
    revoked = ctx.isRevoked(body.mandateId);
  } catch {
    revoked = true;
  }
  if (revoked) return reject("revoked", "mandate is revoked", i);

  // 8. 深度與 scope ⊆（INV-10a）
  if (prev !== null) {
    if (body.maxDepth !== prev.body.maxDepth - 1) {
      return reject("depth", "maxDepth must equal parent.maxDepth - 1", i);                               // INV-10a
    }
    if (!isSubset(body.scope, prev.body.scope)) {
      return reject("scope", "scope is not a subset of parent scope", i);                                 // INV-10a
    }
  }

  return accept(markVerified({ body, sig }, i));
}

function deepFreeze<T>(o: T): T {
  if (typeof o === "object" && o !== null && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const k of Object.keys(o)) deepFreeze((o as Record<string, unknown>)[k]);
  }
  return o;
}

/**
 * 內部：把（已快照、已通過全部檢查的）Mandate 標記成 VerifiedMandate。
 * 只能在 verifyChain 內呼叫；不對外匯出，外部拿到 VerifiedMandate 的唯一途徑是 verifyChain（INV-6）。
 */
function markVerified(m: Mandate, depth: number): VerifiedMandate {
  const frozen = deepFreeze({ body: m.body, sig: m.sig, depth });
  return frozen as unknown as VerifiedMandate;
}
