import { isHexBytes, verifyProof, type PubKey, type Sig, type SigVerifier } from "@mandate/core";
import {
  CLOCK_SKEW_S,
  accept,
  encodeAsset,
  isPlainObject,
  orderBodyProblem,
  orderSigningBytes,
  orderWithinScope,
  reject,
  snapshot,
  verifyChain,
  type Chain,
  type Order,
  type OrderBody,
  type Result,
  type VerifiedMandate,
  type VerifyContext,
} from "@mandate/chain";
import type { NonceStore } from "./nonce-store.js";
import type { RevocationList } from "./revocation.js";
import type { CumulativeState } from "./state.js";

export interface PolicyVerifierOptions {
  audience: string;
  /** 事先信任的根源公鑰（INV-12）。 */
  trustedRoots: ReadonlySet<PubKey>;
  nonces: NonceStore;
  revocations: RevocationList;
  cumulative: CumulativeState;
  sigv: SigVerifier;
  /** unix 秒；未給時用系統時鐘。 */
  clock?: () => number;
}

export interface Decision {
  mandate: VerifiedMandate;
  order: Order;
}

const systemClock = (): number => Math.floor(Date.now() / 1000);

/**
 * 政策驗證器（v0 的強制點，先不接 Hyperliquid）。
 * verifyOrder 順序（INV-13）：
 *   1. verifyChain(chain) → leaf: VerifiedMandate（之後所有授權內容只從 leaf 讀，INV-6）
 *   2. order 快照；body.v === 1（INV-1）；欄位齊全（INV-8）
 *   3. Verify(leaf.subject, orderBytes, order.sig)（INV-8）
 *   4. order.mandateId == leaf.mandateId（INV-8）；order.audience == this.audience（INV-5）
 *   5. issuedAt < expiresAt；issuedAt ≤ now + CLOCK_SKEW_S；now < expiresAt（INV-9 的「過期」半邊）
 *   6. verifyProof(leaf.scope.assetsRoot, asset, assetProof)（INV-7；root 只從 leaf 讀，INV-6）
 *   7. orderWithinScope(order, leaf.scope, now)（INV-10b）
 *   8. cumulative（v0 跳過，TODO C3）
 *   9. nonces.seenOrRecord(leaf.subject, nonce, expiresAt) == false（INV-9）— 放最後，確保被拒的單不消耗 nonce
 */
export class PolicyVerifier {
  constructor(private readonly opts: PolicyVerifierOptions) {}

  async verifyOrder(chain: Chain, order: Order): Promise<Result<Decision>> {
    const now = (this.opts.clock ?? systemClock)();
    const ctx: VerifyContext = {
      audience: this.opts.audience,
      now,
      trustedRoots: this.opts.trustedRoots,
      isRevoked: (id) => this.opts.revocations.isRevoked(id),
    };

    // 1. 先驗鏈（INV-13）；leaf 是 scope / root / subject 的唯一來源（INV-6）
    const chainResult = await verifyChain(chain, ctx, this.opts.sigv);
    if (!chainResult.ok) return chainResult;
    const leaf = chainResult.value;

    // 2. 訂單快照 + tag/版本（INV-1）+ 欄位（INV-8）
    let o: unknown;
    try {
      o = snapshot(order);
    } catch {
      return reject("fields", "order is not plain data");
    }
    if (!isPlainObject(o) || !isPlainObject(o.body)) return reject("tag", "order has no body");  // INV-1
    if (o.body.v !== 1) return reject("tag", "expected ORDER/v1 body (v=1)");                      // INV-1
    const fp = orderBodyProblem(o.body);
    if (fp) return reject("fields", `order.${fp}`);                                                 // INV-8
    if (!isHexBytes(o.sig, 64)) return reject("fields", "order.sig: expected 64-byte hex");         // INV-8
    const body = o.body as unknown as OrderBody;
    const sig = o.sig as Sig;

    // 3. 訂單簽章必須由末端授權的 subject 簽（INV-8）；公鑰只從 leaf 讀（INV-6）
    let sigOk = false;
    try {
      sigOk = await this.opts.sigv.verify(leaf.body.subject, orderSigningBytes(body), sig);
    } catch {
      sigOk = false;
    }
    if (!sigOk) return reject("sig", "order signature does not verify under mandate subject");     // INV-8

    // 4. 鏈接與 audience
    if (body.mandateId !== leaf.body.mandateId) return reject("link", "order.mandateId != leaf mandateId"); // INV-8
    if (body.audience !== this.opts.audience) return reject("audience", "order audience is not this verifier"); // INV-5

    // 5. 生命週期。時鐘偏移只放寬 issuedAt（+CLOCK_SKEW_S），expiresAt 嚴格（spec §4）。
    if (!(body.issuedAt < body.expiresAt)) return reject("time", "order issuedAt >= expiresAt");   // INV-9
    if (!(body.issuedAt <= now + CLOCK_SKEW_S)) return reject("time", "order issuedAt is in the future"); // INV-9
    if (!(now < body.expiresAt)) return reject("time", "order expired");                            // INV-9

    // 6. 資產 membership，只對照 leaf.scope.assetsRoot（INV-7；INV-6）
    if (!verifyProof(leaf.body.scope.assetsRoot, encodeAsset(body.asset), body.assetProof)) {
      return reject("scope", "asset not in mandate whitelist");                                      // INV-7
    }

    // 7. 其餘 scope（INV-10b）
    if (!orderWithinScope(body, leaf.body.scope, now)) {
      return reject("scope", "order exceeds mandate scope");                                         // INV-10b
    }

    // 8. 累計型 scope：v0 不判定（TODO C3）。this.opts.cumulative 保留給 C3。

    // 9. nonce 最後（INV-9）：只有走到這裡的單才會消耗 nonce。鍵為 (subject, nonce)，subject 只從 leaf 讀（INV-6）
    if (this.opts.nonces.seenOrRecord(leaf.body.subject, body.nonce, body.expiresAt)) {
      return reject("nonce", "nonce already seen (replay)");                                         // INV-9
    }

    return accept({ mandate: leaf, order: { body, sig } });
  }
}
