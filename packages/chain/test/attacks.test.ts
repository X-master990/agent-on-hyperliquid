import { describe, it, expect, beforeEach } from "vitest";
import { TAG, tagged, canonicalBytes, ed25519Verifier, fromHex, toHex, randomBytes } from "@mandate/core";
import { CLOCK_SKEW_S, MAX_CHAIN_LENGTH, delegate, issueRoot, verifyChain, type Mandate, type MandateBody, type VerifyContext } from "@mandate/chain";
import { makeWorld, makeTree, scope, signMandate, expectReject, expectOk, NOW, DAY, USDC, AUD, type World } from "./fixtures.js";

/** 每條不變量至少一個負面測試。名稱以 INV-n 開頭。 */
describe("chain/attacks", () => {
  let w: World;
  const verify = (mandates: unknown[], ctx?: VerifyContext) =>
    verifyChain({ mandates: mandates as Mandate[] }, ctx ?? w.ctx, ed25519Verifier);

  beforeEach(async () => {
    w = await makeWorld();
  });

  /* ---------- INV-1 ---------- */

  it("INV-1: body signed under ORDER tag presented as a mandate → rejected (surfaces at 'sig')", async () => {
    // {body, sig} 模型下驗證者自己綁 MANDATE tag 再驗簽；用 ORDER tag 簽出的簽章對不上。
    const body = w.c0.body;
    const sig = await w.leader.sign(tagged(TAG.ORDER, canonicalBytes(body)));
    expectReject(await verify([{ body, sig }]), "sig", 0);
  });

  it("INV-1: body.v !== 1 → reject at 'tag'", async () => {
    const m = await signMandate(w.leader, { ...w.c0.body, v: 2 } as unknown as MandateBody);
    expectReject(await verify([m]), "tag", 0);
  });

  it("INV-1: mandate without a body → reject at 'tag'", async () => {
    expectReject(await verify([{ sig: w.c0.sig }]), "tag", 0);
    expectReject(await verify([null]), "tag", 0);
  });

  /* ---------- INV-4 ---------- */

  it("INV-4: mandate missing expiresAt → reject at 'fields'", async () => {
    const { expiresAt: _drop, ...rest } = w.c0.body;
    const m = await signMandate(w.leader, rest as MandateBody);
    expectReject(await verify([m]), "fields", 0);
  });

  it("INV-4: mandate missing maxDepth → reject at 'fields'", async () => {
    const { maxDepth: _drop, ...rest } = w.c0.body;
    const m = await signMandate(w.leader, rest as MandateBody);
    expectReject(await verify([m]), "fields", 0);
  });

  it("INV-4: scope missing window → reject at 'fields'", async () => {
    const { window: _drop, ...restScope } = w.c0.body.scope;
    const m = await signMandate(w.leader, { ...w.c0.body, scope: restScope } as MandateBody);
    expectReject(await verify([m]), "fields", 0);
  });

  it("INV-4: maxNotional given as number instead of bigint → reject at 'fields'", async () => {
    const m = await signMandate(w.leader, {
      ...w.c0.body,
      scope: { ...w.c0.body.scope, maxNotional: 100 },
    } as unknown as MandateBody);
    expectReject(await verify([m]), "fields", 0);
  });

  it("INV-4: empty chain → reject at 'fields'", async () => {
    expectReject(await verify([]), "fields");
  });

  it("INV-4: malformed hex fields (sig / mandateId / parentId / issuer / subject) → reject at 'fields'", async () => {
    // sig 壞掉必須停在 'fields'，不是 'sig'（INV-13：欄位先於簽章，畸形輸入不做簽章運算）
    expectReject(await verify([{ body: w.c0.body, sig: "0x1234" }]), "fields", 0);
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, mandateId: "0x1234" } as unknown as MandateBody)]), "fields", 0);
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, parentId: "0xzz" } as unknown as MandateBody)]), "fields", 0);
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, issuer: "not-a-key" } as unknown as MandateBody)]), "fields", 0);
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, subject: "0x12" } as unknown as MandateBody)]), "fields", 0);
  });

  it("INV-4: audience / issuedAt wrong type → reject at 'fields' (not at 'audience' / accepted)", async () => {
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, audience: 123 } as unknown as MandateBody)]), "fields", 0);
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, audience: "" } as unknown as MandateBody)]), "fields", 0);
    // 負的 issuedAt 若少了欄位檢查會被整條接受（-5 < expiresAt 且 -5 ≤ now）
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, issuedAt: -5 } as unknown as MandateBody)]), "fields", 0);
  });

  it("INV-4: scope shape and value types → reject at 'fields'", async () => {
    const r = expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, scope: "yolo" } as unknown as MandateBody)]), "fields", 0);
    expect(r.reason).toMatch(/not an object/); // 釘住第一道 scope 檢查（後面的 assetsRoot 檢查也會擋，但理由不同）
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, scope: { ...w.c0.body.scope, assetsRoot: "banana" } } as unknown as MandateBody)]), "fields", 0);
    // 負的 maxLeverageBps 若少了檢查會被接受（比較方向對負數「安全」，但那是運氣不是設計）
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, scope: { ...w.c0.body.scope, maxLeverageBps: -1 } } as unknown as MandateBody)]), "fields", 0);
    // dailyLoss 型別：v0 不判定值（TODO C3），但型別必須今天就擋，否則 C3 上線即踩雷
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, scope: { ...w.c0.body.scope, dailyLoss: 5 } } as unknown as MandateBody)]), "fields", 0);
  });

  it("INV-4: inverted scope window (notBefore > notAfter) → reject at 'fields'", async () => {
    const m = await signMandate(w.leader, {
      ...w.c0.body,
      scope: { ...w.c0.body.scope, window: { notBefore: NOW + DAY, notAfter: NOW - DAY } },
    } as unknown as MandateBody);
    expectReject(await verify([m]), "fields", 0);
  });

  it("INV-4: chain longer than MAX_CHAIN_LENGTH → reject at 'fields' before any verification", async () => {
    const r = expectReject(await verify(Array(MAX_CHAIN_LENGTH + 1).fill(w.c0)), "fields");
    expect(r.reason).toMatch(/too long/);
  });

  /* ---------- INV-5 ---------- */

  it("INV-5: mandate with audience 'signer-Y' verified by 'signer-X' → reject at 'audience'", async () => {
    const m = await signMandate(w.leader, { ...w.c0.body, audience: "signer-Y" });
    expectReject(await verify([m]), "audience", 0);
  });

  it("INV-5: whole valid chain verified by a different audience → reject at 'audience' on c0", async () => {
    expectReject(await verify(w.chain.mandates, { ...w.ctx, audience: "signer-Y" }), "audience", 0);
  });

  /* ---------- INV-10a: scope ⊆ ---------- */

  it("INV-10a: child maxLeverage 400 under parent 300 → reject at 'scope'", async () => {
    const c2 = await signMandate(w.B, { ...w.c2.body, scope: { ...w.c2.body.scope, maxLeverageBps: 400 } });
    expectReject(await verify([w.c0, w.c1, c2]), "scope", 2);
  });

  it("INV-10a: child notional > parent → reject at 'scope'", async () => {
    const c2 = await signMandate(w.B, { ...w.c2.body, scope: { ...w.c2.body.scope, maxNotional: USDC(50_000) } });
    expectReject(await verify([w.c0, w.c1, c2]), "scope", 2);
  });

  it("INV-10a: child window extends past parent → reject at 'scope'", async () => {
    const c2 = await signMandate(w.B, {
      ...w.c2.body,
      scope: { ...w.c2.body.scope, window: { notBefore: NOW - DAY, notAfter: NOW + 60 * DAY } },
    });
    expectReject(await verify([w.c0, w.c1, c2]), "scope", 2);
    const c2b = await signMandate(w.B, {
      ...w.c2.body,
      scope: { ...w.c2.body.scope, window: { notBefore: NOW - 2 * DAY, notAfter: NOW + DAY } },
    });
    expectReject(await verify([w.c0, w.c1, c2b]), "scope", 2);
  });

  it("INV-10a: child assetsRoot ≠ parent assetsRoot → reject at 'scope' (v0 root-equality rule)", async () => {
    // 即使 {BTC} 真的是 {BTC,ETH,SOL} 的子集，v0 也只認 root 相等。
    const c2 = await signMandate(w.B, {
      ...w.c2.body,
      scope: { ...w.c2.body.scope, assetsRoot: makeTree(["BTC"]).root },
    });
    expectReject(await verify([w.c0, w.c1, c2]), "scope", 2);
    // 換成含未授權資產的樹當然也被擋
    const c2b = await signMandate(w.B, {
      ...w.c2.body,
      scope: { ...w.c2.body.scope, assetsRoot: makeTree(["BTC", "ETH", "SOL", "DOGE"]).root },
    });
    expectReject(await verify([w.c0, w.c1, c2b]), "scope", 2);
  });

  /* ---------- INV-10a: 鏈接 ---------- */

  it("INV-10a: c1.issuer != c0.subject (spliced chain) → reject at 'link'", async () => {
    // D 自己簽一張 parentId 指向 c0 的授權；簽章本身有效，但 D 不是 c0 的 subject。
    const c1 = await signMandate(w.D, { ...w.c1.body, issuer: w.D.publicKey });
    expectReject(await verify([w.c0, c1]), "link", 1);
  });

  it("INV-10a: c1.parentId != c0.mandateId → reject at 'link'", async () => {
    const c1 = await signMandate(w.A, { ...w.c1.body, parentId: toHex(randomBytes(32)) });
    expectReject(await verify([w.c0, c1]), "link", 1);
  });

  it("INV-10a: a sub-mandate (parentId ≠ null) presented as the root → reject at 'link'", async () => {
    // leader 自己簽了一張 parentId 指向別張的授權，被拿來當 c0 提交（跳過上層撤銷）。
    const m = await signMandate(w.leader, { ...w.c0.body, parentId: toHex(randomBytes(32)) });
    expectReject(await verify([m]), "link", 0);
  });

  /* ---------- INV-10a: 深度 ---------- */

  it("INV-10a: maxDepth not parent−1 → reject at 'depth'", async () => {
    const same = await signMandate(w.A, { ...w.c1.body, maxDepth: 2 }); // parent is 2
    expectReject(await verify([w.c0, same]), "depth", 1);
    const skip = await signMandate(w.A, { ...w.c1.body, maxDepth: 0 });
    expectReject(await verify([w.c0, skip]), "depth", 1);
  });

  it("INV-10a: delegating below maxDepth 0 → reject at 'depth'", async () => {
    // c2.maxDepth = 0；C 仍硬簽一張給 D
    const c3 = await signMandate(w.C, {
      ...w.c2.body,
      mandateId: toHex(randomBytes(32)),
      parentId: w.c2.body.mandateId,
      issuer: w.C.publicKey,
      subject: w.D.publicKey,
      maxDepth: 0,
    });
    expectReject(await verify([w.c0, w.c1, w.c2, c3]), "depth", 3);
  });

  /* ---------- INV-12 ---------- */

  it("INV-12: self-signed root not in trustedRoots → reject at 'root'", async () => {
    const fake = await issueRoot(w.D, {
      subject: w.C.publicKey,
      audience: AUD,
      issuedAt: NOW - 10,
      expiresAt: NOW + DAY,
      maxDepth: 0,
      scope: scope({ maxNotional: USDC(1_000_000_000) }),
    });
    expectReject(await verify([fake]), "root", 0);
  });

  it("INV-12: trusted root key used as a non-root issuer does not make the chain trusted", async () => {
    // D 偽造 c0，然後讓真 leader 的公鑰出現在 c1.issuer（但 c1 簽章仍由 D 簽，驗不過）。
    const fakeRoot = await signMandate(w.D, { ...w.c0.body, issuer: w.D.publicKey, subject: w.leader.publicKey });
    expectReject(await verify([fakeRoot, w.c1]), "root", 0);
  });

  /* ---------- 簽章 ---------- */

  it("sig: mandate signed by wrong key → reject at 'sig'", async () => {
    const m = await signMandate(w.A, w.c0.body); // issuer 仍寫 leader，但由 A 簽
    expectReject(await verify([m]), "sig", 0);
  });

  it("sig: one flipped bit in signature or body → reject at 'sig'", async () => {
    const sigBytes = fromHex(w.c0.sig);
    sigBytes[10] = (sigBytes[10] ?? 0) ^ 0x01;
    expectReject(await verify([{ body: w.c0.body, sig: toHex(sigBytes) }]), "sig", 0);
    expectReject(await verify([{ body: { ...w.c0.body, maxDepth: 3 }, sig: w.c0.sig }]), "sig", 0);
  });

  it("sig: tampering with c1 after A signed it → reject at 'sig' at index 1", async () => {
    const tampered = { body: { ...w.c1.body, scope: { ...w.c1.body.scope, maxNotional: USDC(100_000) } }, sig: w.c1.sig };
    expectReject(await verify([w.c0, tampered, w.c2]), "sig", 1);
  });

  /* ---------- 時間 ---------- */

  it("time: expired mandate → reject at 'time'", async () => {
    expectReject(await verify(w.chain.mandates, { ...w.ctx, now: NOW + 8 * DAY }), "time", 0);
    // c2 比 c0/c1 早過期：now 在 c2 過期後、c1 之前 → 在 index 2 擋
    expectReject(await verify(w.chain.mandates, { ...w.ctx, now: NOW + 4 * DAY }), "time", 2);
  });

  it("time: issuedAt in the future → reject at 'time'", async () => {
    expectReject(await verify(w.chain.mandates, { ...w.ctx, now: NOW - 7200 }), "time", 0);
  });

  it("time: issuedAt within +CLOCK_SKEW_S accepted; one second beyond rejected", async () => {
    // 發行方時鐘快 30 秒要收；快 31 秒拒。expiresAt 沒有容忍。
    expectOk(await verify([await signMandate(w.leader, { ...w.c0.body, issuedAt: NOW + CLOCK_SKEW_S })]));
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, issuedAt: NOW + CLOCK_SKEW_S + 1 })]), "time", 0);
    expectReject(await verify([await signMandate(w.leader, { ...w.c0.body, issuedAt: NOW - 120, expiresAt: NOW })]), "time", 0);
  });

  it("time: issuedAt >= expiresAt → reject at 'time'", async () => {
    const m = await signMandate(w.leader, { ...w.c0.body, issuedAt: NOW - 10, expiresAt: NOW - 10 });
    const r = expectReject(await verify([m], { ...w.ctx, now: NOW - 10 }), "time", 0);
    // 釘住理由：必須由「issuedAt >= expiresAt」這一條擋（INV-13 固定順序），
    // 而不是靠後面的「已過期」撿到——否則這個檢查形同不存在。
    expect(r.reason).toMatch(/issuedAt >= expiresAt/);
  });

  it("time: child expiresAt later than parent → reject at 'time'", async () => {
    const c1 = await signMandate(w.A, { ...w.c1.body, expiresAt: NOW + 10 * DAY }); // parent: +7d
    expectReject(await verify([w.c0, c1]), "time", 1);
  });

  /* ---------- 撤銷 ---------- */

  it("revoked: isRevoked(c1.mandateId) → reject at 'revoked'; c2 under it also fails", async () => {
    w.revoked.add(w.c1.body.mandateId);
    expectReject(await verify([w.c0, w.c1]), "revoked", 1);
    expectReject(await verify(w.chain.mandates), "revoked", 1);
    expectOk(await verify([w.c0]));
  });

  it("revoked: a throwing revocation oracle fails closed", async () => {
    const ctx: VerifyContext = {
      ...w.ctx,
      isRevoked: () => {
        throw new Error("db down");
      },
    };
    expectReject(await verify([w.c0], ctx), "revoked", 0);
  });

  /* ---------- INV-13 順序 ---------- */

  it("INV-13: a mandate failing at 'sig' never reaches scope / revocation checks", async () => {
    const calls: string[] = [];
    const ctx: VerifyContext = {
      ...w.ctx,
      isRevoked: (id) => {
        calls.push(id);
        return false;
      },
    };
    // c2 同時：簽章壞（由 D 簽）、scope 放大、audience 錯。必須在 'sig' 停。
    const bad = await signMandate(w.D, {
      ...w.c2.body,
      audience: "signer-Y",
      scope: { ...w.c2.body.scope, maxLeverageBps: 9999 },
    });
    expectReject(await verify([w.c0, w.c1, bad], ctx), "sig", 2);
    expect(calls).toEqual([w.c0.body.mandateId, w.c1.body.mandateId]); // 只查了前兩張
  });

  it("INV-13: 'fields' is checked before 'sig' (no signature work on malformed input)", async () => {
    let verifyCalls = 0;
    const countingSigv = {
      verify: async (...args: Parameters<typeof ed25519Verifier.verify>) => {
        verifyCalls++;
        return ed25519Verifier.verify(...args);
      },
    };
    const { maxDepth: _drop, ...rest } = w.c0.body;
    const m = await signMandate(w.leader, rest as MandateBody);
    const r = await verifyChain({ mandates: [m] }, w.ctx, countingSigv);
    expectReject(r, "fields", 0);
    expect(verifyCalls).toBe(0);
  });

  /* ---------- INV-6：快照 ---------- */

  it("INV-6: a getter that changes value between reads cannot split sig-check from scope-check", async () => {
    // body.scope.maxLeverageBps 第一次讀回 200（簽章對得上），之後回 9999。
    // 驗證器先快照，所以整個流程只看到 200，而且回傳的 VerifiedMandate 也是 200。
    let reads = 0;
    const scopeObj = { ...w.c2.body.scope };
    Object.defineProperty(scopeObj, "maxLeverageBps", {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? 200 : 9999;
      },
    });
    const body = { ...w.c2.body, scope: scopeObj };
    const sig = w.c2.sig; // 原簽章對 200
    const leaf = expectOk(await verify([w.c0, w.c1, { body, sig }]));
    expect(leaf.body.scope.maxLeverageBps).toBe(200);
    expect(reads).toBe(1);
  });

  it("INV-6: delegate() only accepts VerifiedMandate — a raw Mandate cannot be used at type level", async () => {
    // 型別層面的保證；執行期示範：繞過型別硬塞未驗證的 parent 時，verifyChain 仍會擋。
    const forgedParent = { ...w.c0, depth: 0 } as unknown as Parameters<typeof delegate>[1];
    const child = await delegate(w.A, forgedParent, {
      subject: w.B.publicKey,
      issuedAt: NOW,
      expiresAt: NOW + DAY,
      scope: scope(),
    });
    // c0 本身是真的，所以這條鏈其實有效；重點是 delegate 不會替未驗證的 parent 背書：
    // 換一張假的 parent（D 自簽）就在 'root' 被擋。
    expectOk(await verify([w.c0, child]));
    const fakeRoot = await signMandate(w.D, { ...w.c0.body, issuer: w.D.publicKey });
    const forged2 = { ...fakeRoot, depth: 0 } as unknown as Parameters<typeof delegate>[1];
    const child2 = await delegate(w.A, forged2, {
      subject: w.B.publicKey,
      issuedAt: NOW,
      expiresAt: NOW + DAY,
      scope: scope(),
    });
    expectReject(await verify([fakeRoot, child2]), "root", 0);
  });
});
