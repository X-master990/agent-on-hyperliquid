import { describe, it, expect, beforeEach } from "vitest";
import { ed25519Verifier } from "@mandate/core";
import { delegate, isSubset, issueRoot, orderWithinScope, verifyChain } from "@mandate/chain";
import { mandateBodyProblem, orderBodyProblem } from "../src/guards.js";
import { makeWorld, makeTree, scope, orderBody, expectOk, leafOf, AUD, NOW, DAY, USDC, type World } from "./fixtures.js";

describe("chain/happy-path", () => {
  let w: World;
  beforeEach(async () => {
    w = await makeWorld();
  });

  it("issueRoot → verifyChain([c0]) ok, depth 0", async () => {
    const v = expectOk(await verifyChain({ mandates: [w.c0] }, w.ctx, ed25519Verifier));
    expect(v.depth).toBe(0);
    expect(v.body).toEqual(w.c0.body);
    expect(v.body.parentId).toBeNull();
    expect(v.body.issuer).toBe(w.leader.publicKey);
    expect(v.body.subject).toBe(w.A.publicKey);
  });

  it("leader → A → B → C: verifyChain ok, depth 2, scope shrinks each hop", async () => {
    const leaf = await leafOf(w);
    expect(leaf.depth).toBe(2);
    expect(leaf.body.subject).toBe(w.C.publicKey);
    expect(leaf.body.maxDepth).toBe(0);
    const [s0, s1, s2] = [w.c0.body.scope, w.c1.body.scope, w.c2.body.scope];
    expect(s1.maxNotional < s0.maxNotional && s2.maxNotional < s1.maxNotional).toBe(true);
    expect(s1.maxLeverageBps < s0.maxLeverageBps && s2.maxLeverageBps < s1.maxLeverageBps).toBe(true);
    expect(w.c1.body.parentId).toBe(w.c0.body.mandateId);
    expect(w.c2.body.parentId).toBe(w.c1.body.mandateId);
    expect(w.c1.body.issuer).toBe(w.c0.body.subject);
    expect(w.c2.body.issuer).toBe(w.c1.body.subject);
  });

  it("INV-6: VerifiedMandate is deeply frozen (scope cannot be mutated after verification)", async () => {
    const leaf = await leafOf(w);
    expect(Object.isFrozen(leaf)).toBe(true);
    expect(Object.isFrozen(leaf.body)).toBe(true);
    expect(Object.isFrozen(leaf.body.scope)).toBe(true);
    expect(Object.isFrozen(leaf.body.scope.window)).toBe(true);
    expect(() => {
      (leaf.body.scope as { maxNotional: bigint }).maxNotional = USDC(999_999_999);
    }).toThrow();
  });

  it("delegate() refuses when signer != parent.subject", async () => {
    const v0 = expectOk(await verifyChain({ mandates: [w.c0] }, w.ctx, ed25519Verifier));
    await expect(
      delegate(w.D, v0, { subject: w.B.publicKey, issuedAt: NOW, expiresAt: NOW + DAY, scope: scope() }),
    ).rejects.toThrow(/not the parent's subject/);
  });

  it("delegate() refuses when parent maxDepth is 0", async () => {
    const leaf = await leafOf(w); // c2, maxDepth 0
    await expect(
      delegate(w.C, leaf, { subject: w.D.publicKey, issuedAt: NOW, expiresAt: NOW + DAY, scope: w.c2.body.scope }),
    ).rejects.toThrow(/maxDepth exhausted/);
  });

  it("delegate() refuses a widening scope", async () => {
    const v0 = expectOk(await verifyChain({ mandates: [w.c0] }, w.ctx, ed25519Verifier));
    await expect(
      delegate(w.A, v0, {
        subject: w.B.publicKey,
        issuedAt: NOW,
        expiresAt: NOW + DAY,
        scope: scope({ maxLeverageBps: 600 }),
      }),
    ).rejects.toThrow(/not a subset/);
  });

  it("delegate() refuses expiresAt beyond parent", async () => {
    const v0 = expectOk(await verifyChain({ mandates: [w.c0] }, w.ctx, ed25519Verifier));
    await expect(
      delegate(w.A, v0, { subject: w.B.publicKey, issuedAt: NOW, expiresAt: NOW + 365 * DAY, scope: scope() }),
    ).rejects.toThrow(/exceeds parent expiresAt/);
  });

  it("INV-4: issueRoot() refuses negative maxDepth and inverted lifetime", async () => {
    // 發行端是禮貌層（真正的防線在 verifyChain），但禮貌層也要有測試，否則形同不存在。
    const p = { subject: w.A.publicKey, audience: AUD, issuedAt: NOW, expiresAt: NOW + DAY, maxDepth: 1, scope: scope() };
    await expect(issueRoot(w.leader, { ...p, maxDepth: -1 })).rejects.toThrow();
    await expect(issueRoot(w.leader, { ...p, expiresAt: NOW })).rejects.toThrow();
  });

  it("INV-4: delegate() refuses inverted lifetime (expiresAt <= issuedAt)", async () => {
    const v0 = expectOk(await verifyChain({ mandates: [w.c0] }, w.ctx, ed25519Verifier));
    await expect(
      delegate(w.A, v0, { subject: w.B.publicKey, issuedAt: NOW, expiresAt: NOW, scope: scope() }),
    ).rejects.toThrow();
  });
});

describe("chain/guards", () => {
  it("INV-4/INV-8: body validators reject non-objects without throwing", () => {
    // verifyChain / verifyOrder 都先檢過 body 是物件才呼叫這兩個函式，
    // 所以這第一道守衛只能用單元測試殺：拔掉它，null.mandateId 會直接丟 TypeError。
    expect(mandateBodyProblem(null)).toBe("body: not an object");
    expect(mandateBodyProblem("x")).toBe("body: not an object");
    expect(orderBodyProblem(null)).toBe("body: not an object");
    expect(orderBodyProblem(42)).toBe("body: not an object");
  });
});

describe("chain/scope", () => {
  it("isSubset: equal scopes → true", () => {
    expect(isSubset(scope(), scope())).toBe(true);
  });

  it("isSubset: smaller notional/leverage/window → true", () => {
    const child = scope({
      maxNotional: USDC(1),
      maxLeverageBps: 100,
      window: { notBefore: NOW, notAfter: NOW + DAY },
    });
    expect(isSubset(child, scope())).toBe(true);
  });

  it("isSubset: assets subset via identical root → true", () => {
    expect(isSubset(scope({}, makeTree(["BTC", "ETH"]).root), scope({}, makeTree(["BTC", "ETH"]).root))).toBe(true);
  });

  it("isSubset (v0 rule): a genuinely smaller whitelist with a different root → false", () => {
    // 決定（2026-10-22）：v0 只做 root 相等；真子集但不同 root 一律不算 ⊆。
    const parent = scope({}, makeTree(["BTC", "ETH", "SOL"]).root);
    const child = scope({}, makeTree(["BTC"]).root);
    expect(isSubset(child, parent)).toBe(false);
  });

  it("isSubset: dailyLoss is ignored in v0 (TODO C3)", () => {
    expect(isSubset(scope({ dailyLoss: USDC(999_999) }), scope({ dailyLoss: USDC(1) }))).toBe(true);
  });

  it("orderWithinScope: order inside → true", () => {
    const leafScope = scope({ maxNotional: USDC(10_000), maxLeverageBps: 200 });
    expect(orderWithinScope(orderBody(`0x${"11".repeat(32)}`), leafScope, NOW)).toBe(true);
  });

  it("orderWithinScope: window is closed on both ends", () => {
    const s = scope({ window: { notBefore: NOW - 100, notAfter: NOW } });
    expect(orderWithinScope(orderBody(`0x${"11".repeat(32)}`, { issuedAt: NOW - 100 }), s, NOW)).toBe(true);
    expect(orderWithinScope(orderBody(`0x${"11".repeat(32)}`, { issuedAt: NOW }), s, NOW)).toBe(true);
    expect(orderWithinScope(orderBody(`0x${"11".repeat(32)}`, { issuedAt: NOW - 101 }), s, NOW)).toBe(false);
    expect(orderWithinScope(orderBody(`0x${"11".repeat(32)}`, { issuedAt: NOW - 50 }), s, NOW + 1)).toBe(false);
  });
});
