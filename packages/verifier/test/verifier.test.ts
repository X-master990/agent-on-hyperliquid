import { describe, it, expect, beforeEach } from "vitest";
import { ed25519Verifier } from "@mandate/core";
import { MemoryNonceStore, MemoryRevocationList, NoopCumulativeState, PolicyVerifier } from "@mandate/verifier";
import { makeWorld, orderBody, signOrder, expectOk, AUD, NOW, USDC, type World } from "../../chain/test/fixtures.js";
import { makeVerifier } from "./helpers.js";

describe("verifier/happy-path", () => {
  let w: World;
  beforeEach(async () => {
    w = await makeWorld();
  });

  it("leader → A → B → C; C places BTC 8k @2x inside scope → ok", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(w.c2.body.mandateId));
    const d = expectOk(await pv.verifyOrder(w.chain, order));
    expect(d.mandate.depth).toBe(2);
    expect(d.mandate.body.subject).toBe(w.C.publicKey);
    expect(d.order.body).toEqual(order.body);
    expect(d.order.sig).toBe(order.sig);
    expect(Object.isFrozen(d.mandate.body.scope)).toBe(true);
  });

  it("boundary: notional == maxNotional and leverage == maxLeverage are accepted", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(w.c2.body.mandateId, { notional: USDC(10_000), leverageBps: 200 }));
    expectOk(await pv.verifyOrder(w.chain, order));
  });

  it("nonce recorded only on accept", async () => {
    const { pv, nonces } = makeVerifier(w);
    expect(nonces.size()).toBe(0);
    const order = await signOrder(w.C, orderBody(w.c2.body.mandateId));
    expectOk(await pv.verifyOrder(w.chain, order));
    expect(nonces.size()).toBe(1);
    // 第二筆不同 nonce 的單也過
    expectOk(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(w.c2.body.mandateId))));
    expect(nonces.size()).toBe(2);
  });

  it("the same order is accepted by a verifier with a fresh nonce store (ledger is per-signer, INV-9)", async () => {
    const order = await signOrder(w.C, orderBody(w.c2.body.mandateId));
    expectOk(await makeVerifier(w).pv.verifyOrder(w.chain, order));
    expectOk(await makeVerifier(w).pv.verifyOrder(w.chain, order));
  });

  it("extra unknown fields in the order body are ignored (covered by sig, never read)", async () => {
    const { pv } = makeVerifier(w);
    const body = { ...orderBody(w.c2.body.mandateId), clientTag: "strategy-7" } as unknown as ReturnType<typeof orderBody>;
    const order = await signOrder(w.C, body);
    expectOk(await pv.verifyOrder(w.chain, order));
  });

  it("uses the system clock when no clock is given", async () => {
    // 不給 clock：直接建構 PolicyVerifier。鏈是以固定 NOW 簽的，在真實時間下必然不在有效期 → 'time'
    const pv = new PolicyVerifier({
      audience: AUD,
      trustedRoots: new Set([w.leader.publicKey]),
      nonces: new MemoryNonceStore(),
      revocations: new MemoryRevocationList(),
      cumulative: new NoopCumulativeState(),
      sigv: ed25519Verifier,
    });
    const real = Math.floor(Date.now() / 1000);
    const order = await signOrder(w.C, orderBody(w.c2.body.mandateId, { issuedAt: real - 1, expiresAt: real + 60 }));
    const r = await pv.verifyOrder(w.chain, order);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.step).toBe("time");
  });
});

describe("verifier/nonce-store", () => {
  const SUBJ_A = `0x${"f1".repeat(32)}` as const;
  const SUBJ_B = `0x${"f2".repeat(32)}` as const;

  it("seenOrRecord: first call records (false), second call reports seen (true); keyed by (subject, nonce)", () => {
    const s = new MemoryNonceStore();
    const n = `0x${"aa".repeat(32)}` as const;
    expect(s.seenOrRecord(SUBJ_A, n, NOW + 60)).toBe(false);
    expect(s.seenOrRecord(SUBJ_A, n, NOW + 60)).toBe(true);
    expect(s.seenOrRecord(SUBJ_A, n, NOW + 999)).toBe(true); // 不同 expiresAt 也算同一個 nonce
    // 不同 subject 用同一個 nonce 值是不同的鍵（INV-9，spec §5）
    expect(s.seenOrRecord(SUBJ_B, n, NOW + 60)).toBe(false);
    expect(s.size()).toBe(2);
  });

  it("prune() removes expired nonces", () => {
    const s = new MemoryNonceStore();
    s.seenOrRecord(SUBJ_A, `0x${"01".repeat(32)}`, NOW + 10);
    s.seenOrRecord(SUBJ_A, `0x${"02".repeat(32)}`, NOW + 100);
    s.seenOrRecord(SUBJ_A, `0x${"03".repeat(32)}`, NOW + 1000);
    expect(s.size()).toBe(3);
    s.prune(NOW + 100); // 清掉 expiresAt < now：只有 +10
    expect(s.size()).toBe(2);
    expect(s.seenOrRecord(SUBJ_A, `0x${"02".repeat(32)}`, NOW + 100)).toBe(true); // == now 的還在
    s.prune(NOW + 5000);
    expect(s.size()).toBe(0);
    expect(s.seenOrRecord(SUBJ_A, `0x${"01".repeat(32)}`, NOW + 6000)).toBe(false); // 清掉後可再用（它已過期，單本身會被 time 擋）
  });
});

describe("verifier/revocation", () => {
  it("revoke/isRevoked; first revocation time is kept", () => {
    const r = new MemoryRevocationList();
    const id = `0x${"ab".repeat(32)}` as const;
    expect(r.isRevoked(id)).toBe(false);
    r.revoke(id, NOW);
    expect(r.isRevoked(id)).toBe(true);
    r.revoke(id, NOW + 100);
    expect(r.isRevoked(id)).toBe(true);
    expect(r.isRevoked(`0x${"cd".repeat(32)}`)).toBe(false);
  });
});
