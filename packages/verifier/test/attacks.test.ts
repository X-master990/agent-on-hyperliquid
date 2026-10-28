import { describe, it, expect, beforeEach } from "vitest";
import { TAG, tagged, canonicalBytes, getProof, toHex, randomBytes, type Hex } from "@mandate/core";
import { CLOCK_SKEW_S, encodeAsset, type OrderBody, type Order } from "@mandate/chain";
import { MemoryNonceStore, utcDay, type NonceStore } from "@mandate/verifier";
import {
  makeWorld,
  makeTree,
  orderBody,
  signOrder,
  signMandate,
  assetProof,
  expectReject,
  expectOk,
  NOW,
  DAY,
  USDC,
  type World,
} from "../../chain/test/fixtures.js";
import { makeVerifier } from "./helpers.js";

/** 每條不變量至少一個負面測試。名稱以 INV-n 開頭。 */
describe("verifier/attacks", () => {
  let w: World;
  let leafId: Hex;
  beforeEach(async () => {
    w = await makeWorld();
    leafId = w.c2.body.mandateId;
  });

  /* ---------- INV-1 ---------- */

  it("INV-1: order body signed under MANDATE tag presented as an order → rejected (surfaces at 'sig')", async () => {
    const { pv } = makeVerifier(w);
    const body = orderBody(leafId);
    const sig = await w.C.sign(tagged(TAG.MANDATE, canonicalBytes(body)));
    expectReject(await pv.verifyOrder(w.chain, { body, sig }), "sig");
  });

  it("INV-1: order body.v !== 1 → reject at 'tag'", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, { ...orderBody(leafId), v: 2 } as unknown as OrderBody);
    expectReject(await pv.verifyOrder(w.chain, order), "tag");
    expectReject(await pv.verifyOrder(w.chain, { sig: order.sig } as unknown as Order), "tag");
  });

  /* ---------- INV-5 ---------- */

  it("INV-5: order.audience = 'signer-Y' → reject at 'audience'", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(leafId, { audience: "signer-Y" }));
    expectReject(await pv.verifyOrder(w.chain, order), "audience");
  });

  /* ---------- INV-6 / INV-7 ---------- */

  it("INV-6: order carries its own assetsRoot field → ignored; proof checked against leaf.scope.assetsRoot", async () => {
    const { pv } = makeVerifier(w);
    const evilAssets = ["BTC", "ETH", "SOL", "DOGE"];
    const evilTree = makeTree(evilAssets);
    const body = {
      ...orderBody(leafId, { asset: "DOGE", assetProof: assetProof("DOGE", evilTree, evilAssets) }),
      assetsRoot: evilTree.root, // 請求方自填 root
    } as unknown as OrderBody;
    const order = await signOrder(w.C, body);
    const r = expectReject(await pv.verifyOrder(w.chain, order), "scope");
    expect(r.reason).toMatch(/whitelist/);
  });

  it("INV-7: valid proof against a different root (tree containing DOGE) → reject at 'scope'", async () => {
    const { pv } = makeVerifier(w);
    const evilAssets = ["DOGE", "BTC"];
    const evilTree = makeTree(evilAssets);
    const order = await signOrder(w.C, orderBody(leafId, { asset: "DOGE", assetProof: getProof(evilTree, 0) }));
    expectReject(await pv.verifyOrder(w.chain, order), "scope");
    // 同一棵假樹裡的 BTC 也不行：proof 對的是假 root
    const order2 = await signOrder(w.C, orderBody(leafId, { asset: "BTC", assetProof: getProof(evilTree, 1) }));
    expectReject(await pv.verifyOrder(w.chain, order2), "scope");
  });

  it("INV-7: proof for a different asset of the right tree does not prove the claimed asset", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(leafId, { asset: "DOGE", assetProof: assetProof("BTC") }));
    expectReject(await pv.verifyOrder(w.chain, order), "scope");
  });

  /* ---------- INV-8 ---------- */

  it("INV-8: order missing nonce → reject at 'fields'", async () => {
    const { pv } = makeVerifier(w);
    const { nonce: _drop, ...rest } = orderBody(leafId);
    const order = await signOrder(w.C, rest as OrderBody);
    expectReject(await pv.verifyOrder(w.chain, order), "fields");
  });

  it("INV-8: order missing mandateId / audience / expiresAt → reject at 'fields'", async () => {
    const { pv } = makeVerifier(w);
    for (const key of ["mandateId", "audience", "expiresAt", "issuedAt", "assetProof"] as const) {
      const body = { ...orderBody(leafId) };
      delete (body as Partial<OrderBody>)[key];
      const order = await signOrder(w.C, body);
      expectReject(await pv.verifyOrder(w.chain, order), "fields");
    }
  });

  it("INV-8: order.sig not 64-byte hex → reject at 'fields' (no signature work on malformed input)", async () => {
    const { pv } = makeVerifier(w);
    const signed = await signOrder(w.C, orderBody(leafId));
    expectReject(await pv.verifyOrder(w.chain, { body: signed.body, sig: "0x1234" as Hex }), "fields");
  });

  it("INV-8: side outside 'buy' | 'sell' → reject at 'fields' (nothing downstream reads side)", async () => {
    // 這是整條管線唯一看 side 的地方：少了它，side:"hold" 的單會被完整接受。
    const { pv } = makeVerifier(w);
    for (const side of ["hold", "BUY", "", 1, null]) {
      const order = await signOrder(w.C, orderBody(leafId, { side } as unknown as Partial<OrderBody>));
      expectReject(await pv.verifyOrder(w.chain, order), "fields");
    }
  });

  it("INV-8: zero notional / leverage → reject at 'fields' (positive integers required)", async () => {
    // 零名目單無經濟意義，卻會消耗 nonce；spec §5 拍板值域 ≥ 1
    const { pv } = makeVerifier(w);
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { notional: 0n }))), "fields");
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { leverageBps: 0 }))), "fields");
  });

  it("INV-8: asset must be a non-empty string → reject at 'fields'", async () => {
    const { pv } = makeVerifier(w);
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { asset: "" }))), "fields");
    // 數字 asset 不能靠 TextEncoder 的 ToString 坐滑梯進 membership 檢查
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { asset: 123 } as unknown as Partial<OrderBody>))), "fields");
  });

  it("INV-8: malformed assetProof shape → reject at 'fields' (shape at 'fields', membership at 'scope')", async () => {
    const { pv } = makeVerifier(w);
    const good = assetProof("BTC");
    const bads = [
      { siblings: "zz", path: good.path },                               // 非陣列
      { siblings: good.siblings, path: good.path.slice(0, -1) },         // siblings/path 長度不符
      { siblings: ["0xzz", ...good.siblings.slice(1)], path: good.path },// sibling 非 32-byte hex
      { siblings: good.siblings, path: [2, ...good.path.slice(1)] },     // path bit 非 0|1
    ];
    for (const bad of bads) {
      const order = await signOrder(w.C, orderBody(leafId, { assetProof: bad } as unknown as Partial<OrderBody>));
      expectReject(await pv.verifyOrder(w.chain, order), "fields");
    }
  });

  it("INV-8: order signed by A's key under C's mandate → reject at 'sig'", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.A, orderBody(leafId));
    expectReject(await pv.verifyOrder(w.chain, order), "sig");
    const orderB = await signOrder(w.B, orderBody(leafId)); // B 是 c2 的 issuer，也不行
    expectReject(await pv.verifyOrder(w.chain, orderB), "sig");
  });

  it("INV-8: order.mandateId points to c1 while chain leaf is c2 → reject at 'link'", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(w.c1.body.mandateId));
    expectReject(await pv.verifyOrder(w.chain, order), "link");
    // B（c1 的 subject）簽、mandateId 指 c1、但附的是到 c2 的整條鏈：sig 對 leaf.subject=C 驗不過
    const orderB = await signOrder(w.B, orderBody(w.c1.body.mandateId));
    expectReject(await pv.verifyOrder(w.chain, orderB), "sig");
    // 正確作法：B 附到 c1 為止的鏈
    expectOk(await pv.verifyOrder({ mandates: [w.c0, w.c1] }, await signOrder(w.B, orderBody(w.c1.body.mandateId))));
  });

  /* ---------- INV-9 ---------- */

  it("INV-9: same signed order submitted twice → second rejected at 'nonce'", async () => {
    const { pv, nonces } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(leafId));
    expectOk(await pv.verifyOrder(w.chain, order));
    expectReject(await pv.verifyOrder(w.chain, order), "nonce");
    expect(nonces.size()).toBe(1);
    // 重新簽同一個 nonce（不同 body）也擋
    const reuse = await signOrder(w.C, orderBody(leafId, { nonce: order.body.nonce, notional: USDC(1) }));
    expectReject(await pv.verifyOrder(w.chain, reuse), "nonce");
  });

  it("INV-9: expired order → reject at 'time'", async () => {
    const { pv } = makeVerifier(w);
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { issuedAt: NOW - 120, expiresAt: NOW - 60 }))), "time");
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { issuedAt: NOW - 120, expiresAt: NOW }))), "time"); // now < expiresAt 嚴格
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { issuedAt: NOW + CLOCK_SKEW_S + 1, expiresAt: NOW + 120 }))), "time"); // 未來（偏移容忍之外）
    const r = expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { issuedAt: NOW, expiresAt: NOW }))), "time");
    expect(r.reason).toMatch(/issuedAt >= expiresAt/); // 釘住理由：由第一條時間檢查擋，不是靠「已過期」撿到（INV-13）
  });

  it("INV-9: issuedAt within +CLOCK_SKEW_S accepted; one second beyond rejected at 'time'", async () => {
    const { pv } = makeVerifier(w);
    // 邊界：剛好 +30s（發行方時鐘快 30 秒）要收
    expectOk(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { issuedAt: NOW + CLOCK_SKEW_S, expiresAt: NOW + 120 }))));
    // +31s 拒；expiresAt 沒有任何容忍（過期判定嚴格）
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { issuedAt: NOW + CLOCK_SKEW_S + 1, expiresAt: NOW + 120 }))), "time");
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { issuedAt: NOW - 120, expiresAt: NOW }))), "time");
  });

  it("INV-9: nonce ledger keyed by (subject, nonce) — another subject cannot burn C's nonce", async () => {
    const { pv, nonces } = makeVerifier(w);
    const n = toHex(randomBytes(32));
    // B 先用自己的鏈（到 c1）消耗同一個 nonce 值
    expectOk(await pv.verifyOrder({ mandates: [w.c0, w.c1] }, await signOrder(w.B, orderBody(w.c1.body.mandateId, { nonce: n }))));
    // C 用同一個 nonce 值仍然通過（不同 subject，不同鍵）
    expectOk(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { nonce: n }))));
    // C 自己重用才是重放
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { nonce: n }))), "nonce");
    expect(nonces.size()).toBe(2);
  });

  it("INV-9: nonce store is not consulted for orders rejected earlier (no nonce burn)", async () => {
    const calls: string[] = [];
    const inner = new MemoryNonceStore();
    const spy: NonceStore = {
      seenOrRecord: (s, n, e) => {
        calls.push(n);
        return inner.seenOrRecord(s, n, e);
      },
      prune: (t) => inner.prune(t),
      size: () => inner.size(),
    };
    const { pv } = makeVerifier(w, { nonces: spy });
    const bad = await signOrder(w.C, orderBody(leafId, { notional: USDC(12_000) }));
    expectReject(await pv.verifyOrder(w.chain, bad), "scope");
    const badSig = await signOrder(w.A, orderBody(leafId));
    expectReject(await pv.verifyOrder(w.chain, badSig), "sig");
    expect(calls).toEqual([]);
    expect(inner.size()).toBe(0);
    // 同樣的 nonce 之後用在合法單上仍可通過
    const good = await signOrder(w.C, orderBody(leafId, { nonce: bad.body.nonce }));
    expectOk(await pv.verifyOrder(w.chain, good));
    expect(calls).toEqual([bad.body.nonce]);
  });

  /* ---------- INV-10b ---------- */

  it("INV-10b: notional 12k under maxNotional 10k → reject at 'scope'", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(leafId, { notional: USDC(12_000) }));
    expectReject(await pv.verifyOrder(w.chain, order), "scope");
    // 10k + 1 最小單位也擋
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { notional: USDC(10_000) + 1n }))), "scope");
  });

  it("INV-10b: leverage 300 under max 200 → reject at 'scope'", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(leafId, { leverageBps: 300 }));
    expectReject(await pv.verifyOrder(w.chain, order), "scope");
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { leverageBps: 201 }))), "scope");
  });

  it("INV-10b: asset ETH under {BTC} → reject at 'scope'", async () => {
    const wb = await makeWorld({ assets: ["BTC"] });
    const { pv } = makeVerifier(wb);
    // ETH 不在 {BTC} 樹裡，攻擊者只能拿別棵樹的 proof
    const order = await signOrder(wb.C, orderBody(wb.c2.body.mandateId, { asset: "ETH", assetProof: assetProof("ETH") }));
    expectReject(await pv.verifyOrder(wb.chain, order), "scope");
    // 對照：BTC 可以
    expectOk(await pv.verifyOrder(wb.chain, await signOrder(wb.C, orderBody(wb.c2.body.mandateId, {}, wb))));
  });

  it("INV-10b: order issuedAt outside window → reject at 'scope'", async () => {
    const { pv } = makeVerifier(w);
    // window = [NOW-1d, NOW+30d]；issuedAt 在窗前、但未過期、不在未來
    const order = await signOrder(w.C, orderBody(leafId, { issuedAt: NOW - 2 * DAY, expiresAt: NOW + 60 }));
    expectReject(await pv.verifyOrder(w.chain, order), "scope");
  });

  it("INV-10b: verification time outside window → reject at 'scope'", async () => {
    // 窗已關（NOW-100）但授權未過期；訂單 issuedAt 在窗內
    const ww = await makeWorld({ window: { notBefore: NOW - DAY, notAfter: NOW - 100 } });
    const { pv } = makeVerifier(ww);
    const order = await signOrder(ww.C, orderBody(ww.c2.body.mandateId, { issuedAt: NOW - 200, expiresAt: NOW + 60 }));
    expectReject(await pv.verifyOrder(ww.chain, order), "scope");
  });

  it("INV-10b: negative notional / leverage are rejected at 'fields', not silently ≤ max", async () => {
    const { pv } = makeVerifier(w);
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { notional: -1n }))), "fields");
    expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId, { leverageBps: -1 }))), "fields");
    // 浮點連簽都簽不了（canonicalBytes 拒絕非整數）；改成事後竄改，驗證器在 'fields' 擋，不會跑到 sig
    const signed = await signOrder(w.C, orderBody(leafId));
    const tampered = { body: { ...signed.body, leverageBps: 1.5 }, sig: signed.sig };
    expectReject(await pv.verifyOrder(w.chain, tampered), "fields");
    await expect(signOrder(w.C, orderBody(leafId, { leverageBps: 1.5 }))).rejects.toThrow(/non-integer/);
  });

  /* ---------- INV-14（C3a 累計型，ADR-0004） ---------- */

  it("INV-14: daily notional cap — orders accumulate until the cap, the crossing order rejects at 'scope'", async () => {
    const ww = await makeWorld({ scopes: [{ dailyNotional: USDC(50_000) }, { dailyNotional: USDC(20_000) }, { dailyNotional: USDC(12_000) }] });
    const { pv } = makeVerifier(ww);
    const id = ww.c2.body.mandateId;
    expectOk(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, {}, ww))));                           // 8k → 累計 8k
    expectOk(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, { notional: USDC(4_000) }, ww))));    // 12k = 上限，收
    const r = expectReject(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, { notional: 1n }, ww))), "scope");
    expect(r.reason).toMatch(/daily notional/);
    expect(r.at).toBe(2); // 擋在 leaf 那一層
  });

  it("INV-14: two sibling sub-mandates cannot double the parent's daily budget (per-layer accounting)", async () => {
    const ww = await makeWorld({ scopes: [{ dailyNotional: USDC(50_000) }, { dailyNotional: USDC(15_000) }, { dailyNotional: USDC(10_000) }] });
    const { pv } = makeVerifier(ww);
    // B 另發一張合法的兄弟授權 c2'（10k ≤ 15k，subject 同樣是 C）
    const c2b = await signMandate(ww.B, { ...ww.c2.body, mandateId: toHex(randomBytes(32)) });
    // 經 c2 下 8k：c2 與 c1 各累計 8k
    expectOk(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(ww.c2.body.mandateId, {}, ww))));
    // 經 c2' 再下 8k：c2' 自己額度夠（8k ≤ 10k），但 c1 將達 16k > 15k → 擋在第 1 層
    const r = expectReject(
      await pv.verifyOrder({ mandates: [ww.c0, ww.c1, c2b] }, await signOrder(ww.C, orderBody(c2b.body.mandateId, {}, ww))),
      "scope",
    );
    expect(r.reason).toMatch(/daily notional/);
    expect(r.at).toBe(1);
  });

  it("INV-14: rejected orders do not consume daily budget (charge only after full accept)", async () => {
    // 注意順序（INV-13）：累計檢查在 nonce 之前，所以「會爆額度的重放」擋在 'scope'；
    // 這裡的上限取 20k，讓重放通過第 8 步、真正死在 'nonce'，以驗證它沒有入帳。
    const ww = await makeWorld({ scopes: [{}, {}, { dailyNotional: USDC(20_000) }] });
    const { pv } = makeVerifier(ww);
    const id = ww.c2.body.mandateId;
    const good = await signOrder(ww.C, orderBody(id, {}, ww)); // 8k
    expectOk(await pv.verifyOrder(ww.chain, good));
    expectReject(await pv.verifyOrder(ww.chain, good), "nonce");                                        // 重放：不得入帳
    expectReject(await pv.verifyOrder(ww.chain, await signOrder(ww.A, orderBody(id, {}, ww))), "sig");  // 壞簽章：不得入帳
    // 若上面任一筆有入帳（會到 16k+），這筆 10k（8+10 = 18 ≤ 20k）會被誤拒
    expectOk(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, { notional: USDC(10_000) }, ww))));
  });

  it("INV-14: a cap-busting replay is rejected at 'scope' before 'nonce' (INV-13 order) and still burns nothing", async () => {
    const ww = await makeWorld({ scopes: [{}, {}, { dailyNotional: USDC(10_000) }] });
    const { pv, nonces } = makeVerifier(ww);
    const id = ww.c2.body.mandateId;
    const good = await signOrder(ww.C, orderBody(id, {}, ww)); // 8k → 累計 8k
    expectOk(await pv.verifyOrder(ww.chain, good));
    // 重放 8k：8+8 = 16 > 10k → 第 8 步就擋（@scope），不消耗 nonce、不入帳
    expectReject(await pv.verifyOrder(ww.chain, good), "scope");
    expect(nonces.size()).toBe(1);
    expectOk(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, { notional: USDC(2_000) }, ww)))); // 8+2 = 10 ≤ 10k
  });

  it("INV-14: budget resets at the UTC day boundary", async () => {
    const ww = await makeWorld({ scopes: [{}, {}, { dailyNotional: USDC(10_000) }] });
    let now = NOW;
    const { pv } = makeVerifier(ww, { clock: () => now });
    const id = ww.c2.body.mandateId;
    expectOk(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, {}, ww))));             // 8k
    expectReject(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, { notional: USDC(3_000) }, ww))), "scope"); // 11k > 10k
    now = (utcDay(NOW) + 1) * 86_400; // 跨 UTC 日界（仍在授權與 window 有效期內）
    expectOk(await pv.verifyOrder(ww.chain, await signOrder(ww.C, orderBody(id, { issuedAt: now - 10, expiresAt: now + 60 }, ww)))); // 額度歸零，8k 再收
  });

  /* ---------- 撤銷 ---------- */

  it("revocation: revoke c1 → C's next order rejected at 'revoked'", async () => {
    const { pv, revocations } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(leafId));
    expectOk(await pv.verifyOrder(w.chain, order));
    revocations.revoke(w.c1.body.mandateId, NOW);
    const r = expectReject(await pv.verifyOrder(w.chain, await signOrder(w.C, orderBody(leafId))), "revoked");
    expect(r.at).toBe(1);
    // B 自己（c1 的 subject）也不能再用 c1
    expectReject(await pv.verifyOrder({ mandates: [w.c0, w.c1] }, await signOrder(w.B, orderBody(w.c1.body.mandateId))), "revoked");
    // A 用 c0 仍可以
    expectOk(await pv.verifyOrder({ mandates: [w.c0] }, await signOrder(w.A, orderBody(w.c0.body.mandateId))));
  });

  /* ---------- 鏈錯誤傳遞 / INV-12 / INV-13 ---------- */

  it("INV-12: forged root (D self-signs a 'leader' mandate) → reject at 'root' before reading the order", async () => {
    const { pv } = makeVerifier(w);
    const fake = await signMandate(w.D, { ...w.c0.body, issuer: w.D.publicKey, subject: w.C.publicKey, maxDepth: 0 });
    const order = await signOrder(w.C, orderBody(fake.body.mandateId));
    expectReject(await pv.verifyOrder({ mandates: [fake] }, order), "root", 0);
  });

  it("INV-13: chain failure is returned as-is and the order is never examined", async () => {
    let verifyCalls = 0;
    const { pv } = makeVerifier(w, {
      sigv: {
        verify: async (pub, bytes, sig) => {
          verifyCalls++;
          return (await import("@mandate/core")).ed25519Verifier.verify(pub, bytes, sig);
        },
      },
    });
    const spliced = await signMandate(w.D, { ...w.c1.body, issuer: w.D.publicKey });
    const garbageOrder = { body: null, sig: "0x" } as unknown as Order;
    const r = expectReject(await pv.verifyOrder({ mandates: [w.c0, spliced, w.c2] }, garbageOrder), "link", 1);
    expect(r.at).toBe(1);
    expect(verifyCalls).toBe(2); // c0, spliced；c2 與訂單都沒驗
  });

  it("INV-13: an order failing at 'sig' with a bad scope stops at 'sig'", async () => {
    const { pv, nonces } = makeVerifier(w);
    const order = await signOrder(w.D, orderBody(leafId, { notional: USDC(999_999), leverageBps: 9999, audience: "signer-Y" }));
    expectReject(await pv.verifyOrder(w.chain, order), "sig");
    expect(nonces.size()).toBe(0);
  });

  it("INV-6: the decision's mandate is the frozen verified copy, not the caller's object", async () => {
    const { pv } = makeVerifier(w);
    const order = await signOrder(w.C, orderBody(leafId));
    const d = expectOk(await pv.verifyOrder(w.chain, order));
    expect(d.mandate.body).not.toBe(w.c2.body);
    expect(d.mandate.body).toEqual(w.c2.body);
    expect(Object.isFrozen(d.mandate.body.scope)).toBe(true);
    expect(d.order.body).not.toBe(order.body);
    expect(toHex(randomBytes(1))).toMatch(/^0x[0-9a-f]{2}$/);
    expect(encodeAsset("BTC")).toEqual(new TextEncoder().encode("BTC"));
  });
});
