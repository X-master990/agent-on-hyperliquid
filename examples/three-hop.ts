/**
 * leader → A → B → C，C 下一筆 BTC 單；再示範五種失敗情境。
 * 跑法：pnpm tsx examples/three-hop.ts
 *
 * v0 的 assetsRoot 規則是「每層 root 相等」，所以三層共用同一棵白名單樹 {BTC, ETH, SOL}；
 * 能逐層縮的是名目、槓桿、時間窗、深度。
 */
import { Ed25519Signer, ed25519Verifier, buildTree, getProof, randomBytes, toHex } from "@mandate/core";
import {
  delegate,
  encodeAsset,
  issueRoot,
  mandateSigningBytes,
  orderSigningBytes,
  verifyChain,
  type Chain,
  type Mandate,
  type MandateBody,
  type Order,
  type OrderBody,
  type Result,
  type Scope,
  type VerifyContext,
} from "@mandate/chain";
import { MemoryCumulativeState, MemoryNonceStore, MemoryRevocationList, PolicyVerifier } from "@mandate/verifier";

const DAY = 86_400;
const NOW = Math.floor(Date.now() / 1000);
const AUD = "policy-signer-1";
const USDC = (n: number): bigint => BigInt(n) * 1_000_000n;
const short = (h: string) => `${h.slice(0, 10)}…`;

function show<T>(label: string, r: Result<T>): void {
  const mark = r.ok ? "✅ accept" : `❌ reject @${r.step}${r.at !== undefined ? `[c${r.at}]` : ""}`;
  console.log(`${mark.padEnd(28)} ${label}${r.ok ? "" : `  — ${r.reason}`}`);
}

async function main() {
  // 1. 四把鑰匙（+ 一個局外人 D）
  const leader = Ed25519Signer.random();
  const A = Ed25519Signer.random();
  const B = Ed25519Signer.random();
  const C = Ed25519Signer.random();
  const D = Ed25519Signer.random();
  console.log(`leader ${short(leader.publicKey)}  A ${short(A.publicKey)}  B ${short(B.publicKey)}  C ${short(C.publicKey)}  D ${short(D.publicKey)}\n`);

  // 2. 資產白名單樹
  const ASSETS = ["BTC", "ETH", "SOL"];
  const tree = buildTree(ASSETS.map(encodeAsset));
  const proofFor = (asset: string) => getProof(tree, ASSETS.indexOf(asset));
  const window = { notBefore: NOW - DAY, notAfter: NOW + 30 * DAY };
  const scope = (maxNotional: bigint, maxLeverageBps: number, dailyNotional?: bigint): Scope => ({
    assetsRoot: tree.root,
    maxNotional,
    maxLeverageBps,
    window,
    ...(dailyNotional !== undefined ? { dailyNotional } : {}),
  });

  // 3. 驗證上下文與政策驗證器
  const nonces = new MemoryNonceStore();
  const revocations = new MemoryRevocationList();
  const ctx: VerifyContext = {
    audience: AUD,
    now: NOW,
    trustedRoots: new Set([leader.publicKey]),
    isRevoked: (id) => revocations.isRevoked(id),
  };
  const pv = new PolicyVerifier({
    audience: AUD,
    trustedRoots: new Set([leader.publicKey]),
    nonces,
    revocations,
    cumulative: new MemoryCumulativeState(),
    sigv: ed25519Verifier,
    clock: () => NOW,
  });

  // 4. issueRoot(leader → A, maxDepth 2, 5x, 100k) → verifyChain → delegate → verifyChain → delegate
  const c0 = await issueRoot(leader, {
    subject: A.publicKey,
    audience: AUD,
    issuedAt: NOW - 60,
    expiresAt: NOW + 7 * DAY,
    maxDepth: 2,
    scope: scope(USDC(100_000), 500, USDC(50_000)),
  });
  const v0 = await verifyChain({ mandates: [c0] }, ctx, ed25519Verifier);
  if (!v0.ok) throw new Error(`c0: ${v0.reason}`);

  const c1 = await delegate(A, v0.value.leaf, { subject: B.publicKey, issuedAt: NOW - 30, expiresAt: NOW + 5 * DAY, scope: scope(USDC(30_000), 300, USDC(20_000)) });
  const v1 = await verifyChain({ mandates: [c0, c1] }, ctx, ed25519Verifier);
  if (!v1.ok) throw new Error(`c1: ${v1.reason}`);

  const c2 = await delegate(B, v1.value.leaf, { subject: C.publicKey, issuedAt: NOW - 10, expiresAt: NOW + 3 * DAY, scope: scope(USDC(10_000), 200, USDC(16_000)) });
  const chain: Chain = { mandates: [c0, c1, c2] };
  const v2 = await verifyChain(chain, ctx, ed25519Verifier);
  if (!v2.ok) throw new Error(`c2: ${v2.reason}`);

  console.log("鏈：");
  for (const m of chain.mandates) {
    const s = m.body.scope;
    console.log(`  c${chain.mandates.indexOf(m)}  ${short(m.body.issuer)} → ${short(m.body.subject)}  maxDepth=${m.body.maxDepth}  ≤${Number(s.maxNotional) / 1e6} USDC  ≤${s.maxLeverageBps / 100}x`);
  }
  console.log();

  // 5. C 簽訂單 BTC 8k @2x，附 membership proof
  const makeOrder = (over: Partial<OrderBody> = {}): OrderBody => ({
    v: 1,
    mandateId: c2.body.mandateId,
    audience: AUD,
    nonce: toHex(randomBytes(32)),
    issuedAt: NOW - 1,
    expiresAt: NOW + 60,
    asset: "BTC",
    assetProof: proofFor("BTC"),
    notional: USDC(8_000),
    leverageBps: 200,
    side: "buy",
    ...over,
  });
  const signOrder = async (signer: Ed25519Signer, body: OrderBody): Promise<Order> => ({ body, sig: await signer.sign(orderSigningBytes(body)) });
  const signMandate = async (signer: Ed25519Signer, body: MandateBody): Promise<Mandate> => ({ body, sig: await signer.sign(mandateSigningBytes(body)) });

  // 6. PolicyVerifier.verifyOrder → ok
  const good = await signOrder(C, makeOrder());
  show("C 下 BTC 8k @2x", await pv.verifyOrder(chain, good));

  // 7. 失敗情境
  console.log("\n失敗情境：");

  // (a) B 給 C 4x —— delegate() 直接拒絕；硬簽出來的鏈在驗證時被擋
  try {
    await delegate(B, v1.value.leaf, { subject: C.publicKey, issuedAt: NOW - 10, expiresAt: NOW + 3 * DAY, scope: scope(USDC(10_000), 400) });
  } catch (e) {
    console.log(`delegate() threw:             B → C @4x  — ${(e as Error).message}`);
  }
  const c2x4 = await signMandate(B, { ...c2.body, scope: scope(USDC(10_000), 400) });
  show("B 硬簽 C @4x（鏈上驗）", await pv.verifyOrder({ mandates: [c0, c1, c2x4] }, await signOrder(C, makeOrder())));

  // (b) C 轉 D —— maxDepth 已是 0
  const c3 = await signMandate(C, {
    ...c2.body,
    mandateId: toHex(randomBytes(32)),
    parentId: c2.body.mandateId,
    issuer: C.publicKey,
    subject: D.publicKey,
    maxDepth: 0,
  });
  show("C 轉授權給 D（深度耗盡）", await pv.verifyOrder({ mandates: [c0, c1, c2, c3] }, await signOrder(D, makeOrder({ mandateId: c3.body.mandateId }))));

  // (c) C 下 DOGE，自備一棵含 DOGE 的樹（換樹攻擊，INV-7）
  const evil = ["BTC", "DOGE"];
  const evilTree = buildTree(evil.map(encodeAsset));
  show("C 下 DOGE（自備含 DOGE 的樹）", await pv.verifyOrder(chain, await signOrder(C, makeOrder({ asset: "DOGE", assetProof: getProof(evilTree, 1) }))));

  // (d) 重放：同一筆已接受的單再送一次
  show("重放第一筆已接受的單", await pv.verifyOrder(chain, good));

  // (e) 偽造 c0：D 自簽一張「leader 授權」
  const fakeRoot = await issueRoot(D, { subject: C.publicKey, audience: AUD, issuedAt: NOW - 60, expiresAt: NOW + DAY, maxDepth: 0, scope: scope(USDC(1_000_000), 5000) });
  show("D 自簽根授權給 C", await pv.verifyOrder({ mandates: [fakeRoot] }, await signOrder(C, makeOrder({ mandateId: fakeRoot.body.mandateId }))));

  // (f) 累計型（INV-14 / C3a）：c2 每日上限 16k，前面已入帳 8k
  show("C 同日再下 3k（累計 11k ≤ 16k）", await pv.verifyOrder(chain, await signOrder(C, makeOrder({ notional: USDC(3_000) }))));
  show("C 同日再下 6k（累計將達 17k）", await pv.verifyOrder(chain, await signOrder(C, makeOrder({ notional: USDC(6_000) }))));

  // 加碼：超額、撤銷
  show("C 下 12k（上限 10k）", await pv.verifyOrder(chain, await signOrder(C, makeOrder({ notional: USDC(12_000) }))));
  revocations.revoke(c1.body.mandateId, NOW);
  show("撤銷 c1 後 C 再下單", await pv.verifyOrder(chain, await signOrder(C, makeOrder())));

  console.log(`\nnonce 帳本：${nonces.size()} 筆`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
