/**
 * 測試共用夾具。不是測試檔（檔名不含 .test）。
 * 世界：leader → A（5x, 100k, depth 2）→ B（3x, 30k）→ C（2x, 10k）；D 是局外人。
 * 時鐘固定在 NOW；所有時間都是 unix 秒。
 */
import { expect } from "vitest";
import {
  Ed25519Signer,
  ed25519Verifier,
  buildTree,
  getProof,
  randomBytes,
  toHex,
  type Hex,
  type MerkleTree,
  type Signer,
} from "@mandate/core";
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
  type Reject,
  type Result,
  type Scope,
  type VerifiedMandate,
  type VerifyContext,
} from "@mandate/chain";

export const NOW = 1_800_000_000;
export const DAY = 86_400;
export const AUD = "signer-X";
export const ASSETS: readonly string[] = ["BTC", "ETH", "SOL"];
export const USDC = (n: number): bigint => BigInt(n) * 1_000_000n;

export function makeTree(assets: readonly string[]): MerkleTree {
  return buildTree(assets.map(encodeAsset));
}
export const tree = makeTree(ASSETS);

export function assetProof(asset: string, t: MerkleTree = tree, list: readonly string[] = ASSETS) {
  const i = list.indexOf(asset);
  if (i < 0) throw new Error(`fixture: ${asset} not in ${list.join(",")}`);
  return getProof(t, i);
}

export function scope(over: Partial<Scope> = {}, root: Hex = tree.root): Scope {
  return {
    assetsRoot: root,
    maxNotional: USDC(100_000),
    maxLeverageBps: 500,
    window: { notBefore: NOW - DAY, notAfter: NOW + 30 * DAY },
    ...over,
  };
}

export interface World {
  leader: Ed25519Signer;
  A: Ed25519Signer;
  B: Ed25519Signer;
  C: Ed25519Signer;
  D: Ed25519Signer;
  c0: Mandate;
  c1: Mandate;
  c2: Mandate;
  chain: Chain;
  ctx: VerifyContext;
  revoked: Set<Hex>;
  tree: MerkleTree;
  assets: readonly string[];
}

export interface WorldOptions {
  assets?: readonly string[];
  /** 覆蓋三層共用的 window（root 相等規則下三層 root 相同，但 window 可各自縮） */
  window?: Scope["window"];
}

export async function makeWorld(opt: WorldOptions = {}): Promise<World> {
  const assets = opt.assets ?? ASSETS;
  const t = makeTree(assets);
  const leader = Ed25519Signer.random();
  const A = Ed25519Signer.random();
  const B = Ed25519Signer.random();
  const C = Ed25519Signer.random();
  const D = Ed25519Signer.random();
  const revoked = new Set<Hex>();
  const ctx: VerifyContext = {
    audience: AUD,
    now: NOW,
    trustedRoots: new Set([leader.publicKey]),
    isRevoked: (id) => revoked.has(id),
  };
  const win = opt.window ?? { notBefore: NOW - DAY, notAfter: NOW + 30 * DAY };

  const c0 = await issueRoot(leader, {
    subject: A.publicKey,
    audience: AUD,
    issuedAt: NOW - 3600,
    expiresAt: NOW + 7 * DAY,
    maxDepth: 2,
    scope: scope({ window: win }, t.root),
  });
  const v0 = await verifyChain({ mandates: [c0] }, ctx, ed25519Verifier);
  if (!v0.ok) throw new Error(`fixture c0: ${v0.step} ${v0.reason}`);

  const c1 = await delegate(A, v0.value, {
    subject: B.publicKey,
    issuedAt: NOW - 1800,
    expiresAt: NOW + 5 * DAY,
    scope: scope({ maxNotional: USDC(30_000), maxLeverageBps: 300, window: win }, t.root),
  });
  const v1 = await verifyChain({ mandates: [c0, c1] }, ctx, ed25519Verifier);
  if (!v1.ok) throw new Error(`fixture c1: ${v1.step} ${v1.reason}`);

  const c2 = await delegate(B, v1.value, {
    subject: C.publicKey,
    issuedAt: NOW - 600,
    expiresAt: NOW + 3 * DAY,
    scope: scope({ maxNotional: USDC(10_000), maxLeverageBps: 200, window: win }, t.root),
  });

  return { leader, A, B, C, D, c0, c1, c2, chain: { mandates: [c0, c1, c2] }, ctx, revoked, tree: t, assets };
}

/** 直接簽任意 body（攻擊測試用；不經 issueRoot / delegate 的檢查）。 */
export async function signMandate(signer: Signer, body: MandateBody): Promise<Mandate> {
  return { body, sig: await signer.sign(mandateSigningBytes(body)) };
}
export async function signOrder(signer: Signer, body: OrderBody): Promise<Order> {
  return { body, sig: await signer.sign(orderSigningBytes(body)) };
}

/** C 的標準訂單：BTC 8k @2x。 */
export function orderBody(mandateId: Hex, over: Partial<OrderBody> = {}, w?: World): OrderBody {
  const t = w?.tree ?? tree;
  const list = w?.assets ?? ASSETS;
  return {
    v: 1,
    mandateId,
    audience: AUD,
    nonce: toHex(randomBytes(32)),
    issuedAt: NOW - 10,
    expiresAt: NOW + 60,
    asset: "BTC",
    assetProof: assetProof("BTC", t, list),
    notional: USDC(8_000),
    leverageBps: 200,
    side: "buy",
    ...over,
  };
}

export async function leafOf(w: World): Promise<VerifiedMandate> {
  const r = await verifyChain(w.chain, w.ctx, ed25519Verifier);
  if (!r.ok) throw new Error(`fixture leaf: ${r.step} ${r.reason}`);
  return r.value;
}

export function expectReject<T>(r: Result<T>, step: Reject["step"], at?: number): Reject {
  if (r.ok) throw new Error(`expected reject at '${step}' but got ok`);
  expect(r.step, `reason: ${r.reason}`).toBe(step);
  if (at !== undefined) expect(r.at).toBe(at);
  return r;
}

export function expectOk<T>(r: Result<T>): T {
  if (!r.ok) throw new Error(`expected ok but rejected at '${r.step}': ${r.reason}`);
  return r.value;
}
