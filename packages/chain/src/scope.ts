import type { Scope, OrderBody } from "./types.js";

const enc = new TextEncoder();

/** 資產白名單葉子的編碼：utf-8(asset)。建樹與驗 proof 都必須用這個，否則 root 對不上。 */
export function encodeAsset(asset: string): Uint8Array {
  return enc.encode(asset);
}

/**
 * 子 scope ⊆ 父 scope（INV-10a）。
 * v0（ADR-0001，2026-10-22 決定）：assetsRoot 必須相等（不支援提供葉子證明真子集）；
 * maxNotional ≤；maxLeverageBps ≤；window 區間包含。
 * TODO(C3)：累計型（dailyLoss）、類別式白名單、OR。
 */
export function isSubset(child: Scope, parent: Scope): boolean {
  if (child.assetsRoot !== parent.assetsRoot) return false;              // INV-10a：資產 root 相等
  if (child.maxNotional > parent.maxNotional) return false;               // INV-10a：名目 ≤
  if (child.maxLeverageBps > parent.maxLeverageBps) return false;         // INV-10a：槓桿 ≤
  if (child.window.notBefore < parent.window.notBefore) return false;     // INV-10a：窗起點不得更早
  if (child.window.notAfter > parent.window.notAfter) return false;       // INV-10a：窗終點不得更晚
  // TODO(C3): dailyLoss 不在 v0 判定
  return true;
}

/**
 * 訂單 ⊆ scope（INV-10b）。
 * 資產 membership 不在這裡：assetProof 由呼叫端先以 verifyProof 對照 scope.assetsRoot（INV-7）。
 * 時間窗為閉區間 [notBefore, notAfter]。
 */
export function orderWithinScope(order: OrderBody, scope: Scope, now: number): boolean {
  if (order.notional > scope.maxNotional) return false;                   // INV-10b：notional ≤ maxNotional
  if (order.leverageBps > scope.maxLeverageBps) return false;             // INV-10b：leverage ≤ maxLeverage
  const { notBefore, notAfter } = scope.window;
  if (order.issuedAt < notBefore || order.issuedAt > notAfter) return false; // INV-10b：issuedAt ∈ window
  // TODO(spec): 「時間 ∈ window」是否也要求驗證當下在窗內；v0 兩者都檢（較嚴）。
  if (now < notBefore || now > notAfter) return false;                    // INV-10b：now ∈ window
  return true;
}
