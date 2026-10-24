import { TAG, tagged, canonicalBytes } from "@mandate/core";
import type { MandateBody, OrderBody } from "./types.js";

/**
 * 被簽 bytes 的唯一定義（INV-1 + ADR-0003）。
 * 簽發與驗證都必須走這兩個函式；不得自行組 tag 或自行序列化（ADR-0003）。
 */
export function mandateSigningBytes(body: MandateBody): Uint8Array {
  return tagged(TAG.MANDATE, canonicalBytes(body)); // INV-1
}

export function orderSigningBytes(body: OrderBody): Uint8Array {
  return tagged(TAG.ORDER, canonicalBytes(body)); // INV-1
}
