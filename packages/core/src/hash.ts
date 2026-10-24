import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, concatBytes, randomBytes as nobleRandomBytes } from "@noble/hashes/utils";
import type { Hash, Hex } from "./types.js";

/** v0 用 SHA-256；ZK 階段換 Poseidon（另開 ADR）。所有雜湊走這裡。 */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** 小寫、0x 前綴。全專案的 hex 表示法只有這一種。 */
export function toHex(b: Uint8Array): Hash {
  return `0x${bytesToHex(b)}`;
}

const HEX_RE = /^0x(?:[0-9a-f]{2})*$/;

/** 只接受 toHex 產出的格式（0x + 小寫 + 偶數長）；其他一律丟錯。 */
export function fromHex(h: string): Uint8Array {
  if (typeof h !== "string" || !HEX_RE.test(h)) {
    throw new Error("fromHex: expected 0x-prefixed lowercase even-length hex");
  }
  return hexToBytes(h.slice(2));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts);
}

/** CSPRNG。salt、nonce、mandateId 都從這裡拿（各自獨立呼叫，不共用同一個值，INV-3）。 */
export function randomBytes(n: number): Uint8Array {
  return nobleRandomBytes(n);
}

/** 型別守衛：v 是否為 0x + 恰好 n bytes 的小寫 hex。 */
export function isHexBytes(v: unknown, n: number): v is Hex {
  return typeof v === "string" && v.length === 2 + 2 * n && HEX_RE.test(v);
}
