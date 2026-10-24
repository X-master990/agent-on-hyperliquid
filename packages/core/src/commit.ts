import { COMMIT_PREFIX } from "./tags.js";
import { sha256, toHex, concat, randomBytes } from "./hash.js";
import type { Hash } from "./types.js";

export interface Commitment { c: Hash }
export interface Opening { value: Uint8Array; salt: Uint8Array }

export const MIN_SALT_BYTES = 32;

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/**
 * c = sha256(0x02 ‖ u32be(len(salt)) ‖ salt ‖ value)。
 * salt 必須 ≥32 bytes 隨機（INV-3）；長度不足直接丟錯。
 * salt 帶長度前綴，避免 (salt, value) 邊界移動造成同一個 c 有兩種開啟。
 */
export function commit(value: Uint8Array, salt: Uint8Array): Commitment {
  if (!(salt instanceof Uint8Array) || salt.length < MIN_SALT_BYTES) {
    throw new Error(`commit: salt must be >= ${MIN_SALT_BYTES} bytes`); // INV-3
  }
  if (!(value instanceof Uint8Array)) throw new Error("commit: value must be bytes");
  return { c: toHex(sha256(concat(new Uint8Array([COMMIT_PREFIX]), u32be(salt.length), salt, value))) };
}

/** 開啟失敗（含 salt 太短等格式問題）一律回 false。 */
export function open(c: Commitment, o: Opening): boolean {
  try {
    return commit(o.value, o.salt).c === c.c;
  } catch {
    return false;
  }
}

export function randomSalt(): Uint8Array {
  return randomBytes(MIN_SALT_BYTES);
}
