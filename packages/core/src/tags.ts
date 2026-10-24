/**
 * Domain tags（INV-1）、Merkle 前綴（INV-2）、承諾前綴（INV-3）。
 * 全專案唯一的 tag / 前綴來源；其他地方只能 import，不得手打字串。
 */
export const TAG = {
  MANDATE: "MANDATE/v1",
  ORDER: "ORDER/v1",
  REVOKE: "REVOKE/v1",
} as const;
export type Tag = (typeof TAG)[keyof typeof TAG];

export const MERKLE_PREFIX = {
  LEAF: 0x00,
  NODE: 0x01,
} as const;

/** 承諾雜湊前綴（INV-3）。與 MERKLE_PREFIX 共用同一個 1-byte 命名空間，不得重複。 */
export const COMMIT_PREFIX = 0x02;

const KNOWN_TAGS: ReadonlySet<string> = new Set(Object.values(TAG));
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export function isTag(s: unknown): s is Tag {
  return typeof s === "string" && KNOWN_TAGS.has(s);
}

/**
 * 回傳 len(tag) ‖ tag ‖ payload。len 為 1 byte（所有 tag 都 < 256 bytes）。
 * 長度前綴避免 "MANDATE/v1" 與 "MANDATE/v10" 之類的邊界歧義。
 */
export function tagged(tag: Tag, payload: Uint8Array): Uint8Array {
  if (!isTag(tag)) throw new Error(`tagged: unknown tag ${String(tag)}`); // INV-1
  const t = enc.encode(tag);
  if (t.length === 0 || t.length > 255) throw new Error("tagged: tag length out of range");
  const out = new Uint8Array(1 + t.length + payload.length);
  out[0] = t.length;
  out.set(t, 1);
  out.set(payload, 1 + t.length);
  return out;
}

/** 解析開頭的 tag；不符合任何已知 tag 時丟錯（驗證者第一步，INV-1 / INV-13）。 */
export function readTag(bytes: Uint8Array): { tag: Tag; payload: Uint8Array } {
  if (bytes.length < 1) throw new Error("readTag: empty input"); // INV-1
  const len = bytes[0] ?? 0;
  if (len === 0 || bytes.length < 1 + len) throw new Error("readTag: truncated tag"); // INV-1
  let s: string;
  try {
    s = dec.decode(bytes.subarray(1, 1 + len));
  } catch {
    throw new Error("readTag: tag is not valid utf-8"); // INV-1
  }
  if (!isTag(s)) throw new Error(`readTag: unknown tag "${s}"`); // INV-1, INV-13
  return { tag: s, payload: bytes.subarray(1 + len) };
}
