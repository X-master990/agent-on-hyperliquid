import canonicalize from "canonicalize";

/**
 * 正規序列化（ADR-0003）：唯一的序列化入口。
 * 規則：RFC 8785 JCS；bigint 以十進位字串表示；number 只允許安全整數（不允許浮點）；
 * undefined 欄位省略；只接受 plain object / array / 基本型別。
 */
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

function normalize(v: unknown, path: string): unknown {
  switch (typeof v) {
    case "bigint":
      return v.toString(10);
    case "number":
      if (!Number.isSafeInteger(v)) throw new Error(`canonical: non-integer number at ${path}`);
      return v;
    case "string":
    case "boolean":
      return v;
    case "undefined":
      return undefined;
    case "object": {
      if (v === null) return null;
      if (Array.isArray(v)) {
        return v.map((x, i) => {
          const n = normalize(x, `${path}[${i}]`);
          if (n === undefined) throw new Error(`canonical: undefined inside array at ${path}[${i}]`);
          return n;
        });
      }
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error(`canonical: non-plain object at ${path}`);
      }
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v)) {
        const n = normalize((v as Record<string, unknown>)[k], `${path}.${k}`);
        if (n !== undefined) out[k] = n;
      }
      return out;
    }
    default:
      throw new Error(`canonical: unsupported type ${typeof v} at ${path}`);
  }
}

export function canonicalBytes(obj: unknown): Uint8Array {
  const n = normalize(obj, "$");
  if (n === undefined) throw new Error("canonical: root is undefined");
  const s = canonicalize(n);
  if (typeof s !== "string") throw new Error("canonical: serialization failed");
  return enc.encode(s);
}

/**
 * 解析正規 bytes。會檢查輸入確實是正規形式（重新序列化後 bytes 相同），否則丟錯。
 * 注意：bigint 欄位會以十進位字串回來；呼叫端須依 schema 自行還原（v0 無 schema）。
 */
export function parseCanonical<T>(bytes: Uint8Array): T {
  const text = dec.decode(bytes);
  const parsed: unknown = JSON.parse(text);
  const again = canonicalBytes(parsed);
  if (again.length !== bytes.length || !again.every((b, i) => b === bytes[i])) {
    throw new Error("parseCanonical: input is not in canonical form");
  }
  return parsed as T;
}
