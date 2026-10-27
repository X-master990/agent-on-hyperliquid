import { describe, it, expect } from "vitest";
import {
  TAG,
  tagged,
  readTag,
  canonicalBytes,
  parseCanonical,
  sha256,
  toHex,
  fromHex,
  concat,
  buildTree,
  getProof,
  verifyProof,
  hashLeaf,
  hashNode,
  EMPTY_NODE,
  MAX_PROOF_DEPTH,
  commit,
  open,
  randomSalt,
  Ed25519Signer,
  ed25519Verifier,
  isHexBytes,
  type Hash,
  type MerkleProof,
} from "@mandate/core";

const enc = new TextEncoder();
const dec = new TextDecoder();
const utf8 = (s: string) => enc.encode(s);

describe("core/tags", () => {
  it("tagged() prefixes length ‖ tag ‖ payload and readTag() round-trips", () => {
    const payload = utf8("hello");
    const b = tagged(TAG.ORDER, payload);
    expect(b[0]).toBe("ORDER/v1".length);
    expect(dec.decode(b.subarray(1, 1 + 8))).toBe("ORDER/v1");
    const r = readTag(b);
    expect(r.tag).toBe(TAG.ORDER);
    expect(dec.decode(r.payload)).toBe("hello");
    for (const t of Object.values(TAG)) expect(readTag(tagged(t, payload)).tag).toBe(t);
  });

  it("readTag() rejects unknown tag", () => {
    const fake = concat(new Uint8Array([9]), utf8("EVIL/v1xx"), utf8("payload"));
    expect(() => readTag(fake)).toThrow(/unknown tag/);
  });

  it("readTag() rejects empty / truncated input", () => {
    expect(() => readTag(new Uint8Array())).toThrow();
    expect(() => readTag(new Uint8Array([10, 77, 65]))).toThrow(/truncated/);
    expect(() => readTag(new Uint8Array([0]))).toThrow();
  });

  it("INV-1: 'MANDATE/v1' and 'MANDATE/v10' do not collide", () => {
    // 沒有長度前綴時，"MANDATE/v1"+"0abc" 與 "MANDATE/v10"+"abc" 是同一串 bytes：
    expect(toHex(utf8("MANDATE/v1" + "0abc"))).toBe(toHex(utf8("MANDATE/v10" + "abc")));
    // 有長度前綴時不同，且偽造的那串被 readTag 拒絕：
    const real = tagged(TAG.MANDATE, utf8("0abc"));
    const fake = concat(new Uint8Array([11]), utf8("MANDATE/v10"), utf8("abc"));
    expect(toHex(real)).not.toBe(toHex(fake));
    expect(() => readTag(fake)).toThrow(/unknown tag/);
    expect(dec.decode(readTag(real).payload)).toBe("0abc");
  });

  it("tagged() refuses a string that is not a known tag", () => {
    expect(() => tagged("ORDER/v2" as typeof TAG.ORDER, utf8("x"))).toThrow(/unknown tag/);
  });
});

describe("core/canonical", () => {
  it("same object, different key order → identical bytes", () => {
    const a = { z: 1, a: { y: [1, 2, { k: "v", j: true }], x: "s" }, m: null };
    const b = { m: null, a: { x: "s", y: [1, 2, { j: true, k: "v" }] }, z: 1 };
    expect(toHex(canonicalBytes(a))).toBe(toHex(canonicalBytes(b)));
    expect(dec.decode(canonicalBytes(a))).toBe('{"a":{"x":"s","y":[1,2,{"j":true,"k":"v"}]},"m":null,"z":1}');
  });

  it("bigint serialized as decimal string", () => {
    const s = dec.decode(canonicalBytes({ maxNotional: 123456789012345678901234567890n, n: 7n, zero: 0n }));
    expect(s).toBe('{"maxNotional":"123456789012345678901234567890","n":"7","zero":"0"}');
  });

  it("rejects floats, NaN, Infinity, functions, and non-plain objects", () => {
    expect(() => canonicalBytes({ x: 1.5 })).toThrow(/non-integer/);
    expect(() => canonicalBytes({ x: Number.NaN })).toThrow();
    expect(() => canonicalBytes({ x: Number.POSITIVE_INFINITY })).toThrow();
    expect(() => canonicalBytes({ x: 2 ** 53 })).toThrow(/non-integer/);
    expect(() => canonicalBytes({ x: () => 1 })).toThrow(/unsupported/);
    expect(() => canonicalBytes({ x: new Uint8Array([1]) })).toThrow(/non-plain/);
    expect(() => canonicalBytes({ x: new Map() })).toThrow(/non-plain/);
    expect(() => canonicalBytes([1, undefined])).toThrow(/undefined inside array/);
  });

  it("undefined fields are omitted (optional dailyLoss absent ≡ omitted)", () => {
    expect(toHex(canonicalBytes({ a: 1, dailyLoss: undefined }))).toBe(toHex(canonicalBytes({ a: 1 })));
  });

  it("unicode strings are escaped per JCS (JSON.stringify semantics)", () => {
    expect(dec.decode(canonicalBytes({ s: "é\u0000\"\\" }))).toBe('{"s":"é\\u0000\\"\\\\"}');
  });

  it("parseCanonical round-trips and rejects non-canonical input", () => {
    const obj = { b: 2, a: "x", big: 10n };
    const bytes = canonicalBytes(obj);
    expect(parseCanonical<{ a: string; b: number; big: string }>(bytes)).toEqual({ a: "x", b: 2, big: "10" });
    expect(() => parseCanonical(utf8('{"b":2,"a":"x"}'))).toThrow(/not in canonical form/);
    expect(() => parseCanonical(utf8('{ "a": "x" }'))).toThrow(/not in canonical form/);
    expect(() => parseCanonical(utf8("{"))).toThrow();
  });
});

describe("core/hash", () => {
  it("toHex/fromHex round-trip; fromHex is strict", () => {
    const b = new Uint8Array([0, 1, 254, 255]);
    expect(toHex(b)).toBe("0x0001feff");
    expect(fromHex("0x0001feff")).toEqual(b);
    expect(() => fromHex("0001feff")).toThrow();
    expect(() => fromHex("0x0001FEFF")).toThrow(); // 大寫不收
    expect(() => fromHex("0xabc")).toThrow(); // 奇數長
    expect(isHexBytes(`0x${"ab".repeat(32)}`, 32)).toBe(true);
    expect(isHexBytes(`0x${"ab".repeat(31)}`, 32)).toBe(false);
    expect(isHexBytes(`0x${"AB".repeat(32)}`, 32)).toBe(false);
  });

  it("sha256 matches a known vector", () => {
    expect(toHex(sha256(utf8("abc")))).toBe("0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

describe("core/merkle", () => {
  const leaves8 = ["BTC", "ETH", "SOL", "DOGE", "AVAX", "LINK", "ARB", "OP"].map(utf8);

  it("build 8 leaves, proof for each index verifies", () => {
    const t = buildTree(leaves8);
    expect(t.layers.length).toBe(4);
    expect(t.layers[3]?.length).toBe(1);
    for (let i = 0; i < 8; i++) {
      const p = getProof(t, i);
      expect(p.siblings.length).toBe(3);
      expect(verifyProof(t.root, leaves8[i] as Uint8Array, p)).toBe(true);
    }
  });

  it("proof for wrong leaf fails", () => {
    const t = buildTree(leaves8);
    const p = getProof(t, 2);
    expect(verifyProof(t.root, leaves8[3] as Uint8Array, p)).toBe(false);
    expect(verifyProof(t.root, utf8("SHIB"), p)).toBe(false);
    expect(verifyProof(buildTree(leaves8.slice(0, 4)).root, leaves8[2] as Uint8Array, p)).toBe(false); // 別棵樹的 root
  });

  it("INV-2: internal node preimage (left‖right) presented as leaf is rejected", () => {
    const t = buildTree(leaves8);
    const L0 = t.leaves[0] as Hash;
    const L1 = t.leaves[1] as Hash;
    const N01 = t.layers[1]?.[0] as Hash;
    expect(hashNode(L0, L1)).toBe(N01);
    // 攻擊者宣稱「葉子資料 = L0‖R0」，附上少一層的 proof（N01 在 layer 1 的兄弟、layer 2 的兄弟）
    const shortProof = { siblings: [t.layers[1]?.[1] as Hash, t.layers[2]?.[1] as Hash], path: [0, 0] as (0 | 1)[] };
    const preimageA = concat(fromHex(L0), fromHex(L1));
    const preimageB = concat(new Uint8Array([0x01]), fromHex(L0), fromHex(L1)); // 連前綴一起偽造
    expect(verifyProof(t.root, preimageA, shortProof)).toBe(false);
    expect(verifyProof(t.root, preimageB, shortProof)).toBe(false);
    // 對照：若葉與內節點用同一種雜湊（無前綴），這個攻擊會成功
    const naiveHash = (d: Uint8Array) => toHex(sha256(d));
    const naiveNode = (l: Hash, r: Hash) => naiveHash(concat(fromHex(l), fromHex(r)));
    const nl = leaves8.map(naiveHash);
    const n01 = naiveNode(nl[0] as Hash, nl[1] as Hash);
    const n23 = naiveNode(nl[2] as Hash, nl[3] as Hash);
    const n45 = naiveNode(nl[4] as Hash, nl[5] as Hash);
    const n67 = naiveNode(nl[6] as Hash, nl[7] as Hash);
    const naiveRoot = naiveNode(naiveNode(n01, n23), naiveNode(n45, n67));
    let h = naiveHash(concat(fromHex(nl[0] as Hash), fromHex(nl[1] as Hash))); // 「葉子」= 內節點原像
    h = naiveNode(h, n23);
    h = naiveNode(h, naiveNode(n45, n67));
    expect(h).toBe(naiveRoot); // naive 方案下偽造成功 → 這就是 INV-2 要擋的事
  });

  it("odd leaf count handled per documented rule (EMPTY_NODE padding, no duplicate-last)", () => {
    for (const n of [1, 3, 5, 6, 7]) {
      const data = leaves8.slice(0, n);
      const t = buildTree(data);
      for (let i = 0; i < n; i++) expect(verifyProof(t.root, data[i] as Uint8Array, getProof(t, i))).toBe(true);
    }
    const t3 = buildTree(leaves8.slice(0, 3));
    expect(t3.layers[1]?.[1]).toBe(hashNode(t3.leaves[2] as Hash, EMPTY_NODE));
    // [a,b,c] 與 [a,b,c,c] 的 root 不同（重複最後節點的方案會相同）
    const t4dup = buildTree([...leaves8.slice(0, 3), leaves8[2] as Uint8Array]);
    expect(t3.root).not.toBe(t4dup.root);
    // 單葉樹：root = hashLeaf，proof 為空
    const t1 = buildTree([leaves8[0] as Uint8Array]);
    expect(t1.root).toBe(hashLeaf(leaves8[0] as Uint8Array));
    expect(getProof(t1, 0)).toEqual({ siblings: [], path: [] });
    expect(verifyProof(t1.root, leaves8[0] as Uint8Array, { siblings: [], path: [] })).toBe(true);
  });

  it("verifyProof rejects malformed proofs without throwing", () => {
    const t = buildTree(leaves8);
    const good = getProof(t, 0);
    expect(verifyProof(t.root, leaves8[0] as Uint8Array, { siblings: good.siblings, path: [0, 0] })).toBe(false);
    expect(verifyProof(t.root, leaves8[0] as Uint8Array, { siblings: ["0xzz" as Hash, ...good.siblings.slice(1)], path: good.path })).toBe(false);
    expect(verifyProof(t.root, leaves8[0] as Uint8Array, { siblings: good.siblings, path: [2, 0, 0] as unknown as (0 | 1)[] })).toBe(false);
    expect(verifyProof("0x12" as Hash, leaves8[0] as Uint8Array, good)).toBe(false);
    expect(verifyProof(t.root, leaves8[0] as Uint8Array, null as unknown as typeof good)).toBe(false);
    const huge = { siblings: Array(MAX_PROOF_DEPTH + 1).fill(EMPTY_NODE), path: Array(MAX_PROOF_DEPTH + 1).fill(0) as (0 | 1)[] };
    expect(verifyProof(t.root, leaves8[0] as Uint8Array, huge)).toBe(false);
    expect(() => buildTree([])).toThrow();
    expect(() => getProof(t, 8)).toThrow();
  });

  it("INV-7: guards hold even when the hash walk itself would succeed (mutation-hardened)", () => {
    // 上面那個測試的髒輸入在「檢查被拔掉」時也會因 h !== root 而 false——殺不死突變。
    // 這裡每個輸入都構造成「拔掉對應檢查後 verifyProof 會回 true」，所以檢查消失測試必紅。
    const leaf = leaves8[0] as Uint8Array;

    // (1) 深度上限：手工折出一條在數學上成立的 65 層 hash 走讀
    let acc = hashLeaf(leaf);
    const sibs: Hash[] = [];
    for (let i = 0; i < MAX_PROOF_DEPTH; i++) {
      const s = hashLeaf(utf8(`sib-${i}`));
      sibs.push(s);
      acc = hashNode(acc, s);
    }
    // 邊界：剛好 MAX_PROOF_DEPTH 層是合法的
    expect(verifyProof(acc, leaf, { siblings: [...sibs], path: Array(MAX_PROOF_DEPTH).fill(0) as (0 | 1)[] })).toBe(true);
    const extra = hashLeaf(utf8("sib-64"));
    const root65 = hashNode(acc, extra);
    expect(verifyProof(root65, leaf, { siblings: [...sibs, extra], path: Array(MAX_PROOF_DEPTH + 1).fill(0) as (0 | 1)[] })).toBe(false);

    // (2) siblings/path 長度不符：單葉樹 root = hashLeaf，空 siblings 走讀「少走一步就對」
    const t1 = buildTree([leaf]);
    expect(verifyProof(t1.root, leaf, { siblings: [], path: [0] as (0 | 1)[] })).toBe(false);

    // (3) siblings/path 非陣列：必須回 false 而不是丟錯（verifyProof 的不丟錯契約）
    const t = buildTree(leaves8);
    const good = getProof(t, 0);
    expect(verifyProof(t.root, leaf, { siblings: null, path: null } as unknown as MerkleProof)).toBe(false);

    // (4) leafData 非 Uint8Array：同內容的普通陣列若被收下，hash 走讀會完全成立
    expect(verifyProof(t.root, Array.from(leaf) as unknown as Uint8Array, good)).toBe(false);
  });
});

describe("core/commit", () => {
  it("commit/open round-trips", () => {
    const salt = randomSalt();
    expect(salt.length).toBe(32);
    const c = commit(utf8("50000"), salt);
    expect(open(c, { value: utf8("50000"), salt })).toBe(true);
    expect(open(c, { value: utf8("50001"), salt })).toBe(false);
  });

  it("open with wrong salt fails (binding)", () => {
    const c = commit(utf8("50000"), randomSalt());
    expect(open(c, { value: utf8("50000"), salt: randomSalt() })).toBe(false);
  });

  it("INV-3: commit() throws when salt < 32 bytes", () => {
    expect(() => commit(utf8("x"), new Uint8Array(31))).toThrow(/salt/);
    expect(() => commit(utf8("x"), new Uint8Array(0))).toThrow(/salt/);
    expect(open({ c: "0x00" as Hash }, { value: utf8("x"), salt: new Uint8Array(8) })).toBe(false);
    expect(commit(utf8("x"), new Uint8Array(32)).c).toMatch(/^0x[0-9a-f]{64}$/);
    expect(commit(utf8("x"), new Uint8Array(64)).c).not.toBe(commit(utf8("x"), new Uint8Array(32)).c);
  });

  it("INV-3 demo: unsalted commitment of value in [0,100000] is brute-forced quickly; salted is not", () => {
    const secret = 73_421;
    const encode = (n: number) => utf8(String(n));
    const unsalted = toHex(sha256(encode(secret)));
    const t0 = performance.now();
    let found = -1;
    for (let v = 0; v <= 100_000; v++) {
      if (toHex(sha256(encode(v))) === unsalted) {
        found = v;
        break;
      }
    }
    const ms = performance.now() - t0;
    expect(found).toBe(secret);
    expect(ms).toBeLessThan(2000);
    // 同樣的暴力法對有 salt 的承諾無效（攻擊者不知道 salt，只能猜 value）
    const c = commit(encode(secret), randomSalt());
    let hit = false;
    for (let v = 0; v <= 100_000 && !hit; v++) hit = open(c, { value: encode(v), salt: new Uint8Array(32) });
    expect(hit).toBe(false);
  });
});

describe("core/signer", () => {
  it("sign/verify round-trips", async () => {
    const s = Ed25519Signer.random();
    expect(s.publicKey).toMatch(/^0x[0-9a-f]{64}$/);
    const msg = tagged(TAG.MANDATE, utf8("body"));
    const sig = await s.sign(msg);
    expect(sig).toMatch(/^0x[0-9a-f]{128}$/);
    expect(await ed25519Verifier.verify(s.publicKey, msg, sig)).toBe(true);
    // 同一把私鑰 → 同一公鑰（決定性）
    const priv = new Uint8Array(32).fill(7);
    expect(new Ed25519Signer(priv).publicKey).toBe(new Ed25519Signer(priv).publicKey);
    expect(() => new Ed25519Signer(new Uint8Array(31))).toThrow();
  });

  it("flipping one byte of sig fails", async () => {
    const s = Ed25519Signer.random();
    const msg = utf8("m");
    const sig = fromHex(await s.sign(msg));
    sig[3] = (sig[3] ?? 0) ^ 0x80;
    expect(await ed25519Verifier.verify(s.publicKey, msg, toHex(sig))).toBe(false);
  });

  it("flipping one byte of message fails", async () => {
    const s = Ed25519Signer.random();
    const sig = await s.sign(utf8("message"));
    expect(await ed25519Verifier.verify(s.publicKey, utf8("messagf"), sig)).toBe(false);
  });

  it("wrong public key and malformed inputs return false, never throw", async () => {
    const a = Ed25519Signer.random();
    const b = Ed25519Signer.random();
    const sig = await a.sign(utf8("m"));
    expect(await ed25519Verifier.verify(b.publicKey, utf8("m"), sig)).toBe(false);
    expect(await ed25519Verifier.verify("0x1234" as Hash, utf8("m"), sig)).toBe(false);
    expect(await ed25519Verifier.verify(a.publicKey, utf8("m"), "0xnothex" as Hash)).toBe(false);
    expect(await ed25519Verifier.verify(a.publicKey, utf8("m"), `0x${"ff".repeat(64)}`)).toBe(false);
  });
});
