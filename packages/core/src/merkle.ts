import { MERKLE_PREFIX } from "./tags.js";
import { sha256, toHex, fromHex, concat, isHexBytes } from "./hash.js";
import type { Hash } from "./types.js";

export interface MerkleProof {
  /** 兄弟節點，由葉到根 */
  siblings: Hash[];
  /** 每層自己在左(0)或右(1) */
  path: (0 | 1)[];
}

export interface MerkleTree {
  root: Hash;
  leaves: Hash[];        // 已加 LEAF 前綴雜湊後的葉子
  layers: Hash[][];      // layers[0] = leaves … 最後一層 = [root]
}

/**
 * 補位節點：32 個 0 byte。
 * 它不是任何 hashLeaf / hashNode 的可行輸出，所以不能被當成葉子或子樹宣稱。
 */
export const EMPTY_NODE: Hash = `0x${"00".repeat(32)}`;
/** proof 深度上限（防超長 proof 的 DoS）；2^64 片葉子遠超任何白名單。 */
export const MAX_PROOF_DEPTH = 64;

/** 葉子雜湊：sha256(0x00 ‖ data)（INV-2） */
export function hashLeaf(data: Uint8Array): Hash {
  return toHex(sha256(concat(new Uint8Array([MERKLE_PREFIX.LEAF]), data))); // INV-2
}

/** 內節點雜湊：sha256(0x01 ‖ left ‖ right)（INV-2） */
export function hashNode(left: Hash, right: Hash): Hash {
  return toHex(sha256(concat(new Uint8Array([MERKLE_PREFIX.NODE]), fromHex(left), fromHex(right)))); // INV-2
}

/**
 * 葉子數非 2 的冪時的規則：每一層若為奇數個節點，右側補一個 EMPTY_NODE。
 * 不採「重複最後一個節點」，因為那會讓 [a,b,c] 與 [a,b,c,c] 得到同一個 root。
 */
export function buildTree(leafData: Uint8Array[]): MerkleTree {
  if (leafData.length === 0) throw new Error("buildTree: empty tree");
  const leaves = leafData.map(hashLeaf);
  const layers: Hash[][] = [leaves];
  let cur = leaves;
  while (cur.length > 1) {
    const next: Hash[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      const l = cur[i] as Hash;
      const r = i + 1 < cur.length ? (cur[i + 1] as Hash) : EMPTY_NODE;
      next.push(hashNode(l, r));
    }
    layers.push(next);
    cur = next;
  }
  return { root: cur[0] as Hash, leaves, layers };
}

export function getProof(tree: MerkleTree, index: number): MerkleProof {
  if (!Number.isInteger(index) || index < 0 || index >= tree.leaves.length) {
    throw new Error("getProof: index out of range");
  }
  const siblings: Hash[] = [];
  const path: (0 | 1)[] = [];
  let idx = index;
  for (let d = 0; d < tree.layers.length - 1; d++) {
    const layer = tree.layers[d] as Hash[];
    const isRight = idx % 2 === 1;
    const sibIdx = isRight ? idx - 1 : idx + 1;
    siblings.push(sibIdx < layer.length ? (layer[sibIdx] as Hash) : EMPTY_NODE);
    path.push(isRight ? 1 : 0);
    idx = Math.floor(idx / 2);
  }
  return { siblings, path };
}

/**
 * 驗證 proof。leafData 一律先經 hashLeaf（0x00 前綴），
 * 因此內節點原像（left‖right）無法冒充葉子（INV-2）。
 * 任何格式問題一律回 false，不丟錯。
 */
export function verifyProof(root: Hash, leafData: Uint8Array, proof: MerkleProof): boolean {
  if (!isHexBytes(root, 32)) return false;
  if (!(leafData instanceof Uint8Array)) return false;
  if (typeof proof !== "object" || proof === null) return false;
  const { siblings, path } = proof;
  if (!Array.isArray(siblings) || !Array.isArray(path)) return false;
  if (siblings.length !== path.length || siblings.length > MAX_PROOF_DEPTH) return false;
  let h = hashLeaf(leafData); // INV-2
  for (let i = 0; i < siblings.length; i++) {
    const sib: unknown = siblings[i];
    const bit: unknown = path[i];
    if (!isHexBytes(sib, 32)) return false;
    if (bit === 0) h = hashNode(h, sib);
    else if (bit === 1) h = hashNode(sib, h);
    else return false;
  }
  return h === root;
}
