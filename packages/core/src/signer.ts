import { ed25519 } from "@noble/curves/ed25519";
import { toHex, fromHex, isHexBytes } from "./hash.js";
import type { PubKey, Sig } from "./types.js";

/**
 * 簽名抽象（ADR-0002）。chain/verifier 只能依賴這個介面。
 * v0: Ed25519Signer；ZK 階段: BabyJubjubSigner（內層）。
 */
export interface Signer {
  readonly publicKey: PubKey;
  sign(bytes: Uint8Array): Promise<Sig>;
}

export interface SigVerifier {
  verify(pub: PubKey, bytes: Uint8Array, sig: Sig): Promise<boolean>;
}

export class Ed25519Signer implements Signer {
  readonly publicKey: PubKey;
  readonly #priv: Uint8Array;

  constructor(priv: Uint8Array) {
    if (!(priv instanceof Uint8Array) || priv.length !== 32) {
      throw new Error("Ed25519Signer: private key must be 32 bytes");
    }
    this.#priv = new Uint8Array(priv); // 複製，避免呼叫端之後改動
    this.publicKey = toHex(ed25519.getPublicKey(this.#priv));
  }

  static random(): Ed25519Signer {
    return new Ed25519Signer(ed25519.utils.randomSecretKey());
  }

  async sign(bytes: Uint8Array): Promise<Sig> {
    return toHex(ed25519.sign(bytes, this.#priv));
  }
}

/** 任何格式錯誤（長度、hex、非 canonical 簽章）一律回 false，不丟錯。 */
export const ed25519Verifier: SigVerifier = {
  async verify(pub, bytes, sig) {
    if (!isHexBytes(pub, 32) || !isHexBytes(sig, 64)) return false;
    if (!(bytes instanceof Uint8Array)) return false;
    try {
      return ed25519.verify(fromHex(sig), bytes, fromHex(pub));
    } catch {
      return false;
    }
  },
};
