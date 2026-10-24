import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Ed25519Signer, ed25519Verifier } from "@mandate/core";
import { MemoryNonceStore, MemoryRevocationList, NoopCumulativeState, type PolicyVerifierOptions } from "@mandate/verifier";

const ROOT = join(__dirname, "..", "..");
const srcFiles = (pkg: string) =>
  readdirSync(join(ROOT, pkg, "src"))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => join(ROOT, pkg, "src", f));

/**
 * INV-11 / ADR-0002 是結構性規則，沒有執行期檢查可寫；
 * 這裡用兩個靜態斷言守住：驗證器拿不到私鑰（型別層），chain/verifier 不直接碰曲線庫。
 */
describe("verifier/structure", () => {
  it("INV-11: PolicyVerifierOptions has no slot for a Signer / private key (type-level)", () => {
    const base = {
      audience: "x",
      trustedRoots: new Set([Ed25519Signer.random().publicKey]),
      nonces: new MemoryNonceStore(),
      revocations: new MemoryRevocationList(),
      cumulative: new NoopCumulativeState(),
      sigv: ed25519Verifier,
    };
    // @ts-expect-error — 驗證器選項不接受 signer（INV-11）
    const withSigner: PolicyVerifierOptions = { ...base, signer: Ed25519Signer.random() };
    // @ts-expect-error — 也不接受私鑰 bytes
    const withPriv: PolicyVerifierOptions = { ...base, privateKey: new Uint8Array(32) };
    expect(Object.keys(base)).not.toContain("signer");
    expect(withSigner).toBeTruthy();
    expect(withPriv).toBeTruthy();
  });

  it("INV-11 / ADR-0002: chain and verifier never import @noble directly (only via @mandate/core Signer interface)", () => {
    for (const pkg of ["chain", "verifier"]) {
      for (const f of srcFiles(pkg)) {
        const text = readFileSync(f, "utf8");
        expect(text, f).not.toMatch(/@noble\//);
        expect(text, f).not.toMatch(/JSON\.stringify/); // ADR-0003：序列化只走 canonicalBytes
      }
    }
  });

  it("ADR-0003: only core/canonical.ts calls the canonicalize package", () => {
    for (const pkg of ["core", "chain", "verifier"]) {
      for (const f of srcFiles(pkg)) {
        const text = readFileSync(f, "utf8");
        if (f.endsWith("canonical.ts")) continue;
        expect(text, f).not.toMatch(/from "canonicalize"/);
      }
    }
  });
});
