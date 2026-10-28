import { ed25519Verifier } from "@mandate/core";
import { MemoryCumulativeState, MemoryNonceStore, MemoryRevocationList, PolicyVerifier, type PolicyVerifierOptions } from "@mandate/verifier";
import { AUD, NOW, type World } from "../../chain/test/fixtures.js";

export function makeVerifier(w: World, over: Partial<PolicyVerifierOptions> = {}) {
  const nonces = new MemoryNonceStore();
  const revocations = new MemoryRevocationList();
  const cumulative = new MemoryCumulativeState();
  const pv = new PolicyVerifier({
    audience: AUD,
    trustedRoots: new Set([w.leader.publicKey]),
    nonces,
    revocations,
    cumulative,
    sigv: ed25519Verifier,
    clock: () => NOW,
    ...over,
  });
  return { pv, nonces, revocations, cumulative };
}
