import { randomBytes, toHex, type Signer } from "@mandate/core";
import { mandateSigningBytes } from "./bytes.js";
import { isNonNegInt } from "./guards.js";
import type { Mandate, MandateBody, Scope } from "./types.js";

export interface IssueRootParams {
  subject: Mandate["body"]["subject"];
  audience: string;
  issuedAt: number;
  expiresAt: number;
  maxDepth: number;
  scope: Scope;
}

/** leader 簽根授權 c₀。parentId = null。 */
export async function issueRoot(signer: Signer, p: IssueRootParams): Promise<Mandate> {
  if (!isNonNegInt(p.maxDepth)) throw new Error("issueRoot: maxDepth must be a non-negative integer");
  if (!isNonNegInt(p.issuedAt) || !isNonNegInt(p.expiresAt) || p.expiresAt <= p.issuedAt) {
    throw new Error("issueRoot: expiresAt must be > issuedAt");
  }
  const body: MandateBody = {
    v: 1,
    mandateId: toHex(randomBytes(32)),
    parentId: null,
    issuer: signer.publicKey,
    subject: p.subject,
    audience: p.audience,
    issuedAt: p.issuedAt,
    expiresAt: p.expiresAt,
    maxDepth: p.maxDepth,
    scope: p.scope,
  };
  const sig = await signer.sign(mandateSigningBytes(body));
  return { body, sig };
}
