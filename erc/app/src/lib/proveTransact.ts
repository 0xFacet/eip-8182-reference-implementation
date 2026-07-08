import type { PublicClient, Address } from "viem";
import { buildTransactBundle } from "./transact.ts";
import type { BuildTransactParams, TransactBundle } from "./transact.ts";
import { proveInBrowser } from "../prover/proverClient.ts";
import type { ProveResult } from "../prover/proverClient.ts";
import type { ProvingRunControls } from "../state/useProvingRun.ts";
import { getIdentityProof } from "./indexer.ts";
import { getCurrentRoots, getPrivacyProfile } from "./clients.ts";
import type { DerivedIdentity } from "./identity.ts";
import type { BuilderSpender } from "./transact.ts";
import type { LogScan } from "./indexer.ts";

async function assertLocalIdentityPublished(
  pub: PublicClient,
  registry: Address,
  account: Address,
  derived: DerivedIdentity,
): Promise<void> {
  const profile = await getPrivacyProfile(pub, registry, account);
  if (!profile.identityRegistered) {
    throw new Error(`No on-chain identity for ${account}. Open Identity and register this wallet before spending.`);
  }
  if (profile.identity.ownerNullifierKeyHash !== derived.onkHash || profile.identity.noteSecretSeedHash !== derived.seedHash) {
    throw new Error("Your local identity keys do not match the registry profile for this wallet. Use the browser profile that registered this identity.");
  }
  if (profile.identity.policySetCommitment !== derived.policySetCommitment) {
    throw new Error("Your local policy set is not published. Open Identity, re-publish the profile, then retry.");
  }
}

/** Assemble the pool-circuit spender witness from the derived identity + a live identity proof. */
export async function buildSpenderWitness(
  pub: PublicClient,
  registry: Address,
  account: Address,
  derived: DerivedIdentity,
  scan: LogScan = {},
): Promise<BuilderSpender> {
  if (!derived.primary) throw new Error("no active authorization method in your policy set");
  await assertLocalIdentityPublished(pub, registry, account, derived);
  const authVerifier = derived.primary.method.authVerifier;
  const authVerifierCode = await pub.getCode({ address: authVerifier });
  if (!authVerifierCode || authVerifierCode === "0x") {
    throw new Error("The active auth verifier in your policy set is not deployed on this chain. Open Identity, update the policy method, and publish it.");
  }
  const idProof = await getIdentityProof(pub, registry, account, scan);
  return {
    authVerifier: BigInt(authVerifier),
    ownerNullifierKey: derived.onk,
    noteSecretSeed: derived.seed,
    noteSecretSeedHash: derived.seedHash,
    identityRoot: idProof.root,
    authorizingAddress: BigInt(account),
    authDataCommitment: derived.authDataCommitment,
    policySetCommitment: derived.policySetCommitment,
    registrationBlinder: derived.primary.blinder,
    policySlot: BigInt(derived.primary.slot),
    policySetSiblings: derived.primary.siblings,
    identityLeafPosition: idProof.leafPosition,
    identitySiblings: idProof.siblings,
  };
}

/** Current note + identity roots for a pool (as seen on-chain right now). */
export async function currentRoots(pub: PublicClient, pool: Address) {
  return getCurrentRoots(pub, pool);
}

/** Sign the intent, then generate both proofs in the worker. Drives the overlay. */
export async function proveTransact(
  build: BuildTransactParams,
  c: ProvingRunControls,
): Promise<{ bundle: TransactBundle; result: ProveResult }> {
  c.setPhase("signing");
  c.setStatus("Awaiting wallet signature on the private-transfer intent…");
  const bundle = await buildTransactBundle(build);
  c.pushLog("intent signed · witnesses assembled");

  c.setPhase("proving");
  const result = await proveInBrowser(
    {
      poolWitnessInput: bundle.poolWitnessInput,
      authCircuitInput: bundle.authCircuitInput,
      expectedPublicSignals: bundle.publicInputsArray.map((v) => v.toString()),
      expectedBlinded: bundle.blindedAuthCommitment.toString(),
      expectedDigest: bundle.transactionIntentDigest.toString(),
    },
    c.pushLog,
  );
  c.setResult(result);
  c.pushLog(`proofs verified locally · pool ${result.timings.poolProveMs}ms · auth ${result.timings.authProveMs}ms`);
  return { bundle, result };
}

/** A fresh random nonce/blinding field element for an intent. */
export function randomField(): bigint {
  const bytes = new Uint8Array(31);
  crypto.getRandomValues(bytes);
  let hex = "0x";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  const v = BigInt(hex);
  return v === 0n ? 1n : v;
}
