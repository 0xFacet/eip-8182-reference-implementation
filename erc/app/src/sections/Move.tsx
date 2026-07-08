import { useState } from "react";
import type { Address } from "viem";
import { Reveal, RevealItem } from "../components/Reveal.tsx";
import { Card } from "../components/Card.tsx";
import { Shielded } from "../components/Shielded.tsx";
import { Gate } from "../components/Gate.tsx";
import { ProvingOverlay } from "../components/ProvingOverlay.tsx";
import { useChain } from "../state/useChain.ts";
import { useIdentity } from "../state/identity.tsx";
import { useNotes } from "../state/useNotes.ts";
import { useProvingRun } from "../state/useProvingRun.ts";
import { deploymentStartBlock, poolsOf } from "../config/deployment.ts";
import {
  computeDownstreamActionCommitment,
  executeRouterMove,
  readDownstreamActionCommitment,
  sameAssetMoveSpec,
} from "../lib/clients.ts";
import { buildSpenderWitness, proveTransact, randomField } from "../lib/proveTransact.ts";
import { getNoteProof } from "../lib/indexer.ts";
import { buildWithdraw, resolvePolicy, type FlowCommon } from "../lib/flows.ts";
import { makeIntentSigner } from "../lib/sign.ts";
import { intentReplayId as intentReplayIdOf, ownerCommitment as ownerCommitmentOf, noteBodyCommitment } from "../../../sdk/src/derivations.ts";
import { encodeNotePayload, NOTE_PAYLOAD_KIND_DEPOSIT } from "../../../sdk/src/payload.ts";
import { encryptOutputNoteData } from "../../../sdk/src/envelope.ts";
import { fieldToAddress } from "../../../sdk/src/field.ts";
import { bytesToHex } from "../../../sdk/src/bytes.ts";
import { shortHex, weiLabel } from "../lib/format.ts";
import type { RecoveredNote } from "../lib/indexer.ts";

const ZERO_ADDRESS: Address = "0x0000000000000000000000000000000000000000";

export function Move() {
  const { isConnected, deployment, pub, scanPub, wallet, address, chainId } = useChain();
  const { secrets, derived } = useIdentity();
  const notesQ = useNotes();
  const run = useProvingRun();
  const [selected, setSelected] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  if (!isConnected) return <Gate reason="connect" />;
  if (!deployment) return <Gate reason="deployment" />;
  if (!secrets || !derived) return <Gate reason="identity" />;

  const pools = poolsOf(deployment);
  const freePool = pools.find((p) => p.key === "free")!;
  // Destination is the policy-free pool, so the reshield leg needs no policy data.
  // A "move" only means something across pools, so the source list excludes notes
  // that already live in the destination pool.
  const notes = (notesQ.data?.notes ?? []).filter(
    (n) => !n.spent && fieldToAddress(n.poolAddress, "pool").toLowerCase() !== freePool.address.toLowerCase(),
  );
  const chosen = notes.find((n) => n.id === selected) ?? null;
  const router = deployment.publicActionRouter;
  const destPool = freePool.address;

  async function move(note: RecoveredNote) {
    if (!wallet || !scanPub || !derived) return;
    if (!router) {
      setErr("PublicActionRouter is not deployed for this chain.");
      return;
    }
    setErr(null);
    const sourcePoolAddr = fieldToAddress(note.poolAddress, "pool") as Address;
    const sourcePool = pools.find((p) => p.address.toLowerCase() === sourcePoolAddr.toLowerCase());
    const noteSourceIsFree = sourcePoolAddr.toLowerCase() === freePool.address.toLowerCase();
    const sourceGated = sourcePool?.gated ?? !noteSourceIsFree;
    const sourceStartBlock = sourcePool?.startBlock ?? 0n;
    await run.run(async (c) => {
      const block = await pub!.getBlock();
      const nonce = randomField();
      const validUntilSeconds = BigInt(block.timestamp) + 3600n;

      const moveSecret = randomField();
      const oc = ownerCommitmentOf(BigInt(chainId!), BigInt(destPool), derived.onkHash, moveSecret);
      const nbc = noteBodyCommitment(oc, note.amount, 0n);
      const payload = encodeNotePayload({
        kind: NOTE_PAYLOAD_KIND_DEPOSIT,
        chainId: BigInt(chainId!),
        poolAddress: destPool,
        tokenAddress: ZERO_ADDRESS,
        amount: note.amount,
        ownerNullifierKeyHash: derived.onkHash,
        noteSecret: moveSecret,
        noteBodyCommitment: nbc,
        outputIndex: 0,
      });
      const depositNoteData = bytesToHex(await encryptOutputNoteData(derived.kemPublicKey, payload));

      const spender = await buildSpenderWitness(scanPub!, deployment!.registry, address!, derived, { fromBlock: deploymentStartBlock(deployment!, "registry") });
      const policy = await resolvePolicy(pub!, sourcePoolAddr, sourceGated);
      const noteProof = await getNoteProof(scanPub!, sourcePoolAddr, note.leafIndex, { fromBlock: sourceStartBlock });
      const replayId = intentReplayIdOf(spender.ownerNullifierKey, spender.authorizingAddress, BigInt(chainId!), BigInt(sourcePoolAddr), nonce);

      const spec = sameAssetMoveSpec({
        sourcePool: sourcePoolAddr,
        token: ZERO_ADDRESS,
        amount: note.amount,
        targetPool: destPool,
        ownerCommitment: oc,
        depositNoteData,
        routerDeadline: validUntilSeconds,
      });
      const commitment = computeDownstreamActionCommitment(BigInt(chainId!), sourcePoolAddr, replayId, router, spec);
      const onchainCommitment = await readDownstreamActionCommitment(pub!, router, BigInt(chainId!), sourcePoolAddr, replayId, spec);
      if (commitment !== onchainCommitment) throw new Error("router commitment mismatch");
      c.pushLog(`router action bound ${shortHex(`0x${commitment.toString(16)}`, 6, 6)}`);

      const common: FlowCommon = {
        chainId: BigInt(chainId!),
        poolAddress: BigInt(sourcePoolAddr),
        spender,
        noteCommitmentRoot: noteProof.root,
        input: { amount: note.amount, noteSecret: note.noteSecret, leafIndex: note.leafIndex, siblings: noteProof.siblings },
        self: { onkHash: derived.onkHash, kemPublicKey: derived.kemPublicKey },
        nonce,
        validUntilSeconds,
        blindingFactor: randomField(),
        policy,
        signIntent: makeIntentSigner(wallet, wallet.account),
      };
      const params = buildWithdraw(common, BigInt(router), note.amount);
      params.authorizedSubmitter = BigInt(router);
      params.downstreamActionCommitment = commitment;
      const { bundle, result } = await proveTransact(params, c);

      c.setPhase("submitting");
      c.pushLog("executeRouterMove — atomic unshield → reshield…");
      const hash = await executeRouterMove(
        wallet,
        pub!,
        router,
        address!,
        {
          from: sourcePoolAddr,
          poolProof: result.poolProofHex,
          authProof: result.authProofHex,
          publicInputs: bundle.publicInputs,
          outputNoteData: bundle.outputNoteData,
          policyData: bundle.policyData,
        },
        spec,
      );
      c.pushLog(`moved ${weiLabel(note.amount)} → policy-free pool · tx ${hash.slice(0, 10)}…`);
    });
    notesQ.refetch();
  }

  const gatedPool = pools.find((p) => p.key === "gated");
  const sourceLabel = chosen?.poolLabel ?? gatedPool?.label ?? "source pool";

  return (
    <>
      <Reveal className="section">
        <RevealItem>
          <div className="eyebrow">atomic pool-to-pool move</div>
          <h1 className="display-lg">Relocate a note without ever unshielding it to yourself.</h1>
          <p className="lede small">
            <code>PublicActionRouter</code> unshields your note to the router and re-deposits it into the policy-free pool in{" "}
            <em className="exposed">one transaction</em> — it never lands in a public wallet you control.
          </p>
        </RevealItem>

        <RevealItem>
          <Card eyebrow="the move" title={`${sourceLabel} → ${freePool.label}`}>
            <MoveFlow sourceLabel={sourceLabel} destLabel={freePool.label} amount={chosen?.amount ?? null} router={router} />

            <div className="note-list-head">
              <div className="eyebrow hidden-head">step 1 · choose a note to relocate</div>
            </div>
            {err ? <div className="banner error small">{err}</div> : null}
            {notes.length === 0 ? (
              <div className="muted small empty">
                no notes outside the policy-free pool — deposit into the {gatedPool?.label ?? "gated"} pool under Pools, then relocate it here
              </div>
            ) : (
              <div className="note-list">
                {notes.map((n) => (
                  <label className={`note-row selectable${selected === n.id ? " chosen" : ""}`} key={n.id}>
                    <input type="radio" name="movenote" checked={selected === n.id} onChange={() => setSelected(n.id)} />
                    <div className="note-info">
                      <span className="note-amount accent">{weiLabel(n.amount)}</span>
                      <span className="note-pool muted">{n.poolLabel}</span>
                      <Shielded label="noteSecret" value={`0x${n.noteSecret.toString(16)}`} display={shortHex(`0x${n.noteSecret.toString(16)}`, 6, 6)} />
                    </div>
                    <span className="muted small">→ {freePool.label}</span>
                  </label>
                ))}
              </div>
            )}
            <div className="row-actions">
              <button className="btn btn-accent lg" disabled={!chosen || !wallet || !scanPub || !router} onClick={() => chosen && move(chosen)}>
                Prove &amp; move →
              </button>
            </div>
            <p className="muted xsmall">
              Same-asset move via <code>PublicActionRouter</code> with no external action target.
            </p>
          </Card>
        </RevealItem>
      </Reveal>
      <ProvingOverlay {...run} onDismiss={() => { run.dismiss(); notesQ.refetch(); }} />
    </>
  );
}

/** Static, ambient-animated illustration of the atomic unshield -> reshield. The
 *  live run is narrated by ProvingOverlay (which covers this card), so this
 *  diagram exists to make the mechanism legible at rest. */
function MoveFlow({
  sourceLabel,
  destLabel,
  amount,
  router,
}: {
  sourceLabel: string;
  destLabel: string;
  amount: bigint | null;
  router: Address | undefined;
}) {
  const amt = amount != null ? weiLabel(amount) : "—";
  return (
    <div className="move-flow" aria-label="atomic unshield to reshield in one transaction">
      <div className="flow-frame-tag">one transaction · commits or reverts as a whole</div>
      <div className="flow-rail">
        <div className="flow-node shielded-node">
          <div className="flow-node-eyebrow hidden-head">source · shielded</div>
          <div className="flow-node-title">{sourceLabel}</div>
          <div className="flow-note-chip">
            <span className="flow-note-dot" />
            <span className="flow-note-amt">{amt}</span>
          </div>
        </div>

        <div className="flow-arrow">
          <span className="flow-arrow-label">unshield</span>
          <span className="flow-track"><span className="flow-pulse" /></span>
        </div>

        <div className="flow-node exposed-node">
          <div className="flow-node-eyebrow exposed-head">router · public for one instant</div>
          <div className="flow-node-title">PublicActionRouter</div>
          <div className="flow-binds">
            <span className="flow-bind"><span className="flow-bind-k">authorizedSubmitter</span> = {router ? shortHex(router, 4, 4) : "router"}</span>
            <span className="flow-bind"><span className="flow-bind-k">downstreamActionCommitment</span> · this move only</span>
          </div>
        </div>

        <div className="flow-arrow flow-arrow-2">
          <span className="flow-arrow-label">reshield</span>
          <span className="flow-track"><span className="flow-pulse" /></span>
        </div>

        <div className="flow-node shielded-node">
          <div className="flow-node-eyebrow hidden-head">destination · shielded</div>
          <div className="flow-node-title">{destLabel}</div>
          <div className="flow-note-chip">
            <span className="flow-note-dot" />
            <span className="flow-note-amt">{amt}</span>
          </div>
        </div>
      </div>
      <p className="flow-caption muted xsmall">
        The proof pins <code>authorizedSubmitter</code> to the router and binds the exact reshield with{" "}
        <code>downstreamActionCommitment</code>, so even a copied proof can only perform this one move — and the router keeps
        nothing.
      </p>
    </div>
  );
}
