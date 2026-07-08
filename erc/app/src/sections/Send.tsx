import { useMemo, useState } from "react";
import { isAddress, parseEther } from "viem";
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
import { resolveRecipient as appResolveRecipient, transact } from "../lib/clients.ts";
import { buildSpenderWitness, proveTransact, randomField } from "../lib/proveTransact.ts";
import { getNoteProof } from "../lib/indexer.ts";
import { buildTransfer, resolvePolicy, type FlowCommon } from "../lib/flows.ts";
import { makeIntentSigner } from "../lib/sign.ts";
import { hexToBytes } from "../../../sdk/src/bytes.ts";
import { shortHex, weiLabel } from "../lib/format.ts";
import { fieldToHex } from "../lib/format.ts";

type Resolution =
  | { ok: true; onkHash: bigint; kemPublicKey: Uint8Array; metadataVersion: number }
  | { ok: false; reason: string };

export function Send() {
  const { isConnected, deployment, pub, scanPub, wallet, address, chainId } = useChain();
  const { secrets, derived } = useIdentity();
  const notesQ = useNotes();
  const run = useProvingRun();

  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("0.02");
  const [poolKey, setPoolKey] = useState<"free" | "gated">("free");
  const [resolution, setResolution] = useState<Resolution | null>(null);
  const [resolving, setResolving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const amountWei = useMemo(() => {
    try {
      return parseEther((amount || "0") as `${number}`);
    } catch {
      return 0n;
    }
  }, [amount]);

  if (!isConnected) return <Gate reason="connect" />;
  if (!deployment) return <Gate reason="deployment" />;
  if (!secrets || !derived) return <Gate reason="identity" />;

  const pools = poolsOf(deployment);
  const pool = pools.find((p) => p.key === poolKey)!;
  const poolNotes = (notesQ.data?.byPool[pool.address] ?? []).filter((n) => !n.spent);
  const inputNote = poolNotes.find((n) => n.amount >= amountWei) ?? null;

  async function resolveRecipient() {
    setErr(null);
    setResolution(null);
    if (!isAddress(recipient)) {
      setResolution({ ok: false, reason: "not a valid address" });
      return;
    }
    setResolving(true);
    try {
      // Full spec §10 usability resolution, using the app's browser-safe ABIs.
      const res = await appResolveRecipient(
        pub!,
        { registry: deployment!.registry, pool: pool.address },
        recipient as Address,
      );
      if (!res.ok) {
        setResolution({ ok: false, reason: res.reason });
        return;
      }
      setResolution({
        ok: true,
        onkHash: res.recipient.ownerNullifierKeyHash,
        kemPublicKey: hexToBytes(res.recipient.mlKem768PublicKey),
        metadataVersion: res.recipient.metadataVersion,
      });
    } catch (e) {
      setResolution({ ok: false, reason: e instanceof Error ? e.message : String(e) });
    } finally {
      setResolving(false);
    }
  }

  async function send() {
    if (!wallet || !scanPub || !derived || !resolution?.ok || !inputNote) return;
    setErr(null);
    await run.run(async (c) => {
      const spender = await buildSpenderWitness(scanPub!, deployment!.registry, address!, derived, { fromBlock: deploymentStartBlock(deployment!, "registry") });
      const policy = await resolvePolicy(pub!, pool.address, pool.gated);
      const noteProof = await getNoteProof(scanPub!, pool.address, inputNote.leafIndex, { fromBlock: pool.startBlock });
      const block = await pub!.getBlock();
      const common: FlowCommon = {
        chainId: BigInt(chainId!),
        poolAddress: BigInt(pool.address),
        spender,
        noteCommitmentRoot: noteProof.root,
        input: { amount: inputNote.amount, noteSecret: inputNote.noteSecret, leafIndex: inputNote.leafIndex, siblings: noteProof.siblings },
        self: { onkHash: derived.onkHash, kemPublicKey: derived.kemPublicKey },
        nonce: randomField(),
        validUntilSeconds: BigInt(block.timestamp) + 3600n,
        blindingFactor: randomField(),
        policy,
        signIntent: makeIntentSigner(wallet, wallet.account),
      };
      const params = buildTransfer(common, { onkHash: resolution.onkHash, kemPublicKey: resolution.kemPublicKey }, amountWei);
      const { bundle, result } = await proveTransact(params, c);
      c.setPhase("submitting");
      c.pushLog("broadcasting private transfer…");
      const res = await transact(wallet, pub!, pool.address, address!, {
        poolProof: result.poolProofHex,
        authProof: result.authProofHex,
        publicInputs: bundle.publicInputs,
        outputNoteData: bundle.outputNoteData,
        policyData: bundle.policyData,
      });
      c.pushLog(`transfer settled · tx ${res.txHash.slice(0, 10)}… · recipient note encrypted to their ML-KEM key`);
    });
    notesQ.refetch();
  }

  const canSend = resolution?.ok && inputNote && amountWei > 0n && wallet && scanPub;

  return (
    <>
      <Reveal className="section">
        <RevealItem>
          <div className="eyebrow">private transfer</div>
          <h1 className="display-lg">Send value no one else can trace.</h1>
          <p className="lede small">
            Paste a recipient address. The app resolves their <em className="exposed">public</em> privacy profile, then builds a transfer whose
            amount and destination note stay <em className="hidden">shielded</em> — encrypted to their ML-KEM key and proven in your browser.
          </p>
        </RevealItem>

        <RevealItem>
          <Card eyebrow="step 1 · resolve" title="Recipient">
            <div className="field-row">
              <input
                className="text-input mono"
                placeholder="0x recipient address"
                value={recipient}
                onChange={(e) => {
                  setRecipient(e.target.value);
                  setResolution(null);
                }}
              />
              <button className="btn btn-ghost" disabled={resolving} onClick={resolveRecipient}>
                {resolving ? "resolving…" : "Resolve"}
              </button>
            </div>
            {resolution ? (
              resolution.ok ? (
                <div className="resolve-ok">
                  <span className="status-pill ok">profile resolved</span>
                  <div className="resolve-detail">
                    <span className="public-value tone-plain">metadata v{resolution.metadataVersion}</span>
                    <Shielded label="ownerNullifierKeyHash" value={fieldToHex(resolution.onkHash)} display={shortHex(fieldToHex(resolution.onkHash), 8, 8)} />
                    <span className="muted small">ML-KEM-768 key · {resolution.kemPublicKey.length} bytes</span>
                  </div>
                </div>
              ) : (
                <div className="banner error small">§10 check failed — {resolution.reason}</div>
              )
            ) : null}
          </Card>
        </RevealItem>

        <RevealItem>
          <Card eyebrow="step 2 · amount & source" title="Transfer">
            <div className="pool-select">
              {pools.map((p) => (
                <button key={p.key} className={`chip${poolKey === p.key ? " active" : ""}`} onClick={() => setPoolKey(p.key)}>
                  {p.label}
                </button>
              ))}
            </div>
            <div className="field-row">
              <input className="amount-input" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
              <span className="amount-unit">ETH</span>
            </div>
            <div className="source-note">
              {poolNotes.length === 0 ? (
                <span className="muted small">no notes in {pool.label} — deposit first under Pools</span>
              ) : inputNote ? (
                <span className="muted small">
                  spending note <span className="accent">{weiLabel(inputNote.amount)}</span> @ leaf {inputNote.leafIndex.toString()}
                  {inputNote.amount > amountWei ? ` · change ${weiLabel(inputNote.amount - amountWei)} returns to you` : ""}
                </span>
              ) : (
                <span className="banner error small">no single note covers {weiLabel(amountWei)} — deposit more or send less</span>
              )}
            </div>
            {err ? <div className="banner error small">{err}</div> : null}
            <div className="row-actions">
              <button className="btn btn-accent lg" disabled={!canSend} onClick={send}>
                Prove & send privately →
              </button>
            </div>
          </Card>
        </RevealItem>
      </Reveal>
      <ProvingOverlay {...run} onDismiss={() => { run.dismiss(); notesQ.refetch(); }} />
    </>
  );
}
