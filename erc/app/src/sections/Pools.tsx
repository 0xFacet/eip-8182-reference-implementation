import { useState } from "react";
import { parseEther } from "viem";
import { useQuery } from "@tanstack/react-query";
import { Reveal, RevealItem } from "../components/Reveal.tsx";
import { Card } from "../components/Card.tsx";
import { Shielded } from "../components/Shielded.tsx";
import { Gate } from "../components/Gate.tsx";
import { ProvingOverlay } from "../components/ProvingOverlay.tsx";
import { useChain } from "../state/useChain.ts";
import { useIdentity } from "../state/identity.tsx";
import { useNotes } from "../state/useNotes.ts";
import { useProvingRun } from "../state/useProvingRun.ts";
import { deploymentStartBlock, poolsOf, type PoolMeta } from "../config/deployment.ts";
import { isAllowlisted, joinAllowlist, poolBalance, policyAppliesToOperations, transact } from "../lib/clients.ts";
import { depositEth } from "../lib/deposit.ts";
import { buildSpenderWitness, proveTransact, randomField } from "../lib/proveTransact.ts";
import { getNoteProof } from "../lib/indexer.ts";
import { buildWithdraw, resolvePolicy, type FlowCommon } from "../lib/flows.ts";
import { makeIntentSigner } from "../lib/sign.ts";
import { ethOf, weiLabel } from "../lib/format.ts";
import type { RecoveredNote } from "../lib/indexer.ts";

export function Pools() {
  const { isConnected, deployment } = useChain();
  const { secrets } = useIdentity();
  if (!isConnected) return <Gate reason="connect" />;
  if (!deployment) return <Gate reason="deployment" />;
  if (!secrets) return <Gate reason="identity" />;
  const pools = poolsOf(deployment);
  return <PoolsInner pools={pools} />;
}

function PoolsInner({ pools }: { pools: PoolMeta[] }) {
  const notesQ = useNotes();
  const run = useProvingRun();
  return (
    <>
      <Reveal className="section">
        <RevealItem>
          <div className="eyebrow">shielded pools</div>
          <h1 className="display-lg">Deposit in the open. Hold in the dark.</h1>
          <p className="lede small">
            A deposit is a <em className="exposed">public</em> act — the amount and your address land on-chain in the clear. What it mints is a{" "}
            <em className="hidden">shielded note</em>: only you can see its value or ever spend it.
          </p>
        </RevealItem>
        <RevealItem>
          <div className="pool-grid">
            {pools.map((p) => (
              <PoolCard key={p.key} pool={p} notesQ={notesQ} run={run} />
            ))}
          </div>
        </RevealItem>
      </Reveal>
      <ProvingOverlay {...run} onDismiss={() => { run.dismiss(); notesQ.refetch(); }} />
    </>
  );
}

function PoolCard({ pool, notesQ, run }: { pool: PoolMeta; notesQ: ReturnType<typeof useNotes>; run: ReturnType<typeof useProvingRun> }) {
  const { pub, scanPub, wallet, address, chainId, deployment } = useChain();
  const { derived } = useIdentity();
  const [amount, setAmount] = useState("0.05");
  const [busy, setBusy] = useState(false);
  const [joining, setJoining] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const statsQ = useQuery({
    queryKey: ["poolStats", pool.address, chainId],
    enabled: Boolean(pub),
    queryFn: async () => ({
      balance: await poolBalance(pub!, pool.address),
      applies: pool.gated ? await policyAppliesToOperations(pub!, pool.address) : 0n,
    }),
  });

  const notes = (notesQ.data?.byPool[pool.address] ?? []).filter((n) => !n.spent);
  const notesLoading = notesQ.isLoading || (notesQ.isFetching && !notesQ.data);
  const notesRefreshing = notesQ.isFetching && Boolean(notesQ.data);
  const notesError = notesQ.error instanceof Error ? notesQ.error.message : notesQ.error ? String(notesQ.error) : null;
  const allowlistQ = useQuery({
    queryKey: ["allowlist", chainId, deployment?.allowlistPolicyVerifier, address],
    enabled: Boolean(pool.gated && pub && deployment && address),
    queryFn: () => isAllowlisted(pub!, deployment!.allowlistPolicyVerifier, address!),
  });
  const allowlistError = allowlistQ.error instanceof Error ? allowlistQ.error.message : allowlistQ.error ? String(allowlistQ.error) : null;
  const joined = !pool.gated || allowlistQ.data === true;
  const canDeposit = Boolean(wallet && !busy && joined && (!pool.gated || !allowlistQ.isLoading));
  const badgeClass = pool.gated ? (joined ? "ok" : "warn") : "ok";
  const badgeText = pool.gated ? (allowlistQ.isLoading ? "checking" : joined ? "joined" : "gated") : "open";

  async function doJoinAllowlist() {
    if (!wallet || !pub || !deployment || !address) return;
    setErr(null);
    setJoining(true);
    try {
      await joinAllowlist(wallet, pub, deployment.allowlistPolicyVerifier, address);
      await allowlistQ.refetch();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setJoining(false);
    }
  }

  async function doDeposit() {
    if (!wallet || !derived) return;
    setErr(null);
    setBusy(true);
    try {
      await depositEth({
        pub: pub!,
        wallet,
        chainId: BigInt(chainId!),
        account: address!,
        pool: pool.address,
        gated: pool.gated,
        onkHash: derived.onkHash,
        kemPublicKey: derived.kemPublicKey,
        amount: parseEther(amount as `${number}`),
      });
      await Promise.all([statsQ.refetch(), notesQ.refetch()]);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function withdraw(note: RecoveredNote) {
    if (!wallet || !scanPub || !derived) return;
    await run.run(async (c) => {
      const spender = await buildSpenderWitness(scanPub!, deployment!.registry, address!, derived, { fromBlock: deploymentStartBlock(deployment!, "registry") });
      const policy = await resolvePolicy(pub!, pool.address, pool.gated);
      const noteProof = await getNoteProof(scanPub!, pool.address, note.leafIndex, { fromBlock: pool.startBlock });
      const block = await pub!.getBlock();
      const common: FlowCommon = {
        chainId: BigInt(chainId!),
        poolAddress: BigInt(pool.address),
        spender,
        noteCommitmentRoot: noteProof.root,
        input: { amount: note.amount, noteSecret: note.noteSecret, leafIndex: note.leafIndex, siblings: noteProof.siblings },
        self: { onkHash: derived.onkHash, kemPublicKey: derived.kemPublicKey },
        nonce: randomField(),
        validUntilSeconds: BigInt(block.timestamp) + 3600n,
        blindingFactor: randomField(),
        policy,
        signIntent: makeIntentSigner(wallet, wallet.account),
      };
      const params = buildWithdraw(common, BigInt(address!), note.amount);
      const { bundle, result } = await proveTransact(params, c);
      c.setPhase("submitting");
      c.pushLog("broadcasting withdrawal transact…");
      const res = await transact(wallet, pub!, pool.address, address!, {
        poolProof: result.poolProofHex,
        authProof: result.authProofHex,
        publicInputs: bundle.publicInputs,
        outputNoteData: bundle.outputNoteData,
        policyData: bundle.policyData,
      });
      c.pushLog(`withdrawn ${weiLabel(note.amount)} · tx ${res.txHash.slice(0, 10)}…`);
    });
  }

  const total = notes.reduce((s, n) => s + n.amount, 0n);

  return (
    <Card
      eyebrow={pool.gated ? "allowlist-gated" : "policy-free"}
      title={pool.label}
      right={<span className={`status-pill ${badgeClass}`}>{badgeText}</span>}
    >
      <p className="muted small">{pool.sub}</p>

      <div className="pool-stats">
        <div>
          <div className="stat-num">{statsQ.data ? ethOf(statsQ.data.balance) : "…"}</div>
          <div className="stat-label">ETH in pool (public)</div>
        </div>
        <div>
          <div className="stat-num accent">{notesQ.isLoading ? "…" : weiLabel(total)}</div>
          <div className="stat-label">your shielded balance</div>
        </div>
      </div>

      <div className="deposit-box">
        <div className="eyebrow exposed-head">public deposit</div>
        {pool.gated ? (
          <div className="allowlist-box">
            <div>
              <div className={`status-pill ${joined ? "ok" : "warn"}`}>{allowlistQ.isLoading ? "checking" : joined ? "allowlisted" : "not joined"}</div>
              <div className="muted small">self-serve gate for this demo pool</div>
            </div>
            <button className="btn btn-ghost" disabled={joining || joined || !wallet} onClick={doJoinAllowlist}>
              {joining ? "joining..." : joined ? "Joined" : "Join allowlist"}
            </button>
          </div>
        ) : null}
        {allowlistError ? <div className="banner error small">allowlist check failed: {allowlistError}</div> : null}
        <div className="deposit-row">
          <input className="amount-input" value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
          <span className="amount-unit">ETH</span>
          <button className="btn btn-accent" disabled={!canDeposit} onClick={doDeposit}>
            {busy ? "depositing…" : "Deposit"}
          </button>
        </div>
        {err ? <div className="banner error small">{err}</div> : null}
      </div>

      <div className="note-list">
        <div className="note-list-head">
          <div className="eyebrow hidden-head">your notes in this pool</div>
          <button className="btn btn-tiny btn-ghost" disabled={notesQ.isFetching} onClick={() => notesQ.refetch()}>
            {notesQ.isFetching ? "Scanning..." : "Rescan"}
          </button>
        </div>
        {notesError ? <div className="banner error small">note scan failed: {notesError}</div> : null}
        {notesLoading ? (
          <div className="muted small empty">scanning pool events...</div>
        ) : notes.length === 0 ? (
          <div className="muted small empty">
            {notesRefreshing ? "rescanning pool events..." : "no recovered notes for this identity"}
          </div>
        ) : (
          notes.map((n) => (
            <div className="note-row" key={n.id}>
              <div className="note-info">
                <span className="note-amount accent">{weiLabel(n.amount)}</span>
                <Shielded label="noteSecret" value={`0x${n.noteSecret.toString(16)}`} display={`0x${n.noteSecret.toString(16).slice(0, 10)}...`} />
                <span className="note-leaf muted">leaf {n.leafIndex.toString()}</span>
              </div>
              <button className="btn btn-ghost" disabled={!wallet || !scanPub} onClick={() => withdraw(n)}>
                Withdraw →
              </button>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}
