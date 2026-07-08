import { useState } from "react";
import { useSignMessage } from "wagmi";
import { useQuery } from "@tanstack/react-query";
import { Reveal, RevealItem } from "../components/Reveal.tsx";
import { Card } from "../components/Card.tsx";
import { Shielded } from "../components/Shielded.tsx";
import { CopyButton } from "../components/CopyButton.tsx";
import { Gate } from "../components/Gate.tsx";
import { useChain } from "../state/useChain.ts";
import { useIdentity } from "../state/identity.tsx";
import { getPrivacyProfile, getCurrentIdentityRoot, setFullProfile } from "../lib/clients.ts";
import { IDENTITY_SIGN_TEMPLATE, deriveIdentity, expandIdentity, randomBlinderHex } from "../lib/identity.ts";
import type { AuthMethod } from "../lib/identity.ts";
import { bytesToHex } from "../../../sdk/src/bytes.ts";
import { fieldToHex, shortHex } from "../lib/format.ts";

export function Identity() {
  const { address, chainId, isConnected, pub, wallet, deployment } = useChain();
  const { secrets, derived, save } = useIdentity();
  const { signMessageAsync } = useSignMessage();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const profileQ = useQuery({
    queryKey: ["profile", chainId, deployment?.registry, address],
    enabled: Boolean(pub && deployment && address),
    queryFn: async () => {
      const profile = await getPrivacyProfile(pub!, deployment!.registry, address!);
      const root = await getCurrentIdentityRoot(pub!, deployment!.registry);
      return { profile, root };
    },
  });

  if (!isConnected) return <Gate reason="connect" />;
  if (!deployment) return <Gate reason="deployment" />;

  async function derive() {
    setError(null);
    setBusy("Signing derivation message…");
    try {
      const signature = await signMessageAsync({ message: IDENTITY_SIGN_TEMPLATE(chainId!, address!) });
      const next = deriveIdentity({ chainId: chainId!, account: address!, signature, authVerifier: deployment!.ecdsaAuthVerifier });
      save(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function publish(nextSecrets = secrets) {
    if (!nextSecrets || !wallet) return;
    setError(null);
    setBusy("Publishing profile (setFullProfile)…");
    try {
      const d = expandIdentity(nextSecrets);
      await setFullProfile(wallet, pub!, deployment!.registry, address!, {
        ownerNullifierKeyHash: d.onkHash,
        noteSecretSeedHash: d.seedHash,
        policySetCommitment: d.policySetCommitment,
        mlKem768PublicKey: bytesToHex(d.kemPublicKey),
        metadataVersion: 1,
      });
      await profileQ.refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  function mutateMethods(methods: AuthMethod[]) {
    if (!secrets) return;
    save({ ...secrets, authMethods: methods });
  }

  const onchainOnk = profileQ.data?.profile.identity.ownerNullifierKeyHash ?? 0n;
  const onchainSeedHash = profileQ.data?.profile.identity.noteSecretSeedHash ?? 0n;
  const registered = profileQ.data?.profile.identityRegistered ?? false;
  const localOnk = derived?.onkHash ?? 0n;
  const localSeedHash = derived?.seedHash ?? 0n;
  const inSync =
    registered &&
    onchainOnk === localOnk &&
    onchainSeedHash === localSeedHash &&
    profileQ.data?.profile.identity.policySetCommitment === derived?.policySetCommitment;

  return (
    <Reveal className="section">
      <RevealItem>
        <div className="eyebrow">privacy identity</div>
        <h1 className="display-lg">Your keys, {secrets ? "derived" : "not yet derived"}.</h1>
        <p className="lede small">
          One wallet signature deterministically seeds your <span className="hidden">ownerNullifierKey</span> and{" "}
          <span className="hidden">noteSecretSeed</span>, plus a local ML-KEM-768 receive key. Only the <em className="exposed">hashes</em> and
          your <em className="exposed">public receive key</em> ever touch the chain.
        </p>
      </RevealItem>

      {error ? (
        <RevealItem>
          <div className="banner error">{error}</div>
        </RevealItem>
      ) : null}

      {!secrets ? (
        <RevealItem>
          <Card eyebrow="guided setup" title="Derive your shielded identity" accent>
            <ol className="steps">
              <li>Sign a domain-separated message bound to this chain and account. No gas, no transaction.</li>
              <li>The signature seeds your private keys locally (stored in this browser only — a demo convenience).</li>
              <li>Publish the commitments on-chain with a single <code>setFullProfile</code>.</li>
            </ol>
            <button className="btn btn-accent" disabled={Boolean(busy)} onClick={derive}>
              {busy ?? "Sign & derive identity"}
            </button>
          </Card>
        </RevealItem>
      ) : (
        <>
          <RevealItem>
            <Card
              eyebrow="key material"
              title="Identity"
              right={<span className={`status-pill ${inSync ? "ok" : registered ? "warn" : "idle"}`}>{inSync ? "in sync" : registered ? "needs re-publish" : "unregistered"}</span>}
            >
              <div className="kv-grid">
                <KVPrivate label="ownerNullifierKey" value={secrets.onk} note="private — spends your notes" />
                <KVPublic label="ownerNullifierKeyHash" value={fieldToHex(derived!.onkHash)} note="published · identity leaf" />
                <KVPrivate label="noteSecretSeed" value={secrets.seed} note="private — derives every note secret" />
                <KVPublic label="noteSecretSeedHash" value={fieldToHex(derived!.seedHash)} note="published · identity leaf" />
                <KVPrivate label="ML-KEM-768 secretKey" value={secrets.kemSecretKey} note="private — trial-decrypts inbound notes" />
                <KVPublic label="ML-KEM-768 publicKey" value={secrets.kemPublicKey} note="published · receive plane" short />
                <KVPublic label="policySetCommitment" value={fieldToHex(derived!.policySetCommitment)} note="root of your auth-method set" />
                <KVPublic
                  label="identityRoot (on-chain)"
                  value={profileQ.data ? fieldToHex(profileQ.data.root) : "…"}
                  note="registry current root"
                />
              </div>
              <div className="row-actions">
                <button className="btn btn-accent" disabled={Boolean(busy) || !wallet} onClick={() => publish()}>
                  {busy ?? (registered ? "Re-publish profile" : "Register on-chain")}
                </button>
                {registered && (onchainOnk !== localOnk || onchainSeedHash !== localSeedHash) ? (
                  <span className="muted small">on-chain key hashes differ from local — use the browser profile that registered this identity</span>
                ) : null}
              </div>
            </Card>
          </RevealItem>

          <RevealItem>
            <PolicyManager methods={secrets.authMethods} onChange={mutateMethods} onPublish={() => publish()} busy={busy} />
          </RevealItem>
        </>
      )}
    </Reveal>
  );
}

function PolicyManager({
  methods,
  onChange,
  onPublish,
  busy,
}: {
  methods: AuthMethod[];
  onChange: (m: AuthMethod[]) => void;
  onPublish: () => void;
  busy: string | null;
}) {
  const { deployment } = useChain();
  function addMethod() {
    const usedSlots = new Set(methods.map((m) => m.slot));
    let slot = 0;
    while (usedSlots.has(slot)) slot++;
    onChange([
      ...methods,
      {
        id: crypto.randomUUID(),
        label: `Additional method · slot ${slot}`,
        slot,
        authVerifier: deployment?.ecdsaAuthVerifier ?? "0x0000000000000000000000000000000000000000",
        blinder: randomBlinderHex(),
        revoked: false,
      },
    ]);
  }
  return (
    <Card
      eyebrow="policy set"
      title="Authorization methods"
      right={
        <button className="btn btn-ghost" onClick={addMethod}>
          + add method
        </button>
      }
    >
      <p className="muted small">
        Your policy set is a depth-8 sparse tree of authorization methods; its root is the <code>policySetCommitment</code> in your identity leaf.
        Rotating a method reseeds its blinder (a fresh commitment); revoking clears its slot. Any change moves the identity root — the registry keeps a
        64-block root-history window so in-flight proofs against the previous root still verify while wallets catch up.
      </p>
      <div className="method-list">
        {methods.map((m) => {
          const activeCount = methods.filter((x) => !x.revoked).length;
          const isLastActive = !m.revoked && activeCount <= 1;
          return (
          <div key={m.id} className={`method-row${m.revoked ? " revoked" : ""}`}>
            <div className="method-main">
              <span className="method-slot">slot {m.slot}</span>
              <span className="method-label">{m.label}</span>
              <span className="method-verifier public-value tone-address">{shortHex(m.authVerifier, 6, 4)}</span>
            </div>
            <div className="method-blinder">
              <Shielded label="blinder" value={m.blinder} display={shortHex(m.blinder, 6, 6)} />
            </div>
            <div className="method-actions">
              <button
                className="btn btn-tiny"
                onClick={() => onChange(methods.map((x) => (x.id === m.id ? { ...x, blinder: randomBlinderHex() } : x)))}
              >
                rotate
              </button>
              <button
                className="btn btn-tiny"
                disabled={isLastActive}
                title={isLastActive ? "Can't revoke your only active method — spending would be disabled until you restore or add one." : undefined}
                onClick={() => onChange(methods.map((x) => (x.id === m.id ? { ...x, revoked: !x.revoked } : x)))}
              >
                {m.revoked ? "restore" : "revoke"}
              </button>
              {m.id !== "primary" ? (
                <button className="btn btn-tiny danger" onClick={() => onChange(methods.filter((x) => x.id !== m.id))}>
                  remove
                </button>
              ) : null}
            </div>
          </div>
          );
        })}
      </div>
      <div className="row-actions">
        <button className="btn btn-accent" disabled={Boolean(busy)} onClick={onPublish}>
          {busy ?? "Publish policy-set change"}
        </button>
      </div>
    </Card>
  );
}

function KVPrivate({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="kv">
      <div className="kv-label hidden-head">{label}</div>
      <Shielded label="" value={value} display={value.length > 26 ? shortHex(value, 8, 8) : value} />
      <div className="kv-note">{note}</div>
    </div>
  );
}

function KVPublic({ label, value, note, short }: { label: string; value: string; note: string; short?: boolean }) {
  return (
    <div className="kv">
      <div className="kv-label exposed-head">{label}</div>
      <div className="kv-public">
        <span className="public-value tone-plain">{short ? shortHex(value, 10, 6) : shortHex(value, 10, 8)}</span>
        <CopyButton value={value} />
      </div>
      <div className="kv-note">{note}</div>
    </div>
  );
}
