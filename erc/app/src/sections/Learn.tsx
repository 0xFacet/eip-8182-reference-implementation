import { Reveal, RevealItem } from "../components/Reveal.tsx";
import { Card } from "../components/Card.tsx";

type Screen = "identity" | "pools" | "send" | "move" | "activity";

const SPEC_URL = "/spec.html";

const STACK: Array<{ k: string; t: string; b: string }> = [
  { k: "identity", t: "Canonical privacy identity registry", b: "One chain-wide singleton binds an address to its owner hash, its set of authorization methods, and a post-quantum receive key — so a recipient registers once and is reachable on every conforming pool." },
  { k: "pools", t: "Shielded pools", b: "Ordinary contracts holding ETH or ERC-20s as notes: deposits and withdrawals are public and auditable, everything in between is a commitment, a nullifier, and ciphertext." },
  { k: "proofs", t: "Split-proof authorization", b: "The pool proves a transfer is valid against one canonical circuit; user authorization is dispatched to pluggable auth verifiers, so new auth methods ship without touching the relation." },
  { k: "delivery", t: "Encrypted note delivery", b: "Output notes are delivered as an ABI-encoded ML-KEM-768 envelope, resistant to harvest-now-decrypt-later. Recipients trial-decrypt pool events — no plaintext key identifier to correlate." },
  { k: "policy", t: "Optional policy verifiers", b: "A standardized hook for pools that want compliance, credential, membership, or disclosure checks on any operation — without forcing a regime on policy-free pools, which are first-class." },
  { k: "router", t: "Public-action / reshield router", b: "Unshield to a contract, perform a public action — swap, payment, bridge deposit — and reshield the result in the same transaction. The same mechanism moves value atomically between pools." },
];

const PILLARS: Array<{ n: string; t: string; b: string }> = [
  { n: "01", t: "Register once, reachable everywhere", b: "Identity is pool-independent. Joining a new pool has near-zero onboarding cost, because your receive key and owner hash already resolve on it." },
  { n: "02", t: "Move value atomically between pools", b: "Atomic unshield-and-reshield relocates a note across pools in one transaction, so anonymity sets are not sticky and users can migrate to the best pool." },
  { n: "03", t: "One circuit, one verifier, one registry", b: "Shared proving, wallet, and indexer infrastructure means pools compete on policy, governance, and assets — not on tooling. Build on existing work instead of one-off systems." },
];

const STEPS: Array<{ t: string; b: string; screen: Screen; tag: string }> = [
  { t: "Publish your identity", b: "Derive an owner nullifier key and a set of authorization methods, generate an ML-KEM-768 receive key, and publish them to the canonical registry. This is what lets others send to you and what your spends prove against.", screen: "identity", tag: "Identity" },
  { t: "Shield value", b: "Deposit ETH into a pool. The amount and your address land on-chain in the clear; what it mints is a shielded note only you can see or spend. The deposit is the last public thing that happens to that value.", screen: "pools", tag: "Pools" },
  { t: "Send privately", b: "Spend a note in the browser: a Groth16 pool proof shows the note is real and unspent, a pluggable auth proof shows you are authorized, and the recipient's new note is encrypted to their receive key. Sender, recipient, and amount stay shielded.", screen: "send", tag: "Send" },
  { t: "Discover & spend", b: "The recipient scans pool events, trial-decrypts the encrypted note data with their receive key, verifies the note commitment, and can spend it — no server, no shared secret, no key identifier on-chain.", screen: "activity", tag: "Activity" },
  { t: "Withdraw or move", b: "Exit to a public address, or relocate the note across pools through the router — unshielded to the router and re-deposited elsewhere in one transaction, so it never lands in a public wallet you control.", screen: "move", tag: "Move" },
];

export function Learn({ onNavigate }: { onNavigate: (s: Screen) => void }) {
  return (
    <Reveal className="section">
      <RevealItem>
        <div className="eyebrow">how it works</div>
        <h1 className="display-xl">
          Private transfers, <span className="accent">the whole stack</span>, at the application layer.
        </h1>
        <p className="lede">
          This is a complete standard — and a working reference implementation — for private ETH and ERC-20 transfers built entirely from
          ordinary smart contracts. No protocol change, no new chain: a canonical identity registry, shielded pools, in-browser proving,
          post-quantum note delivery, pluggable authorization, optional policy hooks, and an atomic cross-pool router, deployable on any EVM
          chain today.
        </p>
      </RevealItem>

      <RevealItem>
        <Card eyebrow="the boundary" title="What stays public, what stays private">
          <p className="muted small" style={{ marginTop: 0 }}>
            A public chain exposes every amount, sender, and recipient. This standard keeps the two ends of a transfer honest and everything
            between them hidden.
          </p>
          <div className="legend">
            <div className="legend-col">
              <div className="legend-head exposed-head">EXPOSED · public</div>
              <p>Deposits and withdrawals — amounts and addresses on-chain, auditable by anyone. The pool balance is public.</p>
            </div>
            <div className="legend-col">
              <div className="legend-head hidden-head">SHIELDED · private</div>
              <p>Notes, nullifier keys, and the encrypted payloads that carry them. Sender, recipient, and amount of a transfer reveal nothing.</p>
            </div>
          </div>
        </Card>
      </RevealItem>

      <RevealItem>
        <div className="eyebrow">a complete system, not just a pool</div>
        <h2 className="display-lg">Everything a private-transfer system needs — standardized to interoperate.</h2>
        <div className="feature-grid">
          {STACK.map((s) => (
            <div className="feature-cell" key={s.k}>
              <div className="feature-t">{s.t}</div>
              <div className="feature-b">{s.b}</div>
            </div>
          ))}
        </div>
      </RevealItem>

      <RevealItem>
        <Card eyebrow="why it matters" title="Interoperability is the point" accent>
          <p className="lede small" style={{ marginTop: 0 }}>
            Fragmented pools weaken privacy — each new pool splits the anonymity set. Rather than enshrine one pool, this standard fixes the
            interoperability surface so many pools can compete without fragmenting the engineering, and lets the market consolidate liquidity.
          </p>
          <div className="pillars">
            {PILLARS.map((p) => (
              <div className="pillar" key={p.n}>
                <div className="pillar-n">{p.n}</div>
                <div className="pillar-t">{p.t}</div>
                <div className="pillar-b">{p.b}</div>
              </div>
            ))}
          </div>
        </Card>
      </RevealItem>

      <RevealItem>
        <div className="eyebrow">the mechanism</div>
        <h2 className="display-lg">How a private transfer actually works.</h2>
        <div className="steps">
          {STEPS.map((s, i) => (
            <div className="step" key={s.screen}>
              <div className="step-n">{String(i + 1).padStart(2, "0")}</div>
              <div className="step-main">
                <div className="step-t">{s.t}</div>
                <p className="step-b">{s.b}</p>
                <button className="btn btn-ghost btn-tiny step-tag" onClick={() => onNavigate(s.screen)}>
                  {s.tag} →
                </button>
              </div>
            </div>
          ))}
        </div>
      </RevealItem>

      <RevealItem>
        <div className="callout">
          <div className="callout-k">related work · EIP-8182</div>
          <p>
            This standard shares its cryptographic core — notes, nullifiers, and split-proof authorization — with EIP-8182. Where EIP-8182
            answers pool fragmentation by enshrining one protocol-level pool under hard-fork governance, this takes the opposite bet: a
            complete, opinionated application-layer standard that ships the whole interoperability surface — the canonical registry, the one
            circuit, encrypted delivery — plus optional policy verifiers, so independently deployed pools interoperate and compete. The two
            can coexist; their domain-tag namespaces are disjoint, so artifacts never collide.
          </p>
        </div>
      </RevealItem>

      <RevealItem>
        <div className="cta-row">
          <a className="btn btn-accent lg" href={SPEC_URL} target="_blank" rel="noreferrer">
            Read the full draft spec →
          </a>
          <button className="btn btn-ghost lg" onClick={() => onNavigate("identity")}>
            Try it — set up your identity →
          </button>
        </div>
        <p className="muted xsmall" style={{ marginTop: 12 }}>
          The spec is a draft proposal published for this demo — it carries every domain separator, hash formula, and constant, and is not an
          assigned ERC number.
        </p>
      </RevealItem>
    </Reveal>
  );
}
