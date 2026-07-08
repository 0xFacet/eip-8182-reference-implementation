import { useAccount } from "wagmi";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { getDeployment } from "../config/deployment.ts";
import { Reveal, RevealItem } from "../components/Reveal.tsx";
import { Card } from "../components/Card.tsx";
import { CopyButton } from "../components/CopyButton.tsx";
import { shortHex } from "../lib/format.ts";

const CONTRACTS = (d: ReturnType<typeof getDeployment>) => {
  if (!d) return [];
  const rows = [
    { k: "Identity Registry", v: d.registry, note: "onk + ML-KEM receive keys, depth-32 identity tree" },
    { k: "Pool Verifier", v: d.poolVerifier, note: "Groth16 — the 24-signal pool relation" },
    { k: "Auth Verifier (Honk)", v: d.honkVerifier, note: "UltraHonk — EIP-712 / ECDSA intent auth" },
    { k: "Policy-Free Pool", v: d.poolPolicyFree, note: "open shielded pool" },
    { k: "Allowlist-Gated Pool", v: d.poolAllowlistGated, note: "self-serve demo allowlist for deposits & withdrawals" },
    { k: "Public Action Router", v: d.publicActionRouter, note: "action-bound pool move and reshield helper" },
  ];
  return rows;
};

export function Overview({ onNavigate }: { onNavigate: (s: "identity") => void }) {
  const { isConnected, address, chainId } = useAccount();
  const deployment = getDeployment(chainId);
  const contracts = CONTRACTS(deployment);

  return (
    <Reveal className="section overview">
      <RevealItem>
        <div className="eyebrow">App-layer private transfers · reference wallet</div>
        <h1 className="display-xl">
          A vault for <span className="accent">value that stays private</span> even as it moves on a public chain.
        </h1>
        <p className="lede">
          Deposits and withdrawals are <em className="exposed">exposed</em> on-chain — amounts, addresses, plain to see. Everything in between
          is <em className="hidden">shielded</em>: notes, nullifier keys, and ciphertext that only their owner can read. Transfers are proven in
          your browser with a Groth16 pool proof and an UltraHonk authorization proof, then settled without revealing sender, recipient, or amount.
        </p>
      </RevealItem>

      <RevealItem>
        <Card eyebrow="the visual language" title="Public vs. private, everywhere">
          <div className="legend">
            <div className="legend-col">
              <div className="legend-head exposed-head">EXPOSED · public</div>
              <p>On-chain, visible to all. Rendered plainly.</p>
              <div className="legend-sample">
                <span className="public-value tone-address">0x8a79…c318</span>
                <span className="public-value tone-amount">0.25 ETH</span>
              </div>
            </div>
            <div className="legend-col">
              <div className="legend-head hidden-head">SHIELDED · private</div>
              <p>
                Cryptographic material. Blurred + glowing — <strong>hover or click to reveal</strong>.
              </p>
              <div className="legend-sample">
                <span className="shielded is-demo">
                  <span className="shielded-text">0x7c…nullifierKeyHash</span>
                </span>
              </div>
            </div>
          </div>
        </Card>
      </RevealItem>

      <RevealItem>
        <Card eyebrow="configured deployment" title="Live contract addresses">
          <div className="contract-grid">
            {contracts.map((c) => (
              <div className="contract-row" key={c.k}>
                <div className="contract-k">
                  <span className="public-value tone-plain">{c.k}</span>
                  <span className="contract-note">{c.note}</span>
                </div>
                <div className="contract-v">
                  <span className="public-value tone-address">{shortHex(c.v, 6, 4)}</span>
                  <CopyButton value={c.v} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </RevealItem>

      <RevealItem>
        <Card eyebrow="your session" title="Connection state" accent>
          {isConnected ? (
            <div className="conn-state">
              <div className="conn-line">
                <span className="dot live" /> connected as <span className="public-value tone-address">{shortHex(address ?? "0x", 6, 4)}</span> on chain{" "}
                <span className="public-value tone-plain">{chainId}</span>
              </div>
              <p className="muted">
                Next: derive your shielded identity so the pools unlock.
              </p>
              <button className="btn btn-accent" onClick={() => onNavigate("identity")}>
                Go to Identity →
              </button>
            </div>
          ) : (
            <div className="conn-state">
              <div className="conn-line">
                <span className="dot idle" /> no wallet connected
              </div>
              <p className="muted">Connect an anvil account to begin. The Overview is readable without one.</p>
              <ConnectButton />
            </div>
          )}
        </Card>
      </RevealItem>
    </Reveal>
  );
}
