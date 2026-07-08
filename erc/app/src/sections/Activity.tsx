import { motion } from "framer-motion";
import { Reveal, RevealItem } from "../components/Reveal.tsx";
import { Card } from "../components/Card.tsx";
import { Shielded } from "../components/Shielded.tsx";
import { Gate } from "../components/Gate.tsx";
import { useChain } from "../state/useChain.ts";
import { useIdentity } from "../state/identity.tsx";
import { useNotes } from "../state/useNotes.ts";
import { fieldToHex, shortHex, weiLabel } from "../lib/format.ts";

export function Activity() {
  const { isConnected, deployment } = useChain();
  const { secrets } = useIdentity();
  const notesQ = useNotes();

  if (!isConnected) return <Gate reason="connect" />;
  if (!deployment) return <Gate reason="deployment" />;
  if (!secrets) return <Gate reason="identity" />;

  const notes = notesQ.data?.notes ?? [];
  const spent = notes.filter((n) => n.spent).length;
  const live = notes.length - spent;
  const balance = notes.filter((n) => !n.spent).reduce((s, n) => s + n.amount, 0n);

  return (
    <Reveal className="section">
      <RevealItem>
        <div className="eyebrow">indexer · note discovery</div>
        <h1 className="display-lg">Every output, trial-decrypted.</h1>
        <p className="lede small">
          The indexer scans <em className="exposed">public</em> deposit and transact logs across both pools and tries your ML-KEM secret key against
          each ciphertext. A note only resolves — <em className="hidden">ciphertext → plaintext</em> — when decryption succeeds and its recomputed
          commitment matches the on-chain leaf.
        </p>
      </RevealItem>

      <RevealItem>
        <Card
          eyebrow="scan"
          title="Discovered notes"
          right={
            <button className="btn btn-ghost" disabled={notesQ.isFetching} onClick={() => notesQ.refetch()}>
              {notesQ.isFetching ? "scanning…" : "Re-scan"}
            </button>
          }
        >
          <div className="activity-stats">
            <div>
              <div className="stat-num accent">{weiLabel(balance)}</div>
              <div className="stat-label">spendable</div>
            </div>
            <div>
              <div className="stat-num">{live}</div>
              <div className="stat-label">live notes</div>
            </div>
            <div>
              <div className="stat-num muted">{spent}</div>
              <div className="stat-label">spent (nullified)</div>
            </div>
          </div>

          {notes.length === 0 ? (
            <div className="muted small empty">{notesQ.isFetching ? "scanning logs…" : "no notes discovered for this identity yet"}</div>
          ) : (
            <div className="activity-list">
              {notes.map((n, i) => (
                <motion.div
                  key={n.id}
                  className={`activity-row${n.spent ? " spent" : ""}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.04 }}
                >
                  <div className="activity-left">
                    <span className={`resolve-dot ${n.spent ? "spent" : "live"}`} />
                    <div>
                      <div className="activity-amount">
                        <span className="accent">{weiLabel(n.amount)}</span>
                        <span className="activity-pool muted">{n.poolLabel}</span>
                      </div>
                      <div className="activity-sub muted">
                        leaf {n.leafIndex.toString()} · slot {n.outputIndex.toString()} · resolved from ciphertext
                      </div>
                    </div>
                  </div>
                  <div className="activity-right">
                    <span className="public-value tone-plain" title="noteCommitment (public leaf)">
                      {shortHex(fieldToHex(n.noteCommitment), 8, 6)}
                    </span>
                    {n.spent ? (
                      <span className="status-pill muted">nullified</span>
                    ) : (
                      <Shielded label="nullifier" value={fieldToHex(n.nullifier)} display={shortHex(fieldToHex(n.nullifier), 6, 6)} />
                    )}
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </Card>
      </RevealItem>
    </Reveal>
  );
}
