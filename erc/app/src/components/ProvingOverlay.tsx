import { AnimatePresence, motion } from "framer-motion";
import type { ProveResult } from "../prover/proverClient.ts";

export type ProvePhase = "idle" | "signing" | "proving" | "submitting" | "done" | "error";

interface ProvingOverlayProps {
  phase: ProvePhase;
  status: string;
  log: string[];
  elapsedMs: number;
  result: ProveResult | null;
  error: string | null;
  onDismiss: () => void;
}

const PHASE_LABEL: Record<ProvePhase, string> = {
  idle: "",
  signing: "Awaiting wallet signature",
  proving: "Generating zero-knowledge proofs",
  submitting: "Broadcasting transaction",
  done: "Shielded",
  error: "Halted",
};

export function ProvingOverlay({ phase, status, log, elapsedMs, result, error, onDismiss }: ProvingOverlayProps) {
  const open = phase !== "idle";
  const spinning = phase === "signing" || phase === "proving" || phase === "submitting";
  return (
    <AnimatePresence>
      {open && (
        <motion.div className="overlay" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <motion.div
            className={`overlay-panel${phase === "error" ? " is-error" : ""}${phase === "done" ? " is-done" : ""}`}
            initial={{ scale: 0.96, y: 12, opacity: 0 }}
            animate={{ scale: 1, y: 0, opacity: 1 }}
            exit={{ scale: 0.98, opacity: 0 }}
            transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="prover-core" data-phase={phase}>
              <div className="ring ring-a" />
              <div className="ring ring-b" />
              <div className="ring ring-c" />
              <div className="core-dot">
                {phase === "done" ? "✓" : phase === "error" ? "!" : <span className="core-count">{Math.round(elapsedMs / 100) / 10}s</span>}
              </div>
              {spinning && (
                <>
                  <motion.div className="scan" animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2.4, ease: "linear" }} />
                </>
              )}
            </div>

            <div className="eyebrow">{PHASE_LABEL[phase]}</div>
            <div className="prover-status">{error ?? status}</div>

            <div className="prover-log">
              {log.slice(-6).map((line, i) => (
                <motion.div key={`${i}-${line}`} className="log-line" initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}>
                  <span className="log-caret">›</span> {line}
                </motion.div>
              ))}
            </div>

            {result && (
              <div className="prover-timings">
                <div>
                  <span className="t-num">{result.timings.poolProveMs}</span>
                  <span className="t-unit">ms</span>
                  <span className="t-label">pool · Groth16</span>
                </div>
                <div>
                  <span className="t-num">{result.timings.authProveMs}</span>
                  <span className="t-unit">ms</span>
                  <span className="t-label">auth · UltraHonk</span>
                </div>
              </div>
            )}

            {(phase === "done" || phase === "error") && (
              <button type="button" className="btn btn-ghost overlay-dismiss" onClick={onDismiss}>
                {phase === "done" ? "Done" : "Dismiss"}
              </button>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
