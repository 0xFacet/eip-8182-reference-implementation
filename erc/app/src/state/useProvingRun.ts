import { useCallback, useEffect, useRef, useState } from "react";
import type { ProvePhase } from "../components/ProvingOverlay.tsx";
import type { ProveResult } from "../prover/proverClient.ts";

export interface ProvingRunControls {
  setPhase: (p: ProvePhase) => void;
  setStatus: (s: string) => void;
  pushLog: (line: string) => void;
  setResult: (r: ProveResult) => void;
}

export function useProvingRun() {
  const [phase, setPhase] = useState<ProvePhase>("idle");
  const [status, setStatus] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const [result, setResult] = useState<ProveResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const startRef = useRef(0);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (phase === "signing" || phase === "proving" || phase === "submitting") {
      startRef.current = performance.now();
      timerRef.current = window.setInterval(() => setElapsedMs(performance.now() - startRef.current), 100);
    } else if (timerRef.current !== null) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
    return () => {
      if (timerRef.current !== null) window.clearInterval(timerRef.current);
    };
  }, [phase]);

  const pushLog = useCallback((line: string) => {
    setLog((l) => [...l, line]);
    setStatus(line);
  }, []);

  const dismiss = useCallback(() => {
    setPhase("idle");
    setStatus("");
    setLog([]);
    setResult(null);
    setError(null);
    setElapsedMs(0);
  }, []);

  const run = useCallback(
    async (fn: (c: ProvingRunControls) => Promise<void>) => {
      setLog([]);
      setResult(null);
      setError(null);
      setElapsedMs(0);
      setPhase("signing");
      try {
        await fn({ setPhase, setStatus, pushLog, setResult });
        setPhase("done");
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        setPhase("error");
      }
    },
    [pushLog],
  );

  return { phase, status, log, result, error, elapsedMs, run, dismiss };
}
