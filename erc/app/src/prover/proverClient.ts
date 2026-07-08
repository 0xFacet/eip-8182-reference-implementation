import type { ProveRequest, ProveResult } from "./proverWorker.ts";

export type { ProveRequest, ProveResult };

type WorkerResponse =
  | { type: "status"; message: string }
  | { type: "result"; result: ProveResult }
  | { type: "error"; error: string };

/** Spin up the prover worker, stream status updates, resolve with the proofs. */
export function proveInBrowser(request: ProveRequest, onStatus: (message: string) => void): Promise<ProveResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./proverWorker.ts", import.meta.url), { type: "module" });
    let settled = false;
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const msg = event.data;
      if (msg.type === "status") {
        onStatus(msg.message);
        return;
      }
      if (settled) return;
      settled = true;
      worker.terminate();
      if (msg.type === "result") resolve(msg.result);
      else reject(new Error(msg.error));
    };
    worker.onerror = (event) => {
      if (settled) return;
      settled = true;
      worker.terminate();
      reject(new Error(event.message || "prover worker failed"));
    };
    worker.postMessage({ type: "prove", request });
  });
}
