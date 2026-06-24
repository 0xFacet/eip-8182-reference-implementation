import type { BrowserProverRequest } from '../../src/index.js';
import type { BrowserProverResponse } from './proverWorker';

type WorkerRequestMessage = {
  type: 'prove';
  request: BrowserProverRequest;
};

type WorkerResponseMessage =
  | { type: 'status'; message: string }
  | { type: 'result'; result: BrowserProverResponse }
  | { type: 'error'; error: string };

export type { BrowserProverResponse };

export function proveTransferInBrowser(
  request: BrowserProverRequest,
  onStatus: (message: string) => void,
): Promise<BrowserProverResponse> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./proverWorker.ts', import.meta.url), { type: 'module' });
    let settled = false;

    worker.onmessage = (event: MessageEvent<WorkerResponseMessage>) => {
      const message = event.data;
      if (message.type === 'status') {
        onStatus(message.message);
        return;
      }
      if (settled) return;
      settled = true;
      worker.terminate();
      if (message.type === 'result') {
        resolve(message.result);
      } else {
        reject(new Error(message.error));
      }
    };

    worker.onerror = (event) => {
      if (settled) return;
      settled = true;
      worker.terminate();
      reject(new Error(event.message || 'browser prover worker failed'));
    };

    const message: WorkerRequestMessage = { type: 'prove', request };
    worker.postMessage(message);
  });
}
