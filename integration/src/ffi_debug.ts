import {
  appendFileSync,
  mkdirSync,
  readFileSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import { execSync } from "child_process";
import os from "os";
import { resolve } from "path";

const DEFAULT_WAIT_LOG_MS = 5_000;

export interface FfiLogger {
  enabled: boolean;
  logPath?: string;
  setStage(stage: string): void;
  log(message: string): void;
  noteLockAcquired(lockDir: string): void;
  noteLockReleased(): void;
}

interface LockOwnerMetadata {
  pid: number;
  script: string;
  acquiredAt: string;
  stage: string;
  logPath?: string;
}

export function createFfiLogger(script: string): FfiLogger {
  const enabled =
    isTruthy(process.env.EIP8182_FFI_DEBUG) || Boolean(process.env.EIP8182_FFI_LOG_DIR);
  const echoToStderr = enabled && process.env.EIP8182_FFI_LOG_STDERR !== "0";
  const baseDir =
    process.env.EIP8182_FFI_LOG_DIR || resolve(os.tmpdir(), "eip8182-ffi-logs");

  let logPath: string | undefined;
  let lockOwnerPath: string | undefined;
  let stage = "boot";
  let acquiredAt: string | undefined;

  if (enabled) {
    mkdirSync(baseDir, { recursive: true });
    const safeScript = script.replace(/[^a-zA-Z0-9_-]+/g, "_");
    logPath = resolve(baseDir, `${safeScript}-${process.pid}.log`);
    appendLine(logPath, formatLine(script, `log started pid=${process.pid}`));
  }

  const log = (message: string) => {
    if (!enabled) return;
    const line = formatLine(script, message);
    if (logPath) appendLine(logPath, line);
    if (echoToStderr) process.stderr.write(line);
  };

  const writeOwner = () => {
    if (!enabled || !lockOwnerPath || !acquiredAt) return;
    const owner: LockOwnerMetadata = {
      pid: process.pid,
      script,
      acquiredAt,
      stage,
      logPath,
    };
    writeFileSync(lockOwnerPath, `${JSON.stringify(owner, null, 2)}\n`);
  };

  return {
    enabled,
    logPath,
    setStage(nextStage: string) {
      stage = nextStage;
      log(`stage=${nextStage}`);
      writeOwner();
    },
    log,
    noteLockAcquired(lockDir: string) {
      if (!enabled) return;
      acquiredAt = new Date().toISOString();
      lockOwnerPath = resolve(lockDir, "owner.json");
      stage = "lock-acquired";
      writeOwner();
      log(`circuit lock acquired path=${lockDir}`);
    },
    noteLockReleased() {
      if (!enabled) return;
      log("circuit lock released");
      lockOwnerPath = undefined;
      acquiredAt = undefined;
    },
  };
}

export async function withLoggedCircuitLock<T>(
  lockDir: string,
  staleMs: number,
  logger: FfiLogger | undefined,
  fn: () => Promise<T>,
): Promise<T> {
  const waitStart = Date.now();
  let lastWaitLog = 0;

  while (true) {
    try {
      mkdirSync(lockDir);
      logger?.noteLockAcquired(lockDir);
      if (Date.now() - waitStart >= 1_000) {
        logger?.log(`lock wait finished duration=${formatDuration(Date.now() - waitStart)}`);
      }
      break;
    } catch (error: any) {
      if (error.code !== "EEXIST") throw error;

      const owner = readLockOwner(lockDir);
      const ageMs = readLockAge(lockDir);
      if (ageMs !== null && ageMs > staleMs) {
        logger?.log(
          `removing stale lock age=${formatDuration(ageMs)} holder=${formatLockOwner(owner)}`,
        );
        removeLockDir(lockDir);
        continue;
      }

      if (logger?.enabled && Date.now() - lastWaitLog >= DEFAULT_WAIT_LOG_MS) {
        lastWaitLog = Date.now();
        logger.log(
          `waiting for circuit lock duration=${formatDuration(Date.now() - waitStart)} holder=${formatLockOwner(owner)}`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  try {
    return await fn();
  } finally {
    logger?.noteLockReleased();
    removeLockDir(lockDir);
  }
}

export function execLogged(
  command: string,
  options: {
    cwd: string;
    env: Record<string, string | undefined>;
    timeout?: number;
    logger?: FfiLogger;
    stage: string;
  },
) {
  options.logger?.setStage(options.stage);
  options.logger?.log(
    `exec start stage=${options.stage} timeout_ms=${options.timeout ?? 0} cwd=${options.cwd} cmd=${command}`,
  );
  const startedAt = Date.now();
  try {
    execSync(command, {
      cwd: options.cwd,
      stdio: "pipe",
      timeout: options.timeout,
      env: options.env,
    });
    options.logger?.log(
      `exec finish stage=${options.stage} duration=${formatDuration(Date.now() - startedAt)}`,
    );
  } catch (error: any) {
    const stderr = summarizeOutput(error?.stderr);
    const stdout = summarizeOutput(error?.stdout);
    options.logger?.log(
      `exec fail stage=${options.stage} duration=${formatDuration(Date.now() - startedAt)} status=${error?.status ?? "unknown"} signal=${error?.signal ?? "none"} stdout=${JSON.stringify(stdout)} stderr=${JSON.stringify(stderr)}`,
    );
    throw error;
  }
}

function isTruthy(value: string | undefined): boolean {
  if (!value) return false;
  return value !== "0" && value.toLowerCase() !== "false";
}

function appendLine(path: string, line: string) {
  appendFileSync(path, line);
}

function formatLine(script: string, message: string): string {
  return `[${new Date().toISOString()}] [${script}:${process.pid}] ${message}\n`;
}

function formatDuration(ms: number): string {
  if (ms < 1_000) return `${ms}ms`;
  return `${(ms / 1_000).toFixed(1)}s`;
}

function summarizeOutput(value: unknown): string {
  if (!value) return "";
  try {
    const text = Buffer.isBuffer(value) ? value.toString("utf8") : String(value);
    return text.trim().replace(/\s+/g, " ").slice(0, 400);
  } catch {
    return "";
  }
}

function readLockAge(lockDir: string): number | null {
  try {
    return Date.now() - statSync(lockDir).mtimeMs;
  } catch {
    return null;
  }
}

function readLockOwner(lockDir: string): LockOwnerMetadata | null {
  try {
    return JSON.parse(readFileSync(resolve(lockDir, "owner.json"), "utf8")) as LockOwnerMetadata;
  } catch {
    return null;
  }
}

function formatLockOwner(owner: LockOwnerMetadata | null): string {
  if (!owner) return "unknown";
  const parts = [`${owner.script}:${owner.pid}`, `stage=${owner.stage}`];
  if (owner.logPath) parts.push(`log=${owner.logPath}`);
  return parts.join(" ");
}

function removeLockDir(lockDir: string) {
  try {
    unlinkSync(resolve(lockDir, "owner.json"));
  } catch {}
  try {
    rmdirSync(lockDir);
  } catch {}
}
