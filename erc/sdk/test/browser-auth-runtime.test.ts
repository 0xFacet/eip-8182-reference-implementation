import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { describe, expect, it } from "vitest";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ERC_ROOT = path.resolve(HERE, "../..");
const AUTH_ARTIFACT = path.join(ERC_ROOT, "circuits-noir/auth/target/auth.json");
const AUTH_PROVER_TOML = path.join(ERC_ROOT, "circuits-noir/auth/Prover.toml");
const AUTH_PUBLIC_INPUTS = path.join(ERC_ROOT, "circuits-noir/auth/target/public_inputs");

const PROVER_PACKAGES = [
  "@aztec/bb.js",
  "@noir-lang/acvm_js",
  "@noir-lang/noir_js",
  "@noir-lang/noirc_abi",
] as const;
const NOIR_RUNTIME_PACKAGES = ["@noir-lang/acvm_js", "@noir-lang/noir_js", "@noir-lang/noirc_abi"] as const;

type ProverPackage = (typeof PROVER_PACKAGES)[number];
type NoirRuntimePackage = (typeof NOIR_RUNTIME_PACKAGES)[number];
type RootPackageJson = { devDependencies?: Partial<Record<ProverPackage, string>> };
type PackageJson = { version: string };
type AuthArtifact = CompiledCircuit & { noir_version?: string };
type WasmPackage = {
  default?: (moduleOrPath?: unknown) => Promise<unknown>;
  initSync?: (module: Uint8Array | { module: Uint8Array }) => unknown;
};

function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

function packagePath(pkg: string, ...parts: string[]): string {
  return path.join(ERC_ROOT, "node_modules", ...pkg.split("/"), ...parts);
}

function installedVersion(pkg: ProverPackage): string {
  return readJson<PackageJson>(packagePath(pkg, "package.json")).version;
}

function assertPinnedRootVersion(pkg: ProverPackage): string {
  const root = readJson<RootPackageJson>(path.join(ERC_ROOT, "package.json"));
  const declared = root.devDependencies?.[pkg];
  expect(declared, `${pkg} must be a root devDependency`).toBeTypeOf("string");
  expect(declared, `${pkg} must be exact-pinned`).not.toMatch(/^[~^]/);
  expect(installedVersion(pkg)).toBe(declared);
  return declared!;
}

function artifactNoirVersion(artifact: AuthArtifact): string {
  expect(artifact.noir_version, "auth artifact should record the Noir compiler version").toBeTypeOf("string");
  return artifact.noir_version!.split("+", 1)[0]!;
}

function parseProverToml(raw: string): InputMap {
  const input: Record<string, string | number[]> = {};
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const match = /^([A-Za-z0-9_]+)\s*=\s*(.+)$/.exec(line);
    if (!match) throw new Error(`unsupported Prover.toml line: ${rawLine}`);
    const [, key, rawValue] = match;
    const value = rawValue.trim();

    if (value.startsWith("[")) {
      const bytes = [...value.matchAll(/"0x([0-9a-fA-F]{2})"/g)].map((m) => Number.parseInt(m[1]!, 16));
      if (bytes.length === 0) throw new Error(`empty or unsupported byte array for ${key}`);
      input[key!] = bytes;
    } else {
      const quoted = /^"([^"]*)"$/.exec(value);
      input[key!] = quoted ? quoted[1]! : value;
    }
  }
  return input as InputMap;
}

async function initNoirWasmPackage(pkg: NoirRuntimePackage, wasmFile: string): Promise<void> {
  const mod = (await import(pkg)) as WasmPackage;
  const wasm = fs.readFileSync(packagePath(pkg, "web", wasmFile));
  if (typeof mod.initSync === "function") {
    mod.initSync(wasm);
  } else if (typeof mod.default === "function") {
    await mod.default(wasm);
  }
}

function publicInputsFromFile(): string[] {
  const bytes = fs.readFileSync(AUTH_PUBLIC_INPUTS);
  expect(bytes.length % 32).toBe(0);
  const fields: string[] = [];
  for (let i = 0; i < bytes.length; i += 32) {
    fields.push(`0x${bytes.subarray(i, i + 32).toString("hex")}`);
  }
  return fields;
}

function normalizeReturnValues(value: unknown): string[] {
  expect(Array.isArray(value)).toBe(true);
  return (value as unknown[]).map((v) => `0x${BigInt(v as string | number | bigint).toString(16).padStart(64, "0")}`);
}

describe("browser auth prover runtime", () => {
  it("pins the JS prover runtime to the compiled auth artifact version", () => {
    const artifact = readJson<AuthArtifact>(AUTH_ARTIFACT);
    const noirVersion = artifactNoirVersion(artifact);

    for (const pkg of PROVER_PACKAGES) assertPinnedRootVersion(pkg);
    for (const pkg of NOIR_RUNTIME_PACKAGES) expect(installedVersion(pkg)).toBe(noirVersion);
  });

  it("loads and executes the shipped auth circuit with noir_js", async () => {
    await Promise.all([
      initNoirWasmPackage("@noir-lang/acvm_js", "acvm_js_bg.wasm"),
      initNoirWasmPackage("@noir-lang/noirc_abi", "noirc_abi_wasm_bg.wasm"),
    ]);

    const artifact = readJson<AuthArtifact>(AUTH_ARTIFACT);
    const noir = new Noir(artifact);
    await noir.init();

    const result = await noir.execute(parseProverToml(fs.readFileSync(AUTH_PROVER_TOML, "utf8")));
    expect(result.witness.length).toBeGreaterThan(0);
    expect(normalizeReturnValues(result.returnValue)).toEqual(publicInputsFromFile());
  });
});
