import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");
const benchmarkProofsScript = resolve(repoRoot, "scripts", "benchmark-eip712-proofs.mjs");
const contractTestsScript = resolve(repoRoot, "scripts", "run-contract-tests.mjs");

const CASES = ["transfer", "withdraw"];
const DEFAULT_PROOF_RUNS = 10;
const MAX_CAPTURE_BYTES = 100 * 1024 * 1024;
const ARTIFACT_SIZE_FILES = [
  "assets/eip-8182/outer_vk.bin",
  "assets/eip-8182/outer_vk.bb_hash.hex",
  "assets/eip-8182/outer_verifier_metadata.json",
  "assets/eip-8182/outer_verifier_transcript_vk_hash.hex",
  "assets/eip-8182/poseidon2_vectors.json",
  "assets/eip-8182/delivery_scheme1_vectors.json",
  "circuits/target/outer.json",
  "circuits/target/eip712.json",
  "contracts/out/HonkVerifier.sol/HonkVerifier.json",
  "contracts/out/HonkVerifier.sol/ZKTranscriptLib.json",
  "contracts/out/ShieldedPool.sol/ShieldedPool.json",
];
const REQUIRED_STATIC_REPO_PATHS = [
  benchmarkProofsScript,
  contractTestsScript,
  ...ARTIFACT_SIZE_FILES.filter((relativePath) => relativePath.startsWith("assets/eip-8182/")).map(
    (relativePath) => resolve(repoRoot, relativePath),
  ),
];

main();

function main() {
  const options = parseArgs(process.argv.slice(2));
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outDir = resolve(options.outDirRoot, options.variant, timestamp);
  mkdirSync(outDir, { recursive: true });

  const summary = {
    variant: options.variant,
    timestamp,
    repoRoot,
    git: collectGitMetadata(),
    options: {
      proofRuns: options.proofRuns,
      selectedCases: options.cases,
      verify: options.verify,
      outDir,
    },
    steps: [],
    proofBenchmarkSummary: null,
    gasBenchmarkSummary: null,
    artifactSizeSummary: null,
    compatibilitySummary: null,
  };

  initializeOutputBundle(outDir, options.verify);
  writeSummary(outDir, summary);

  try {
    validateBenchmarkPreflight();

    runStep(summary, outDir, {
      title: "contracts:build",
      command: "npm",
      args: ["run", "contracts:build"],
      cwd: repoRoot,
      stem: "contracts-build",
    });

    const proofResults = runProofBenchmarks(options, outDir, summary);
    summary.proofBenchmarkSummary = proofResults.summary;
    writeSummary(outDir, summary);

    const gasResults = runGasBenchmarks(outDir, summary);
    summary.gasBenchmarkSummary = gasResults.summary;
    writeSummary(outDir, summary);

    const artifactSizes = collectArtifactSizes();
    writeJson(resolve(outDir, "artifact-sizes.json"), artifactSizes);
    summary.artifactSizeSummary = artifactSizes;
    writeSummary(outDir, summary);

    if (options.verify) {
      const compatibilityResults = runCompatibilityChecks(outDir, summary);
      summary.compatibilitySummary = compatibilityResults.summary;
      writeSummary(outDir, summary);
    }

    printHumanSummary(summary, outDir);
  } catch (error) {
    if (!summary.failure) {
      summary.failure = normalizeFailure(error);
    }
    writeSummary(outDir, summary);
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[benchmark] ${message}`);
    process.exit(1);
  }
}

function parseArgs(args) {
  let variant = null;
  let outDirRoot = resolve(repoRoot, "tmp", "benchmark-results");
  let proofRuns = DEFAULT_PROOF_RUNS;
  let verify = false;
  let cases = [...CASES];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--variant") {
      variant = args[index + 1] ?? null;
      index += 1;
      continue;
    }
    if (arg === "--proof-runs") {
      const next = Number(args[index + 1]);
      if (!Number.isInteger(next) || next <= 0) {
        usage("--proof-runs must be a positive integer");
      }
      proofRuns = next;
      index += 1;
      continue;
    }
    if (arg === "--case") {
      const next = args[index + 1];
      if (!CASES.includes(next)) {
        usage("--case must be one of transfer, withdraw");
      }
      cases = [next];
      index += 1;
      continue;
    }
    if (arg === "--verify") {
      verify = true;
      continue;
    }
    if (arg === "--out-dir") {
      const next = args[index + 1];
      if (!next) {
        usage("missing value for --out-dir");
      }
      outDirRoot = resolve(process.cwd(), next);
      index += 1;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      usage();
    }
    usage(`unknown argument: ${arg}`);
  }

  if (!variant) {
    usage("--variant is required");
  }

  return { variant, outDirRoot, proofRuns, verify, cases };
}

function usage(message) {
  if (message) {
    console.error(message);
  }
  console.error(
    [
      "usage: node scripts/benchmark-variant.mjs --variant <name> [--proof-runs N] [--case transfer|withdraw] [--verify] [--out-dir path]",
      "",
      "Writes results under tmp/benchmark-results/<variant>/<timestamp>/ by default.",
    ].join("\n"),
  );
  process.exit(message ? 1 : 0);
}

function runProofBenchmarks(options, outDir, summary) {
  const rawRuns = [];
  const caseSummaries = {};
  const proofTimesPath = resolve(outDir, "proof-times.json");
  writeJson(proofTimesPath, { rawRuns, caseSummaries });

  for (const caseName of options.cases) {
    const runs = [];
    for (let attempt = 0; attempt < options.proofRuns; attempt += 1) {
      try {
        const step = runStep(summary, outDir, {
          title: `proof-benchmark:${caseName}:run-${attempt + 1}`,
          command: process.execPath,
          args: [benchmarkProofsScript, "--json", "--case", caseName],
          cwd: repoRoot,
          stem: `proof-${caseName}-run-${attempt + 1}`,
        });
        const result = parseProofBenchmarkOutput(step.stdout, caseName);
        runs.push(result);
        rawRuns.push({ case: caseName, run: attempt + 1, result });
        writeJson(proofTimesPath, {
          rawRuns,
          caseSummaries: {
            ...caseSummaries,
            ...(runs.length === options.proofRuns
              ? {
                  [caseName]: {
                    innerMs: summarizeNumbers(runs.map((entry) => entry.innerMs)),
                    outerMs: summarizeNumbers(runs.map((entry) => entry.outerMs)),
                    totalMs: summarizeNumbers(runs.map((entry) => entry.totalMs)),
                    runs,
                  },
                }
              : {}),
          },
        });
      } catch (error) {
        writeJson(proofTimesPath, { rawRuns, caseSummaries });
        throw error;
      }
    }

    caseSummaries[caseName] = {
      innerMs: summarizeNumbers(runs.map((entry) => entry.innerMs)),
      outerMs: summarizeNumbers(runs.map((entry) => entry.outerMs)),
      totalMs: summarizeNumbers(runs.map((entry) => entry.totalMs)),
      runs,
    };
    summary.proofBenchmarkSummary = caseSummaries;
    writeJson(proofTimesPath, { rawRuns, caseSummaries });
    writeSummary(outDir, summary);
  }

  return { rawRuns, summary: caseSummaries };
}

function runGasBenchmarks(outDir, summary) {
  const suites = [
    {
      name: "real-verifier",
      args: [
        contractTestsScript,
        "--ffi-timing",
        "--gas-report",
        "--match-contract",
        "VerifierPrecompileIntegrationTest",
        "-vv",
      ],
    },
  ];

  const gasReportPath = resolve(outDir, "gas-report.txt");
  const ffiTimingPath = resolve(outDir, "ffi-timing.txt");
  const gasReportSections = [];
  const ffiTimingSections = [];
  const suiteSummaries = [];
  writeText(gasReportPath, "");
  writeText(ffiTimingPath, "");

  for (const suite of suites) {
    let step;
    try {
      step = runStep(summary, outDir, {
        title: `gas-benchmark:${suite.name}`,
        command: process.execPath,
        args: suite.args,
        cwd: repoRoot,
        stem: `gas-${suite.name}`,
      });
    } catch (error) {
      const failedStep =
        error && typeof error === "object" && "step" in error ? error.step : null;
      if (failedStep) {
        gasReportSections.push(sectionBlock(suite.name, failedStep.combined));
        ffiTimingSections.push(
          sectionBlock(suite.name, extractFfiTimingLines(failedStep.combined).join("\n")),
        );
        writeText(gasReportPath, `${gasReportSections.join("\n\n")}\n`);
        writeText(ffiTimingPath, `${ffiTimingSections.join("\n\n")}\n`);
      }
      throw error;
    }

    const ffiTimingLines = extractFfiTimingLines(step.combined);
    suiteSummaries.push({
      name: suite.name,
      durationMs: step.durationMs,
      ffiTimingSummary: ffiTimingLines,
    });

    gasReportSections.push(sectionBlock(suite.name, step.combined));
    ffiTimingSections.push(sectionBlock(suite.name, ffiTimingLines.join("\n")));

    writeText(gasReportPath, `${gasReportSections.join("\n\n")}\n`);
    writeText(ffiTimingPath, `${ffiTimingSections.join("\n\n")}\n`);
    summary.gasBenchmarkSummary = suiteSummaries;
    writeSummary(outDir, summary);
  }

  return { summary: suiteSummaries };
}

function runCompatibilityChecks(outDir, summary) {
  const checks = [
    { name: "test:unit", command: "npm", args: ["run", "test:unit"] },
    {
      name: "test:execution-spec-assets",
      command: "npm",
      args: ["run", "test:execution-spec-assets"],
    },
    { name: "test:real-verifier", command: "npm", args: ["run", "test:real-verifier"] },
    { name: "test:circuits", command: "npm", args: ["run", "test:circuits"] },
  ];

  const rows = [];
  const testSummaryPath = resolve(outDir, "test-summary.json");
  writeJson(testSummaryPath, rows);

  for (const check of checks) {
    try {
      const step = runStep(summary, outDir, {
        title: check.name,
        command: check.command,
        args: check.args,
        cwd: repoRoot,
        stem: check.name.replace(/[:]/g, "-"),
      });
      rows.push({
        name: check.name,
        command: stringifyCommand(check.command, check.args),
        durationMs: step.durationMs,
        status: "completed",
      });
      writeJson(testSummaryPath, rows);
      summary.compatibilitySummary = rows;
      writeSummary(outDir, summary);
    } catch (error) {
      const failedStep =
        error && typeof error === "object" && "step" in error ? error.step : null;
      rows.push({
        name: check.name,
        command: stringifyCommand(check.command, check.args),
        durationMs: failedStep?.durationMs ?? 0,
        status: "failed",
        exitCode: failedStep?.exitCode ?? null,
        signal: failedStep?.signal ?? null,
      });
      writeJson(testSummaryPath, rows);
      summary.compatibilitySummary = rows;
      writeSummary(outDir, summary);
      throw error;
    }
  }

  return { summary: rows };
}

function collectArtifactSizes() {
  const result = {
    files: {},
    metadata: {},
  };
  const missing = [];

  for (const relativePath of ARTIFACT_SIZE_FILES) {
    const absolutePath = resolve(repoRoot, relativePath);
    if (existsSync(absolutePath)) {
      result.files[relativePath] = { bytes: statSync(absolutePath).size };
    } else {
      result.files[relativePath] = { missing: true };
      missing.push(relativePath);
    }
  }

  if (missing.length > 0) {
    throw new Error(
      [
        "artifact collection failed: missing required benchmark artifacts:",
        ...missing.map((relativePath) => ` - ${relativePath}`),
      ].join("\n"),
    );
  }

  const verifierMetadataPath = resolve(repoRoot, "assets/eip-8182/outer_verifier_metadata.json");
  if (existsSync(verifierMetadataPath)) {
    const metadata = JSON.parse(readFileSync(verifierMetadataPath, "utf8"));
    result.metadata.outerVerifier = {
      proofByteLength: firstDefined(metadata.proofByteLength, metadata.proofLengthBytes, null),
      proofFieldElementCount: firstDefined(metadata.proofFieldElementCount, null),
      verifierPublicInputCount: firstDefined(
        metadata.verifierPublicInputCount,
        metadata.verifierPublicInputsCount,
        null,
      ),
      poolPublicInputCount: firstDefined(
        metadata.poolPublicInputCount,
        metadata.poolPublicInputsCount,
        null,
      ),
      logN: firstDefined(metadata.logN, metadata.logCircuitSize, null),
    };
  }

  return result;
}

function validateBenchmarkPreflight() {
  const missing = REQUIRED_STATIC_REPO_PATHS.filter((absolutePath) => !existsSync(absolutePath));
  if (missing.length === 0) {
    return;
  }

  throw new Error(
    [
      "benchmark preflight failed: missing required repo inputs:",
      ...missing.map((absolutePath) => {
        const relativePath = absolutePath.startsWith(`${repoRoot}/`)
          ? absolutePath.slice(repoRoot.length + 1)
          : absolutePath;
        return ` - ${relativePath}`;
      }),
      "",
      "Update the benchmark script or restore the referenced files before running benchmarks.",
    ].join("\n"),
  );
}

function initializeOutputBundle(outDir, verify) {
  writeJson(resolve(outDir, "proof-times.json"), { rawRuns: [], caseSummaries: {} });
  writeText(resolve(outDir, "gas-report.txt"), "");
  writeText(resolve(outDir, "ffi-timing.txt"), "");
  writeJson(resolve(outDir, "artifact-sizes.json"), { files: {}, metadata: {} });
  if (verify) {
    writeJson(resolve(outDir, "test-summary.json"), []);
  }
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined) {
      return value;
    }
  }
  return undefined;
}

function collectGitMetadata() {
  try {
    const commit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
    }).trim();
    const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
    }).trim();
    const status = execFileSync("git", ["status", "--porcelain"], {
      cwd: repoRoot,
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean);
    return {
      commit,
      branch,
      dirty: status.length > 0,
      status,
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function runStep(summary, outDir, spec) {
  try {
    const result = runLoggedCommand(spec);
    const logPaths = writeStepArtifacts(outDir, result, spec.stem ?? spec.title);
    summary.steps.push(stepSummary(result, "completed", logPaths));
    writeSummary(outDir, summary);
    return result;
  } catch (error) {
    const failedStep =
      error && typeof error === "object" && "step" in error ? error.step : buildFailedStep(spec, error);
    const logPaths = writeStepArtifacts(outDir, failedStep, spec.stem ?? spec.title);
    summary.steps.push(stepSummary(failedStep, "failed", logPaths));
    summary.failure = {
      ...normalizeFailure(error),
      step: spec.title,
      command: stringifyCommand(spec.command, spec.args),
      durationMs: failedStep.durationMs,
      exitCode: failedStep.exitCode,
      signal: failedStep.signal,
    };
    writeSummary(outDir, summary);
    throw error;
  }
}

function runLoggedCommand({ title, command, args, cwd }) {
  console.error(`[benchmark] ${title}`);
  const startedAt = Date.now();
  const result = spawnSync(command, args, {
    cwd,
    env: process.env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: MAX_CAPTURE_BYTES,
  });
  const durationMs = Date.now() - startedAt;
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const combined = [stdout, stderr].filter(Boolean).join(stdout && stderr ? "\n" : "");
  const step = {
    title,
    command,
    args,
    cwd,
    durationMs,
    stdout,
    stderr,
    combined,
    exitCode: typeof result.status === "number" ? result.status : null,
    signal: result.signal ?? null,
  };

  if (result.error || result.status !== 0) {
    const detail = result.error
      ? result.error.message
      : result.signal
        ? `terminated by signal ${result.signal}`
        : `failed with exit code ${result.status}`;
    const error = new Error(`${title} ${detail}`);
    error.step = step;
    throw error;
  }

  return step;
}

function buildFailedStep(spec, error) {
  return {
    title: spec.title,
    command: spec.command,
    args: spec.args,
    cwd: spec.cwd,
    durationMs: 0,
    stdout: "",
    stderr: error instanceof Error ? `${error.message}\n` : `${String(error)}\n`,
    combined: error instanceof Error ? error.message : String(error),
    exitCode: null,
    signal: null,
  };
}

function writeStepArtifacts(outDir, step, stem) {
  const safeStem = stem.replace(/[^a-zA-Z0-9._-]+/g, "-");
  const stdoutPath = resolve(outDir, `${safeStem}.stdout.txt`);
  const stderrPath = resolve(outDir, `${safeStem}.stderr.txt`);
  writeText(stdoutPath, step.stdout ?? "");
  writeText(stderrPath, step.stderr ?? "");
  return { stdoutPath, stderrPath };
}

function stepSummary(step, status, logPaths) {
  return {
    title: step.title,
    status,
    command: stringifyCommand(step.command, step.args),
    cwd: step.cwd,
    durationMs: step.durationMs,
    exitCode: step.exitCode,
    signal: step.signal,
    stdoutLog: logPaths.stdoutPath,
    stderrLog: logPaths.stderrPath,
  };
}

function stringifyCommand(command, args) {
  return [command, ...args].join(" ");
}

function parseProofBenchmarkOutput(stdout, expectedCase) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    throw new Error(
      `proof benchmark output for ${expectedCase} was not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  if (!Array.isArray(parsed) || parsed.length !== 1) {
    throw new Error(`unexpected proof benchmark output for case ${expectedCase}`);
  }

  const [result] = parsed;
  if (result.case !== expectedCase) {
    throw new Error(`proof benchmark output case mismatch: expected ${expectedCase}, got ${result.case}`);
  }

  for (const metric of ["innerMs", "outerMs", "totalMs"]) {
    if (typeof result[metric] !== "number" || !Number.isFinite(result[metric])) {
      throw new Error(`proof benchmark output missing numeric ${metric} for case ${expectedCase}`);
    }
  }

  return result;
}

function summarizeNumbers(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((accumulator, value) => accumulator + value, 0);
  return {
    runCount: values.length,
    min: sorted[0],
    median: percentile(sorted, 0.5),
    p95: percentile(sorted, 0.95),
    max: sorted[sorted.length - 1],
    mean: sum / sorted.length,
  };
}

function percentile(sorted, percentileValue) {
  if (sorted.length === 1) {
    return sorted[0];
  }
  const index = (sorted.length - 1) * percentileValue;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) {
    return sorted[lower];
  }
  const weight = index - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

function extractFfiTimingLines(text) {
  return text
    .split("\n")
    .map((line) => line.trimEnd())
    .filter((line) => line.includes("[ffi-timing]"));
}

function sectionBlock(title, body) {
  const normalizedBody = body && body.trim().length > 0 ? body.trimEnd() : "(no output)";
  return [`=== ${title} ===`, normalizedBody].join("\n");
}

function normalizeFailure(error) {
  return {
    message: error instanceof Error ? error.message : String(error),
  };
}

function writeSummary(outDir, summary) {
  writeJson(resolve(outDir, "summary.json"), summary);
}

function writeJson(path, value) {
  writeText(path, `${JSON.stringify(value, null, 2)}\n`);
}

function writeText(path, value) {
  writeFileSync(path, value);
}

function printHumanSummary(summary, outDir) {
  console.error("\n[benchmark] complete");
  console.error(`[benchmark] variant=${summary.variant}`);
  console.error(`[benchmark] out=${outDir}`);

  if (summary.proofBenchmarkSummary) {
    for (const [caseName, caseSummary] of Object.entries(summary.proofBenchmarkSummary)) {
      console.error(
        `[benchmark] proofs ${caseName}: total median=${caseSummary.totalMs.median.toFixed(
          2,
        )}ms p95=${caseSummary.totalMs.p95.toFixed(2)}ms`,
      );
    }
  }

  if (summary.gasBenchmarkSummary) {
    for (const suite of summary.gasBenchmarkSummary) {
      console.error(`[benchmark] gas ${suite.name}: duration=${suite.durationMs}ms`);
    }
  }
}
