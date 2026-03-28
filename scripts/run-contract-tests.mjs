import { execFileSync, execSync } from 'node:child_process'
import { mkdirSync, readFileSync, unlinkSync, existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import os from 'node:os'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const repoRoot = resolve(__dirname, '..')
const rawArgs = process.argv.slice(2)
const debugFlagIndex = rawArgs.indexOf('--ffi-debug')
const timingFlagIndex = rawArgs.indexOf('--ffi-timing')
const ffiDebugEnabled =
  debugFlagIndex !== -1 ||
  (process.env.EIP8182_FFI_DEBUG &&
    process.env.EIP8182_FFI_DEBUG !== '0' &&
    process.env.EIP8182_FFI_DEBUG.toLowerCase() !== 'false')
const ffiTimingEnabled =
  timingFlagIndex !== -1 ||
  ffiDebugEnabled ||
  (process.env.EIP8182_FFI_TIMING &&
    process.env.EIP8182_FFI_TIMING !== '0' &&
    process.env.EIP8182_FFI_TIMING.toLowerCase() !== 'false')
if (debugFlagIndex !== -1) rawArgs.splice(debugFlagIndex, 1)
if (timingFlagIndex !== -1) rawArgs.splice(timingFlagIndex, 1)
const env = { ...process.env }
const verifierFixturePath = resolve(
  repoRoot,
  'contracts',
  'test',
  '.tmp-real-verifier-fixture.json',
)

function shouldGenerateVerifierFixture(argv) {
  if (env.REAL_VERIFIER_FIXTURE_PATH) return false
  if (argv.length === 0) return true

  const restrictiveFlags = new Set([
    '--match-path',
    '--match-contract',
    '--match-test',
    '--match-test-revert',
    '--no-match-path',
    '--no-match-contract',
    '--no-match-test',
  ])
  let hasRestrictiveMatcher = false
  let matchesVerifierSuite = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (!restrictiveFlags.has(arg)) continue
    hasRestrictiveMatcher = true
    const value = argv[i + 1] || ''
    if (
      value.includes('VerifierPrecompileIntegration') ||
      value.includes('test/VerifierPrecompileIntegration.t.sol')
    ) {
      matchesVerifierSuite = true
    }
    i += 1
  }

  if (matchesVerifierSuite) return true
  return !hasRestrictiveMatcher
}

if (ffiDebugEnabled) {
  if (!env.EIP8182_FFI_LOG_DIR) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    env.EIP8182_FFI_LOG_DIR = resolve(os.tmpdir(), 'eip8182-ffi-logs', `${stamp}-${process.pid}`)
  }
  if (!env.EIP8182_FFI_LOG_STDERR) env.EIP8182_FFI_LOG_STDERR = '1'
  env.EIP8182_FFI_DEBUG = '1'
  mkdirSync(env.EIP8182_FFI_LOG_DIR, { recursive: true })
  console.error(`[contracts:test] FFI debug logs: ${env.EIP8182_FFI_LOG_DIR}`)
}

if (ffiTimingEnabled) {
  env.EIP8182_FFI_TIMING = '1'
  env.EIP8182_FFI_TIMING_FILE = resolve(
    os.tmpdir(),
    'eip8182-ffi-timing',
    `${Date.now()}-${process.pid}.jsonl`,
  )
  mkdirSync(dirname(env.EIP8182_FFI_TIMING_FILE), { recursive: true })
}

if (shouldGenerateVerifierFixture(rawArgs)) {
  mkdirSync(dirname(verifierFixturePath), { recursive: true })
  execSync(
    `/bin/bash -lc 'cd "${repoRoot}" && npx tsx integration/src/generate_verifier_test_fixture.ts "${verifierFixturePath}"'`,
    {
      stdio: 'inherit',
      cwd: repoRoot,
      env,
    },
  )
  env.REAL_VERIFIER_FIXTURE_PATH = verifierFixturePath
}

try {
  execFileSync('forge', ['test', ...rawArgs], {
    stdio: 'inherit',
    cwd: resolve(repoRoot, 'contracts'),
    env,
  })
} finally {
  if (ffiTimingEnabled) {
    printFfiTimingSummary(env.EIP8182_FFI_TIMING_FILE)
  }
}

function printFfiTimingSummary(timingFilePath) {
  if (!timingFilePath || !existsSync(timingFilePath)) return

  const entries = readFileSync(timingFilePath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line))

  if (entries.length === 0) return

  console.error('\n[ffi-timing] summary')
  let totalMs = 0
  for (const entry of entries) {
    totalMs += entry.durationMs
    const mode = entry.mode ? ` mode=${entry.mode}` : ''
    const outcome = entry.timedOut
      ? 'timeout'
      : entry.exitCode === 0
        ? 'ok'
        : `exit=${entry.exitCode}`
    console.error(
      `[ffi-timing] ${entry.durationMs}ms ${outcome} script=${entry.scriptPath}${mode}`,
    )
  }
  console.error(`[ffi-timing] total=${totalMs}ms calls=${entries.length}`)

  try {
    unlinkSync(timingFilePath)
  } catch {}
}
