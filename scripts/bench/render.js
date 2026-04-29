#!/usr/bin/env node
// Render the EIP-8182 benchmark report.
//
// Inputs:
//   - build/bench/raw/<name>.json — per-bench gas measurements written by
//     contracts/test/Bench.t.sol's `vm.writeFile`.
//   - build/integration_honk/<mode>_session.json — pool/auth prove timings.
//
// Outputs:
//   - human-readable report on stdout
//   - build/bench/report.json (machine-readable)
//
// The transact breakdown is grouped into four categories so a reader can see
// what's intrinsic to EIP-8182 vs. what's an implementation choice that can be
// substituted, vs. what's a stand-in number that won't reflect reality on a
// real chain:
//
//   * EIP-8182 intrinsic — tree insertion, nullifier writes, replay-id write,
//     output-hash checks, history push, event emission, dispatch, range checks.
//     Reported as a residual: total - (everything below).
//   * Implementation choice — auth verifier (we bench Honk; Groth16 is ~10x
//     cheaper, ECDSA-only would be cheaper still) and asset movement.
//   * Mocked / artificial — pool proof verify. The real EIP-8182 precompile
//     would charge a fixed gas amount; here we approximate with a Solidity
//     Groth16 verifier etched at 0x...30. Treat as an upper bound.
//   * Calldata — the EVM's per-byte cost of carrying the proof bytes on the
//     wire. Pulled out separately so readers can see how much each proof
//     costs just to ship.

const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");

function readJsonOrNull(p) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}
function readBench(name) {
  return readJsonOrNull(path.join(ROOT, "build/bench/raw", `${name}.json`));
}
function readSession(mode) {
  const name = mode === "transfer" ? "session.json" : `${mode}_session.json`;
  return readJsonOrNull(path.join(ROOT, "build/integration_honk", name));
}

function fmtMs(n) {
  if (n == null) return "—";
  return (n / 1000).toFixed(2) + " s";
}
function fmtGas(n) {
  if (n == null) return "—";
  return n.toLocaleString("en-US");
}
function fmtPct(num, denom) {
  if (!denom) return "0.0 %";
  return ((num / denom) * 100).toFixed(1) + " %";
}
function pad(s, w, right = false) {
  s = String(s);
  if (s.length >= w) return s;
  const fill = " ".repeat(w - s.length);
  return right ? fill + s : s + fill;
}

const sessions = {
  transfer:       readSession("transfer"),
  withdraw_eth:   readSession("withdraw_eth"),
  withdraw_erc20: readSession("withdraw_erc20"),
};
const benches = {
  register_user:        readBench("register_user"),
  register_auth_policy: readBench("register_auth_policy"),
  deposit_eth:          readBench("deposit_eth"),
  deposit_erc20:        readBench("deposit_erc20"),
  transfer:             readBench("transfer"),
  withdraw_eth:         readBench("withdraw_eth"),
  withdraw_erc20:       readBench("withdraw_erc20"),
};

const TX_BASE_INTRINSIC = 21000;
// Per EIP-8182 §5.5: proof-verify precompile gas. Derivation: a Solidity
// Groth16 verifier with 21 public inputs costs ~335K gas (final pairing ~181K
// + IC sum ~129K + dispatch ~25K). A native precompile can fold the IC sum
// more tightly than EVM dispatch allows, so we model a ~10% discount: 300K.
const POOL_VERIFY_SPEC_GAS = 300_000;

// Total a real user pays = base intrinsic + tx calldata gas + EVM execution,
// adjusted to use the spec precompile gas instead of the mocked Solidity
// verifier we measure on-chain.
function fullTotal(b) {
  if (!b || b.skipped) return null;
  if (b.exec_gas == null) return null;
  if (b.tx_calldata_gas_groth16 != null) {
    const execModeled =
        b.exec_gas
      - b.auth_verify_honk
      + b.auth_verify_groth16
      - b.pool_verify_mocked
      + POOL_VERIFY_SPEC_GAS;
    return TX_BASE_INTRINSIC + b.tx_calldata_gas_groth16 + execModeled;
  }
  return TX_BASE_INTRINSIC + (b.tx_calldata_gas || 0) + b.exec_gas;
}

function summaryRow(label, sessionKey, benchKey) {
  const s = sessions[sessionKey];
  const b = benches[benchKey];
  if (b && b.skipped) {
    return [label, "skipped", "", "", ""];
  }
  const tp = s?.timings?.pool_prove_ms;
  const ta = s?.timings?.auth_prove_ms;
  const e2e = (tp != null && ta != null) ? tp + ta : null;
  return [label, fmtMs(tp), fmtMs(ta), fmtMs(e2e), fmtGas(fullTotal(b))];
}
function nonProveRow(label, benchKey) {
  const b = benches[benchKey];
  if (b && b.skipped) {
    return [label, "skipped", "", "", ""];
  }
  return [label, "—", "—", "—", fmtGas(fullTotal(b))];
}

const header = ["operation", "pool prove", "auth prove", "wallet e2e", "on-chain gas"];
const rows = [
  nonProveRow("register user",       "register_user"),
  nonProveRow("register auth policy","register_auth_policy"),
  nonProveRow("deposit (ETH)",       "deposit_eth"),
  nonProveRow("deposit (ERC-20)",    "deposit_erc20"),
  summaryRow ("transfer",            "transfer",       "transfer"),
  summaryRow ("withdraw (ETH)",      "withdraw_eth",   "withdraw_eth"),
  summaryRow ("withdraw (ERC-20)",   "withdraw_erc20", "withdraw_erc20"),
];

const widths = header.map((_, i) => Math.max(header[i].length,
  ...rows.map(r => String(r[i]).length)));

console.log();
console.log("EIP-8182 benchmarks");
console.log(`Pool circuit:  Groth16/BN254 (snarkjs WASM)`);
console.log(`Auth circuit:  UltraHonk/BN254 (Noir + bb)`);
console.log(`CPU:           ${os.cpus()[0]?.model}, ${os.cpus().length} cores, ${(os.totalmem() / 1e9).toFixed(0)} GB`);
console.log(`Generated:     ${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC`);
console.log();

console.log("Per-operation summary");
console.log("─────────────────────");
function printRow(r) {
  console.log(
    pad(r[0], widths[0]) + "  " +
    pad(r[1], widths[1], true) + "  " +
    pad(r[2], widths[2], true) + "  " +
    pad(r[3], widths[3], true) + "  " +
    pad(r[4], widths[4], true)
  );
}
printRow(header);
for (const r of rows) printRow(r);

// -------- Bucket breakdowns --------

function transactBuckets(b) {
  if (!b || b.skipped) return null;
  const execGas        = b.exec_gas                  || 0;
  const txCdGroth16    = b.tx_calldata_gas_groth16   || 0;
  const txCdHonk       = b.tx_calldata_gas_honk      || 0;
  const poolVerifyMock = b.pool_verify_mocked        || 0;
  const authHonk       = b.auth_verify_honk          || 0;
  const authGroth16    = b.auth_verify_groth16       || 0;
  const asset          = b.asset_movement            || 0;
  const poolCd         = b.pool_calldata_gas         || 0;
  const authCdGroth16  = b.auth_calldata_gas_groth16 || 0;
  const authCdHonk     = b.auth_calldata_gas_honk    || 0;
  const restCdGroth16  = txCdGroth16 - poolCd - authCdGroth16;

  // exec_gas was measured with the Honk auth verifier and the Solidity Groth16
  // pool-verify stand-in. Adjust to the modeled flow:
  //   - swap Honk auth verify for Groth16 auth verify
  //   - swap mocked Solidity pool verify for the spec precompile gas (§5.5)
  const execModeled =
      execGas
    - authHonk    + authGroth16
    - poolVerifyMock + POOL_VERIFY_SPEC_GAS;
  // EIP-8182 intrinsic = exec gas minus directly-attributable buckets.
  const intrinsic = execModeled - (POOL_VERIFY_SPEC_GAS + authGroth16 + asset);

  // Mandatory: everything except the auth verify + auth calldata.
  const mandatory =
      TX_BASE_INTRINSIC
    + poolCd
    + restCdGroth16
    + POOL_VERIFY_SPEC_GAS
    + asset
    + intrinsic;
  const discretionary = authGroth16 + authCdGroth16;
  const total = mandatory + discretionary;

  // Reference: if you'd shipped Honk instead of Groth16. Same precompile gas.
  const honkExecModeled = execGas - poolVerifyMock + POOL_VERIFY_SPEC_GAS;
  const totalHonk = TX_BASE_INTRINSIC + txCdHonk + honkExecModeled;

  return {
    sections: [
      { title: "Mandatory (paid by every user, independent of auth choice)", rows: [
        ["Tx base intrinsic (Berlin)",                                   TX_BASE_INTRINSIC],
        ["Calldata: pool proof (256 B)",                                 poolCd],
        ["Calldata: rest (public inputs, ond bytes, selector, offsets)", restCdGroth16],
        ["Pool proof verify (precompile, EIP-8182 §5.5)",                POOL_VERIFY_SPEC_GAS],
        ...(asset > 0 ? [["Asset movement (ETH/ERC-20 transfer)", asset]] : []),
        ["EIP-8182 intrinsic (tree, hashing, writes, dispatch)",         intrinsic],
      ], subtotal: ["Mandatory subtotal", mandatory] },
      { title: "Discretionary (your auth circuit choice; here: Groth16, 2 PI)", rows: [
        ["Auth proof verify (Solidity Groth16, 2 public inputs)",        authGroth16],
        ["Calldata: auth proof (256 B Groth16)",                         authCdGroth16],
      ], subtotal: ["Discretionary subtotal", discretionary] },
    ],
    total,
    totalHonk,
    honkAuthVerify: authHonk,
    honkAuthCalldata: authCdHonk,
    honkProofBytes: b.auth_proof_bytes_honk || 0,
  };
}

function depositBuckets(b) {
  if (!b || b.skipped) return null;
  const execGas     = b.exec_gas        || 0;
  const txCalldata  = b.tx_calldata_gas || 0;
  const asset       = b.asset           || 0;
  const intrinsic   = execGas - asset;
  const total       = TX_BASE_INTRINSIC + txCalldata + execGas;
  return {
    sections: [
      { title: "Mandatory (everything; deposit has no auth choice)", rows: [
        ["Tx base intrinsic (Berlin)",                                21000],
        ["Calldata (selector + args)",                                txCalldata],
        ...(asset > 0 ? [["ERC-20 asset path (4× balanceOf + 1× transferFrom)", asset]] : []),
        ["EIP-8182 intrinsic (body+final hash, tree insert, history, event)", intrinsic],
      ]},
    ],
    total,
  };
}

function registerBuckets(b) {
  if (!b || b.skipped) return null;
  const execGas    = b.exec_gas        || 0;
  const txCalldata = b.tx_calldata_gas || 0;
  const total      = TX_BASE_INTRINSIC + txCalldata + execGas;
  return {
    sections: [
      { title: "Mandatory (everything; register has no auth choice)", rows: [
        ["Tx base intrinsic (Berlin)",                21000],
        ["Calldata (selector + args)",                txCalldata],
        ["EIP-8182 intrinsic (tree insert + writes)", execGas],
      ]},
    ],
    total,
  };
}

function printBuckets(label, breakdown) {
  if (!breakdown) return;
  const { sections, total, totalHonk, honkAuthVerify, honkAuthCalldata, honkProofBytes } = breakdown;
  console.log();
  console.log(label);
  console.log("─".repeat(72));
  const labelWidth = 62;
  for (const sec of sections) {
    console.log("  " + sec.title);
    for (const [name, gas] of sec.rows) {
      console.log(
        pad("    " + name, labelWidth) + "  " +
        pad(fmtGas(gas), 10, true) + "  " +
        pad(fmtPct(gas, total), 7, true)
      );
    }
    if (sec.subtotal) {
      const [stName, stGas] = sec.subtotal;
      console.log(
        pad("    " + stName, labelWidth) + "  " +
        pad(fmtGas(stGas), 10, true) + "  " +
        pad(fmtPct(stGas, total), 7, true)
      );
    }
  }
  console.log(
    pad("    Total", labelWidth) + "  " +
    pad(fmtGas(total), 10, true) + "  " +
    pad("100.0 %", 7, true)
  );
  if (totalHonk != null) {
    console.log();
    console.log(
      "    For comparison — if discretionary uses UltraHonk auth (the Noir+ECDSA"
    );
    console.log(
      "    circuit benched here for prove time):"
    );
    console.log(
      pad(`      Auth verify (Honk): ${fmtGas(honkAuthVerify)}; ` +
          `proof: ${honkProofBytes.toLocaleString("en-US")} B (calldata ${fmtGas(honkAuthCalldata)})`,
        labelWidth)
    );
    console.log(
      pad("      Total with Honk auth", labelWidth) + "  " +
      pad(fmtGas(totalHonk), 10, true)
    );
  }
}

console.log();
console.log("Gas breakdown by operation");
console.log("══════════════════════════");
printBuckets("register user",        registerBuckets(benches.register_user));
printBuckets("register auth policy", registerBuckets(benches.register_auth_policy));
printBuckets("deposit (ETH)",        depositBuckets(benches.deposit_eth));
printBuckets("deposit (ERC-20)",     depositBuckets(benches.deposit_erc20));
printBuckets("transfer",             transactBuckets(benches.transfer));
printBuckets("withdraw (ETH)",       transactBuckets(benches.withdraw_eth));
printBuckets("withdraw (ERC-20)",    transactBuckets(benches.withdraw_erc20));

console.log();
console.log("Notes");
console.log("─────");
console.log("- 'Total' is the full all-in gas a real user pays: tx base intrinsic");
console.log("  (21,000) + calldata gas (EIP-2028: 16/non-zero, 4/zero) + EVM");
console.log("  execution gas (gasleft delta around the pool call).");
console.log("- Pool proof verify is charged at the EIP-8182 §5.5 precompile gas");
console.log(`  (${POOL_VERIFY_SPEC_GAS.toLocaleString("en-US")}). The Solidity Groth16 verifier we etch as a stand-in`);
console.log("  measures ~335K; the spec number is set with a small discount to");
console.log("  reflect that native code can fold IC-sum work more tightly than EVM.");
console.log("- For transact rows the headline models a Groth16 auth verifier (same");
console.log("  proof system as the pool, 2 PI) — what a gas-conscious implementer");
console.log("  would deploy. Per-op 'For comparison' line shows the cost with the");
console.log("  Noir+UltraHonk circuit (~10× more verify gas, ~38× more calldata)");
console.log("  — that's what the prove timings here actually measure.");
console.log("- Pool prove time is snarkjs WASM; rapidsnark is ~10x faster.");
console.log("- Single-shot timings; expect ±10-20% variance.");
const skipped = ["transfer", "withdraw_eth", "withdraw_erc20"]
  .filter(k => benches[k] && benches[k].skipped);
if (skipped.length) {
  console.log(`- Skipped: ${skipped.map(k => `${k} (${benches[k].reason})`).join(", ")}.`);
}

const report = {
  generated_at: new Date().toISOString(),
  cpu: os.cpus()[0]?.model,
  cores: os.cpus().length,
  ram_gb: +(os.totalmem() / 1e9).toFixed(1),
  rows: { header, data: rows },
  benches,
  timings: {
    transfer:       sessions.transfer?.timings || null,
    withdraw_eth:   sessions.withdraw_eth?.timings || null,
    withdraw_erc20: sessions.withdraw_erc20?.timings || null,
  },
};
const reportPath = path.join(ROOT, "build/bench/report.json");
fs.mkdirSync(path.dirname(reportPath), { recursive: true });
fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
console.log();
console.log("wrote", path.relative(ROOT, reportPath));
