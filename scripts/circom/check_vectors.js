// Cross-check the Circom Poseidon2 sponge against asset vectors.
// For each test vector: write a tiny test circuit Poseidon2SpongeTest_N,
// compile it, generate witness from the vector inputs, read back the
// computed output from the witness, compare against the expected output.
//
// Run: node scripts/check_vectors.js [arity1 arity2 ...]
// Default arities: 0 1 2 3 4 5 6 17 116

const fs = require('fs');
const path = require('path');
const { execSync, execFileSync } = require('child_process');

const ROOT     = path.resolve(__dirname, '..');
const CIRCOM   = path.resolve(ROOT, '.cargo/bin/circom');
const ASSET    = path.resolve(ROOT, '../../assets/eip-8182/poseidon2_vectors.json');
const BUILD    = path.resolve(ROOT, 'build/check_vectors');

const vectors = JSON.parse(fs.readFileSync(ASSET, 'utf8')).poseidonVectors;

function runOne(arity) {
  const v = vectors.find(x => x.inputs.length === arity);
  if (!v) {
    console.log(`[skip] no vector for arity ${arity}`);
    return { arity, ok: null };
  }
  const dir = path.join(BUILD, `arity_${arity}`);
  fs.mkdirSync(dir, { recursive: true });

  // Synthesize a tiny test circuit for this arity.
  const circuitSrc = `
pragma circom 2.0.0;
include "poseidon2_sponge.circom";

template Test() {
    signal input  in[${arity}];
    signal output out;
    component s = Poseidon2Sponge(${arity});
    for (var i = 0; i < ${arity}; i++) s.in[i] <== in[i];
    out <== s.out;
}

component main = Test();
`;
  fs.writeFileSync(path.join(dir, 'test.circom'), circuitSrc);

  // Compile.
  execFileSync(CIRCOM, [
    path.join(dir, 'test.circom'),
    '--r1cs', '--wasm', '--sym',
    '-l', path.resolve(ROOT, 'circuits'),
    '-o', dir,
  ], { stdio: 'pipe' });

  // Inputs JSON: convert hex inputs to decimal strings.
  const inputs = { in: v.inputs.map(h => BigInt(h).toString()) };
  if (arity === 0) {
    // Circom Test() will refuse zero-length input array via the JSON path;
    // we still need an empty `in` field. snarkjs witness gen accepts {}.
    fs.writeFileSync(path.join(dir, 'input.json'), '{}');
  } else {
    fs.writeFileSync(path.join(dir, 'input.json'), JSON.stringify(inputs));
  }

  // Witness gen.
  execFileSync('node', [
    path.join(dir, 'test_js/generate_witness.js'),
    path.join(dir, 'test_js/test.wasm'),
    path.join(dir, 'input.json'),
    path.join(dir, 'witness.wtns'),
  ], { stdio: 'pipe' });

  // snarkjs wtns export json -> read output (signal index 1, since 0 is ONE).
  const wtnsJson = path.join(dir, 'witness.json');
  execFileSync('node', [
    path.join(ROOT, 'node_modules/snarkjs/build/cli.cjs'),
    'wtns', 'export', 'json',
    path.join(dir, 'witness.wtns'),
    wtnsJson,
  ], { stdio: 'pipe' });
  const wtns = JSON.parse(fs.readFileSync(wtnsJson, 'utf8'));
  const computed = BigInt(wtns[1]);
  const expected = BigInt(v.output);
  const ok = computed === expected;

  console.log(
    `[arity=${arity}] ${ok ? 'OK' : 'FAIL'}  ` +
    `expected=0x${expected.toString(16).padStart(64,'0')}  ` +
    `got=0x${computed.toString(16).padStart(64,'0')}`
  );
  return { arity, ok };
}

const want = process.argv.slice(2).map(Number);
const arities = want.length ? want : [0, 1, 2, 3, 4, 5, 6, 17, 116];

fs.mkdirSync(BUILD, { recursive: true });
const results = arities.map(runOne);
const fails = results.filter(r => r.ok === false);
console.log('');
console.log(`summary: ${results.length - fails.length}/${results.length} passed`);
process.exit(fails.length ? 1 : 0);
