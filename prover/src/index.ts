// Baseline delegated-proving sidecar for the single-sig eip712 inner circuit.
// It reads on-chain state, builds witnesses, generates inner+outer proofs,
// and encrypts scheme-1 output note data for deposit, transfer, and withdrawal.
import Fastify from 'fastify';
import cors from '@fastify/cors';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { buildPoseidon } from 'circomlibjs';
import * as secp from '@noble/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { XWing } from '@noble/post-quantum/hybrid.js';
import { ethers } from 'ethers';
import {
  AUTH_POLICY_KEY_DOMAIN,
  DELIVERY_SCHEME_X_WING,
  DEPOSIT_OPERATION_KIND,
  bytesToHex,
  compactSignatureBytes,
  computeSingleSigAuthorizationSigningHash,
  hexToBytes,
  NK_DOMAIN,
  ORIGIN_MODE_DEFAULT,
  OUTPUT_SECRET_DOMAIN,
  PROTOCOL_COMMITMENT_TREE_DEPTH,
  PROTOCOL_REGISTRY_TREE_DEPTH,
  PROTOCOL_VERIFYING_CONTRACT,
  singleSigAuthDataCommitment,
  X_WING_PUBLIC_KEY_LENGTH,
} from '../../src/lib/protocol.ts';
import {
  assertAuthPolicyRoot,
  buildCommonTxArtifacts,
  buildSingleSigAuthorizationWitness,
  buildSingleSigAuthorizationWitnessFromIntent,
  byteArrayStrings,
  proveOuterTransaction,
  runInnerCircuit,
  type TxProofParams,
  withCircuitLock,
} from '../../integration/src/tx_proof_shared.ts';
import {
  NoteStore,
  replayShieldedPoolTransactsIntoNoteStore,
} from './note_delivery.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SHIELDED_POOL_ARTIFACT = resolve(__dirname, '../../contracts/out/ShieldedPool.sol/ShieldedPool.json');
const PORT = parseInt(process.env.PORT || '3001');
const RPC_URL = process.env.RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
const POOL_ADDRESS = process.env.POOL_ADDRESS || PROTOCOL_VERIFYING_CONTRACT;
const TREE_DEPTH = PROTOCOL_COMMITMENT_TREE_DEPTH;
const BASELINE_INNER_PACKAGE = 'eip712';
const BASELINE_INNER_OUTPUT_DIR = 'eip712_prove';
const BASELINE_INNER_VK_OUTPUT_DIR = 'eip712_vk_bootstrap';

type PoolStorageLayout = {
  userTreeNodesSlot: bigint;
  authTreeNodesSlot: bigint;
};

let poolStorageLayout: PoolStorageLayout | null = null;

// ==================== Poseidon ====================

let poseidon: any;
let h2: (a: bigint, b: bigint) => bigint;
let pHash: (vals: bigint[]) => bigint;

// ==================== MerkleTree (commitment tree) ====================

class MerkleTree {
  zeros: bigint[] = [];
  private filledSubtrees: bigint[] = [];
  leaves: bigint[] = [];
  nextIndex = 0;

  constructor() {
    this.zeros[0] = 0n;
    for (let i = 1; i <= TREE_DEPTH; i++) this.zeros[i] = h2(this.zeros[i - 1], this.zeros[i - 1]);
    this.filledSubtrees = [...this.zeros.slice(0, TREE_DEPTH)];
  }

  getRoot(): bigint {
    if (this.nextIndex === 0) return this.zeros[TREE_DEPTH];
    let ci = this.nextIndex - 1;
    let cur = this.leaves[ci];
    for (let i = 0; i < TREE_DEPTH; i++) {
      if (((ci >> i) & 1) === 0) cur = h2(cur, this.zeros[i]);
      else cur = h2(this.filledSubtrees[i], cur);
    }
    return cur;
  }

  insert(commitment: bigint): number {
    const idx = this.nextIndex;
    this.leaves.push(commitment);
    let cur = commitment;
    let ci = idx;
    for (let i = 0; i < TREE_DEPTH; i++) {
      if (((ci >> i) & 1) === 0) {
        this.filledSubtrees[i] = cur;
        cur = h2(cur, this.zeros[i]);
      } else {
        cur = h2(this.filledSubtrees[i], cur);
      }
    }
    this.nextIndex = idx + 1;
    return idx;
  }

  private getNodeAtLevel(level: number, index: number): bigint {
    if (level === 0) return index < this.leaves.length ? this.leaves[index] : this.zeros[0];
    return h2(this.getNodeAtLevel(level - 1, index * 2), this.getNodeAtLevel(level - 1, index * 2 + 1));
  }

  generateProof(leafIndex: number): bigint[] {
    const siblings: bigint[] = [];
    let ci = leafIndex;
    for (let level = 0; level < TREE_DEPTH; level++) {
      const sibIdx = ci % 2 === 0 ? ci + 1 : ci - 1;
      const subtreeSize = Math.ceil(this.nextIndex / (1 << level));
      siblings.push(sibIdx < subtreeSize ? this.getNodeAtLevel(level, sibIdx) : this.zeros[level]);
      ci = Math.floor(ci / 2);
    }
    return siblings;
  }
}

// ==================== Registry Cache ====================

interface UserRegistryEntry { nkHash: string; osHash: string; }
const registryCache = new Map<string, UserRegistryEntry>(); // address → {nkHash, osHash}

interface ExecutionConstraintsRequest {
  executionConstraintsFlags?: string;
  lockedOutputBinding0?: string;
  lockedOutputBinding1?: string;
  lockedOutputBinding2?: string;
}

interface BaseProofRequest {
  amount: string;
  tokenAddress?: string;
  feeRecipientAddress?: string;
  feeAmount?: string;
  feeNoteOwner?: string;
  nullifierKey: string;
  outputSecret: string;
  policyVersion?: string;
  originMode?: string;
  nonce: string;
  validUntilSeconds: string;
  executionChainId: string;
  executionConstraints?: ExecutionConstraintsRequest;
  signature: string;
}

interface DepositProofRequest extends BaseProofRequest {
  depositorAddress: string;
  recipientAddress?: string;
}

interface TransferProofRequest extends BaseProofRequest {
  senderAddress: string;
  recipientAddress: string;
  deliverySecret: string;
}

interface WithdrawProofRequest extends BaseProofRequest {
  senderAddress: string;
  recipientAddress: string;
  deliverySecret: string;
}

// ==================== Global State ====================

let commitmentTree: MerkleTree;
let noteStore: NoteStore;
let userEmptyHashes: string[] = [];
let authEmptyHashes: string[] = [];
let innerVkHashCache: bigint | null = null;

// ==================== Init ====================

async function initPoseidon() {
  poseidon = await buildPoseidon();
  h2 = (a: bigint, b: bigint): bigint => BigInt(poseidon.F.toString(poseidon([a, b])));
  const rawHash = (vals: bigint[]): bigint => {
    if (vals.length === 1) return vals[0];
    if (vals.length === 2) return h2(vals[0], vals[1]);
    let ls = 1; while (ls * 2 < vals.length) ls *= 2;
    return h2(rawHash(vals.slice(0, ls)), rawHash(vals.slice(ls)));
  };
  pHash = (vals: bigint[]): bigint => {
    if (vals.length === 1) return vals[0];
    return h2(BigInt(vals.length), rawHash(vals));
  };

  let emp = 0n;
  for (let i = 0; i < PROTOCOL_REGISTRY_TREE_DEPTH; i++) { userEmptyHashes.push(hex(emp)); emp = h2(emp, emp); }
  emp = 0n;
  for (let i = 0; i < PROTOCOL_REGISTRY_TREE_DEPTH; i++) { authEmptyHashes.push(hex(emp)); emp = h2(emp, emp); }

  commitmentTree = new MerkleTree();
  noteStore = new NoteStore(pHash);
}

function loadPoolStorageLayout(): PoolStorageLayout {
  if (poolStorageLayout) return poolStorageLayout;

  const parsed = JSON.parse(readFileSync(SHIELDED_POOL_ARTIFACT, 'utf8')) as {
    storageLayout?: {
      storage?: Array<{ label?: string; slot?: string }>;
    };
  };
  let userTreeNodesSlot: bigint | null = null;
  let authTreeNodesSlot: bigint | null = null;

  for (const entry of parsed.storageLayout?.storage ?? []) {
    if (entry.label === 'userTreeNodes') {
      userTreeNodesSlot = BigInt(entry.slot ?? '0');
    } else if (entry.label === 'authTreeNodes') {
      authTreeNodesSlot = BigInt(entry.slot ?? '0');
    }
  }

  if (userTreeNodesSlot === null || authTreeNodesSlot === null) {
    throw new Error('failed to discover ShieldedPool storage layout');
  }

  poolStorageLayout = { userTreeNodesSlot, authTreeNodesSlot };
  return poolStorageLayout;
}

// ==================== Chain Sync ====================

const POOL_ABI = [
  'event ShieldedPoolTransact(uint256 indexed nullifier0, uint256 indexed nullifier1, uint256 indexed intentNullifier, uint256 commitment0, uint256 commitment1, uint256 commitment2, uint256 leafIndex0, uint256 postInsertionRoot, bytes outputNoteData0, bytes outputNoteData1, bytes outputNoteData2)',
  'event UserRegistered(address indexed user, uint256 nullifierKeyHash, uint256 outputSecretHash)',
  'event DeliveryKeySet(address indexed user, uint32 indexed schemeId, bytes keyBytes)',
  'function getCurrentRoots() view returns (uint256 commitmentRoot, uint256 userRegistryRoot, uint256 authPolicyRoot)',
  'function getDeliveryKey(address user) view returns (uint32 schemeId, bytes keyBytes)',
  'function getUserRegistryEntry(address user) view returns (bool registered, uint256 nullifierKeyHash, uint256 outputSecretHash)',
];

async function syncFromChain() {
  console.log('Syncing from chain...');
  commitmentTree = new MerkleTree();
  noteStore.clear();
  registryCache.clear();
  deliveryKeyCache.clear();
  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
  const pool = new ethers.Contract(POOL_ADDRESS, POOL_ABI, provider);

  // Scan from recent blocks (RPC caps at 50K block range)
  const currentBlock = await provider.getBlockNumber();
  const fromBlock = Math.max(0, currentBlock - 49000);

  const regEvents = await pool.queryFilter(pool.filters.UserRegistered(), fromBlock);
  for (const ev of regEvents) {
    const addr = ev.args!.user.toLowerCase();
    registryCache.set(addr, {
      nkHash: hex(BigInt(ev.args!.nullifierKeyHash.toString())),
      osHash: hex(BigInt(ev.args!.outputSecretHash.toString())),
    });
  }
  console.log(`  ${regEvents.length} UserRegistered events, ${registryCache.size} users cached`);

  // Scan DeliveryKeySet events
  const dkEvents = await pool.queryFilter(pool.filters.DeliveryKeySet(), fromBlock);
  for (const ev of dkEvents) {
    const addr = ev.args!.user.toLowerCase();
    const schemeId = BigInt(ev.args!.schemeId.toString());
    const keyBytes = ev.args!.keyBytes;
    if (!keyBytes) {
      deliveryKeyCache.delete(addr);
      continue;
    }
    const key = fromHexBytes(keyBytes.slice(2));
    if (schemeId === DELIVERY_SCHEME_X_WING && key.length === X_WING_PUBLIC_KEY_LENGTH) {
      deliveryKeyCache.set(addr, key);
    } else {
      deliveryKeyCache.delete(addr);
    }
  }
  console.log(`  ${dkEvents.length} DeliveryKeySet events`);

  // Scan ShieldedPoolTransact events to rebuild commitment tree
  const txEvents = await pool.queryFilter(pool.filters.ShieldedPoolTransact(), fromBlock);
  // Sort by leafIndex0
  txEvents.sort((a, b) => a.args!.leafIndex0.toNumber() - b.args!.leafIndex0.toNumber());

  for (const ev of txEvents) {
    const leafIndex0 = ev.args!.leafIndex0.toNumber();
    const commitments = [
      BigInt(ev.args!.commitment0.toString()),
      BigInt(ev.args!.commitment1.toString()),
      BigInt(ev.args!.commitment2.toString()),
    ];

    while (commitmentTree.nextIndex < leafIndex0) {
      commitmentTree.insert(commitmentTree.zeros[0]);
    }
    for (const commitment of commitments) {
      if (commitmentTree.nextIndex <= leafIndex0 + 2) {
        commitmentTree.insert(commitment);
      }
    }

    replayShieldedPoolTransactsIntoNoteStore(noteStore, [
      {
        leafIndex0,
        nullifier0: hex(BigInt(ev.args!.nullifier0.toString())),
        nullifier1: hex(BigInt(ev.args!.nullifier1.toString())),
        commitment0: hex(commitments[0]),
        commitment1: hex(commitments[1]),
        commitment2: hex(commitments[2]),
        outputNoteData0: ev.args!.outputNoteData0,
        outputNoteData1: ev.args!.outputNoteData1,
        outputNoteData2: ev.args!.outputNoteData2,
      },
    ]);
  }

  console.log(`  Tree: ${commitmentTree.nextIndex} leaves, ${noteStore.chainNotes.length} encrypted notes`);

}

// ==================== Utils ====================

function hex(v: bigint): string { return '0x' + v.toString(16); }

function nestedMappingSlot(k1: bigint, k2: bigint, baseSlot: bigint): string {
  const outerSlot = ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(['uint256', 'uint256'], [k1.toString(), baseSlot.toString()]));
  return ethers.utils.keccak256(ethers.utils.defaultAbiCoder.encode(['uint256', 'bytes32'], [k2.toString(), outerSlot]));
}

async function readTreeSiblings(provider: ethers.providers.JsonRpcProvider, poolAddr: string, baseSlot: bigint, key: bigint, depth: number, emptyHashes: string[]): Promise<string[]> {
  const siblings: string[] = [];
  const BATCH = 50;
  for (let batch = 0; batch < depth; batch += BATCH) {
    const end = Math.min(batch + BATCH, depth);
    const results = await Promise.all(
      Array.from({ length: end - batch }, (_, j) => {
        const i = batch + j;
        const sibIdx = (key >> BigInt(i)) ^ 1n;
        return provider.getStorageAt(poolAddr, nestedMappingSlot(BigInt(i), sibIdx, baseSlot));
      })
    );
    for (let j = 0; j < results.length; j++) {
      const val = BigInt(results[j]);
      siblings.push(val === 0n ? emptyHashes[batch + j] : hex(val));
    }
  }
  return siblings;
}

// ==================== Delivery Key Cache ====================

const deliveryKeyCache = new Map<string, Uint8Array>(); // lowercase address → X-Wing pubkey

async function getDeliveryPubKey(provider: ethers.providers.JsonRpcProvider, ownerAddress: bigint): Promise<Uint8Array | null> {
  const addrHex = '0x' + ownerAddress.toString(16).padStart(40, '0');
  const cached = deliveryKeyCache.get(addrHex.toLowerCase());
  if (cached) return cached;
  // Fallback: read from contract
  const pool = new ethers.Contract(POOL_ADDRESS, POOL_ABI, provider);
  const [schemeId, keyBytes] = await pool.getDeliveryKey(addrHex);
  if (!keyBytes || BigInt(schemeId.toString()) !== DELIVERY_SCHEME_X_WING) return null;
  const key = fromHexBytes(keyBytes.slice(2));
  if (key.length !== X_WING_PUBLIC_KEY_LENGTH) return null;
  deliveryKeyCache.set(addrHex.toLowerCase(), key);
  return key;
}

async function getUserRegistryEntryCachedOrChain(
  provider: ethers.providers.JsonRpcProvider,
  ownerAddress: bigint,
): Promise<UserRegistryEntry> {
  const addrHex = '0x' + ownerAddress.toString(16).padStart(40, '0');
  const cached = registryCache.get(addrHex.toLowerCase());
  if (cached) return cached;

  const pool = new ethers.Contract(POOL_ADDRESS, POOL_ABI, provider);
  const [registered, nkHash, osHash] = await pool.getUserRegistryEntry(addrHex);
  if (!registered) {
    throw new Error(`recipient ${addrHex} is not registered`);
  }

  const entry = {
    nkHash: hex(BigInt(nkHash.toString())),
    osHash: hex(BigInt(osHash.toString())),
  };
  registryCache.set(addrHex.toLowerCase(), entry);
  return entry;
}

function normalizeAddress(addressValue: bigint): string {
  return '0x' + addressValue.toString(16).padStart(40, '0');
}

function deliveryKeyHex(key: Uint8Array | null): string | undefined {
  return key ? bytesToHex(key) : undefined;
}

function addNonDummyOutputNotes(common: ReturnType<typeof buildCommonTxArtifacts>) {
  const notes = [
    { note: common.note0, commitment: common.out0 },
    { note: common.note1, commitment: common.out1 },
    { note: common.note2, commitment: common.out2 },
  ];
  for (const { note, commitment } of notes) {
    if (note.amount !== 0n) {
      noteStore.addNote({
        commitment: hex(commitment),
        leafIndex: commitmentTree.nextIndex,
        amount: note.amount.toString(),
        ownerAddress: hex(note.ownerAddress),
        randomness: hex(note.randomness),
        nullifierKeyHash: hex(note.nullifierKeyHash),
        tokenAddress: hex(note.tokenAddress),
        originTag: hex(note.originTag),
      });
    }
    commitmentTree.insert(commitment);
  }
}

function proveSingleSigTransaction(
  common: ReturnType<typeof buildCommonTxArtifacts>,
  signature: string,
) {
  if (
    common.executionConstraints.executionConstraintsFlags !== 0n ||
    common.executionConstraints.lockedOutputBinding0 !== 0n ||
    common.executionConstraints.lockedOutputBinding1 !== 0n ||
    common.executionConstraints.lockedOutputBinding2 !== 0n
  ) {
    throw new Error('eip712 only supports unconstrained execution constraints');
  }

  const signingHash = computeSingleSigAuthorizationSigningHash({
    policyVersion: common.policyVersion,
    operationKind: common.operationKind,
    tokenAddress: common.tokenAddress,
    recipientAddress: common.recipientAddress,
    amount: common.amount,
    feeRecipientAddress: common.feeRecipientAddress,
    feeAmount: common.feeAmount,
    originMode: common.originMode,
    nonce: common.nonce,
    validUntilSeconds: common.validUntilSeconds,
    executionChainId: common.executionChainId,
  });
  const { pubX, pubY, sig64, authCommitment } = recoverPubKey(signature, signingHash);
  const innerWitness = {
    ...buildSingleSigAuthorizationWitness(common),
    single_sig_policy: {
      signer: {
        x: byteArrayStrings(pubX),
        y: byteArrayStrings(pubY),
      },
    },
    approval: {
      signature: byteArrayStrings(sig64),
    },
  };
  const inner = runInnerCircuit(
    BASELINE_INNER_PACKAGE,
    innerWitness,
    BASELINE_INNER_OUTPUT_DIR,
    pHash,
  );
  assertAuthPolicyRoot(common, authCommitment, inner.innerVkHash, { h2, pHash });
  return proveOuterTransaction(common, authCommitment, inner);
}

// ==================== Inner VK Hash ====================

async function getInnerVkHash(): Promise<bigint> {
  if (innerVkHashCache) return innerVkHashCache;
  console.log(`Generating inner VK${innerVkHashCache ? ' (refresh)' : ' (first run)'}...`);
  const ownerAddress = 0x7e5f4552091a69125d5dfcb7b8c2659029395bdfn;
  const policyVersion = 1n;
  const operationKind = DEPOSIT_OPERATION_KIND;
  const tokenAddress = 0n;
  const recipientAddress = ownerAddress;
  const amount = 1n;
  const feeRecipientAddress = 0n;
  const feeAmount = 0n;
  const originMode = ORIGIN_MODE_DEFAULT;
  const nonce = 42n;
  const validUntilSeconds = 3601n;
  const executionChainId = 31337n;
  const privateKey = fromHexBytes(INNER_BOOTSTRAP_PRIVATE_KEY_HEX);
  const pub = secp.getPublicKey(privateKey, false);
  const pubX = pub.slice(1, 33);
  const pubY = pub.slice(33, 65);
  const signingHash = computeSingleSigAuthorizationSigningHash({
    policyVersion,
    operationKind,
    tokenAddress,
    recipientAddress,
    amount,
    feeRecipientAddress,
    feeAmount,
    nonce,
    validUntilSeconds,
    executionChainId,
  });
  const signature = await secp.signAsync(signingHash, privateKey);
  const inner = runInnerCircuit(
    BASELINE_INNER_PACKAGE,
    {
      ...buildSingleSigAuthorizationWitnessFromIntent({
        policyVersion,
        operationKind,
        tokenAddress,
        recipientAddress,
        amount,
        feeRecipientAddress,
        feeAmount,
        originMode,
        nonce,
        validUntilSeconds,
        executionChainId,
      }),
      single_sig_policy: {
        signer: {
          x: byteArrayStrings(pubX),
          y: byteArrayStrings(pubY),
        },
      },
      approval: {
        signature: byteArrayStrings(signature.toCompactRawBytes()),
      },
    },
    BASELINE_INNER_VK_OUTPUT_DIR,
    pHash,
  );
  innerVkHashCache = inner.innerVkHash;
  console.log(`Inner VK hash: ${hex(innerVkHashCache)}`);
  return innerVkHashCache;
}

// ==================== Inner Proof Generation ====================

// Recover secp256k1 public key from EIP-712 signature
function recoverPubKey(signature: string, signingHash: Uint8Array) {
  const sigBytes = hexToBytes(signature);
  if (sigBytes.length !== 65) {
    throw new Error(`expected 65-byte signature, got ${sigBytes.length}`);
  }
  const recovery = sigBytes[64] >= 27 ? sigBytes[64] - 27 : sigBytes[64];
  const toHex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  const sigObj = new secp.Signature(
    BigInt('0x' + toHex(sigBytes.slice(0, 32))),
    BigInt('0x' + toHex(sigBytes.slice(32, 64))),
  ).addRecoveryBit(recovery);
  const pubKey = sigObj.recoverPublicKey(signingHash);
  const pub = pubKey.toRawBytes(false);
  const pubX = pub.slice(1, 33);
  const pubY = pub.slice(33, 65);
  const authCommitment = singleSigAuthDataCommitment(
    pubX,
    pubY,
    (values) => pHash(values),
  );
  return { pubX, pubY, sig64: compactSignatureBytes(signature), authCommitment };
}

const fromHexBytes = (h: string) => new Uint8Array(h.match(/.{2}/g)!.map(b => parseInt(b, 16)));
const INNER_BOOTSTRAP_PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';

// ==================== Read Contract State ====================

async function readContractState(provider: ethers.providers.JsonRpcProvider, senderAddress: bigint) {
  const layout = loadPoolStorageLayout();
  const pool = new ethers.Contract(POOL_ADDRESS, POOL_ABI, provider);
  const [commitmentRootRaw, userRegistryRootRaw, authPolicyRootRaw] = await pool.getCurrentRoots();
  const commitRoot = BigInt(commitmentRootRaw.toString());
  const userRegRoot = BigInt(userRegistryRootRaw.toString());
  const authPolicyRoot = BigInt(authPolicyRootRaw.toString());

  const userKey = senderAddress & ((1n << 160n) - 1n);
  const userSiblings = await readTreeSiblings(
    provider,
    POOL_ADDRESS,
    layout.userTreeNodesSlot,
    userKey,
    PROTOCOL_REGISTRY_TREE_DEPTH,
    userEmptyHashes
  );

  const innerVkHash = await getInnerVkHash();
  const authTreeKey = pHash([AUTH_POLICY_KEY_DOMAIN, senderAddress, innerVkHash]);
  const authTruncated = authTreeKey & ((1n << 160n) - 1n);
  const authSiblings = await readTreeSiblings(
    provider,
    POOL_ADDRESS,
    layout.authTreeNodesSlot,
    authTruncated,
    PROTOCOL_REGISTRY_TREE_DEPTH,
    authEmptyHashes
  );

  return { commitRoot, userRegRoot, authPolicyRoot, userSiblings, authSiblings, innerVkHash };
}


// ==================== Server ====================

const app = Fastify({ logger: true, bodyLimit: 10 * 1024 * 1024 });
await app.register(cors, { origin: true });
await initPoseidon();
await syncFromChain();

app.get('/health', async () => ({ status: 'ok' }));

app.post('/derive-hashes', async (request) => {
  const { nullifierKey, outputSecret, deliverySecret } = request.body as {
    nullifierKey: string;
    outputSecret: string;
    deliverySecret: string;
  };
  const xwingSeed = keccak_256(new TextEncoder().encode('xwing-delivery-' + deliverySecret));
  const { publicKey: xwingPubKey } = XWing.keygen(xwingSeed);
  return {
    nkHash: hex(pHash([NK_DOMAIN, BigInt(nullifierKey)])),
    osHash: hex(pHash([OUTPUT_SECRET_DOMAIN, BigInt(outputSecret)])),
    deliveryPubKey: '0x' + Array.from(xwingPubKey).map(b => b.toString(16).padStart(2, '0')).join(''),
  };
});

app.get('/info', async () => {
  const innerVkHash = await getInnerVkHash();
  return {
    innerVkHash: hex(innerVkHash),
    innerCircuitPackage: BASELINE_INNER_PACKAGE,
    deliverySchemeId: DELIVERY_SCHEME_X_WING.toString(),
    notes: 'baseline single-sig eip712 example',
  };
});

// Compute the baseline single-sig auth policy commitment from a wallet signature.
app.post('/auth-commitment', async (request) => {
  const { signature, message } = request.body as { signature: string; message: string };
  const prefix = `\x19Ethereum Signed Message:\n${message.length}${message}`;
  const msgHash = keccak_256(new TextEncoder().encode(prefix));
  const { authCommitment } = recoverPubKey(signature, msgHash);
  return { authDataCommitment: hex(authCommitment) };
});

// Get unspent notes for an address
app.get('/notes/:address', async (request) => {
  const { address } = request.params as { address: string };
  const { nullifierKey, deliverySecret } = request.query as { nullifierKey?: string; deliverySecret?: string };
  if (!nullifierKey || !deliverySecret) return { error: 'nullifierKey and deliverySecret query params required' };
  const notes = await noteStore.getUnspentNotes(BigInt(address), BigInt(nullifierKey), BigInt(deliverySecret));
  const balances: Record<string, bigint> = {};
  for (const n of notes) {
    const tok = n.tokenAddress;
    balances[tok] = (balances[tok] || 0n) + BigInt(n.amount);
  }
  return {
    notes: notes.map(n => ({ amount: n.amount, tokenAddress: n.tokenAddress, leafIndex: n.leafIndex, commitment: n.commitment })),
    balances: Object.fromEntries(Object.entries(balances).map(([k, v]) => [k, v.toString()])),
  };
});

// ==================== POST /prove/deposit ====================

app.post('/prove/deposit', async (request, reply) => {
  const params = request.body as DepositProofRequest;
  try {
    const startTime = Date.now();
    console.log('=== Deposit proof request ===');

    const depositorAddress = BigInt(params.depositorAddress);
    const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
    const recipientAddress =
      params.recipientAddress === undefined ? depositorAddress : BigInt(params.recipientAddress);
    const feeAmount = BigInt(params.feeAmount ?? '0');
    const feeNoteOwner = BigInt(params.feeNoteOwner ?? params.feeRecipientAddress ?? '0');

    console.log('Reading chain state for deposit proof...');
    const state = await readContractState(provider, depositorAddress);
    const senderDeliveryKey = await getDeliveryPubKey(provider, depositorAddress);

    let recipientEntry: UserRegistryEntry | null = null;
    let recipientSiblings = state.userSiblings;
    let recipientDeliveryKey = senderDeliveryKey;
    if (recipientAddress !== depositorAddress) {
      recipientEntry = await getUserRegistryEntryCachedOrChain(provider, recipientAddress);
      recipientSiblings = await readTreeSiblings(
        provider,
        POOL_ADDRESS,
        loadPoolStorageLayout().userTreeNodesSlot,
        recipientAddress & ((1n << 160n) - 1n),
        PROTOCOL_REGISTRY_TREE_DEPTH,
        userEmptyHashes,
      );
      recipientDeliveryKey = await getDeliveryPubKey(provider, recipientAddress);
    }

    let feeEntry: UserRegistryEntry | null = null;
    let feeSiblings: string[] | undefined;
    let feeDeliveryKey: Uint8Array | null | undefined;
    if (feeAmount !== 0n && feeNoteOwner !== 0n && feeNoteOwner !== depositorAddress && feeNoteOwner !== recipientAddress) {
      feeEntry = await getUserRegistryEntryCachedOrChain(provider, feeNoteOwner);
      feeSiblings = await readTreeSiblings(
        provider,
        POOL_ADDRESS,
        loadPoolStorageLayout().userTreeNodesSlot,
        feeNoteOwner & ((1n << 160n) - 1n),
        PROTOCOL_REGISTRY_TREE_DEPTH,
        userEmptyHashes,
      );
      feeDeliveryKey = await getDeliveryPubKey(provider, feeNoteOwner);
    }

    const proofParams: TxProofParams = {
      mode: 'deposit',
      depositorAddress: normalizeAddress(depositorAddress),
      recipientAddress: normalizeAddress(recipientAddress),
      amount: params.amount,
      tokenAddress: params.tokenAddress ?? '0',
      feeRecipientAddress: params.feeRecipientAddress,
      feeAmount: params.feeAmount,
      feeNoteOwner: params.feeNoteOwner,
      nullifierKey: params.nullifierKey,
      outputSecret: params.outputSecret,
      policyVersion: params.policyVersion ?? '1',
      originMode: params.originMode,
      nonce: params.nonce,
      validUntilSeconds: params.validUntilSeconds,
      executionChainId: params.executionChainId,
      commitmentRoot: hex(state.commitRoot),
      userRegistryRoot: hex(state.userRegRoot),
      authPolicyRoot: hex(state.authPolicyRoot),
      userSiblings: state.userSiblings,
      recipientSiblings,
      authSiblings: state.authSiblings,
      recipientNkHash: recipientEntry?.nkHash,
      recipientOsHash: recipientEntry?.osHash,
      feeNkHash: feeEntry?.nkHash,
      feeOsHash: feeEntry?.osHash,
      feeSiblings,
      deliverySchemeId: senderDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      deliveryPubKey: deliveryKeyHex(senderDeliveryKey),
      recipientDeliverySchemeId: recipientDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      recipientDeliveryPubKey: deliveryKeyHex(recipientDeliveryKey),
      feeDeliverySchemeId: feeDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      feeDeliveryPubKey: deliveryKeyHex(feeDeliveryKey ?? null),
      executionConstraints: params.executionConstraints,
    };

    const result = await withCircuitLock(async () => {
      const common = buildCommonTxArtifacts(proofParams, { h2, pHash });
      const proofResult = proveSingleSigTransaction(common, params.signature);
      addNonDummyOutputNotes(common);
      return proofResult;
    });

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`Deposit proof generated in ${elapsed}s`);
    return { ...result, provingTime: elapsed };
  } catch (e: any) {
    console.error('Prove error:', e.stderr?.toString()?.slice(0, 500) || e.message);
    reply.code(500);
    return { error: e.message?.slice(0, 500) };
  }
});

// ==================== POST /prove/transfer ====================

app.post('/prove/transfer', async (request, reply) => {
  const params = request.body as TransferProofRequest;
  try {
    const startTime = Date.now();
    console.log('=== Transfer proof request ===');

    const senderAddress = BigInt(params.senderAddress);
    const recipientAddress = BigInt(params.recipientAddress);
    const amount = BigInt(params.amount);
    const tokenAddress = BigInt(params.tokenAddress || '0');
    const nullifierKey = BigInt(params.nullifierKey);
    const deliverySecret = BigInt(params.deliverySecret);
    const feeAmount = BigInt(params.feeAmount ?? '0');
    const feeNoteOwner = BigInt(params.feeNoteOwner ?? params.feeRecipientAddress ?? '0');

    // Find unspent note with sufficient balance
    const unspent = await noteStore.getUnspentNotes(senderAddress, nullifierKey, deliverySecret);
    const note = unspent.find(
      n => BigInt(n.amount) >= amount + feeAmount && n.tokenAddress === hex(tokenAddress),
    );
    if (!note) {
      reply.code(400);
      return { error: `No unspent note with sufficient balance. Have: ${unspent.map(n => n.amount).join(', ')}` };
    }

    const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
    const state = await readContractState(provider, senderAddress);
    const senderDeliveryKey = await getDeliveryPubKey(provider, senderAddress);
    const recipientEntry =
      recipientAddress === senderAddress
        ? null
        : await getUserRegistryEntryCachedOrChain(provider, recipientAddress);
    const recipientSiblings =
      recipientAddress === senderAddress
        ? state.userSiblings
        : await readTreeSiblings(
            provider,
            POOL_ADDRESS,
            loadPoolStorageLayout().userTreeNodesSlot,
            recipientAddress & ((1n << 160n) - 1n),
            PROTOCOL_REGISTRY_TREE_DEPTH,
            userEmptyHashes
          );
    const recipientDeliveryKey =
      recipientAddress === senderAddress ? senderDeliveryKey : await getDeliveryPubKey(provider, recipientAddress);

    let feeEntry: UserRegistryEntry | null = null;
    let feeSiblings: string[] | undefined;
    let feeDeliveryKey: Uint8Array | null | undefined;
    if (feeAmount !== 0n && feeNoteOwner !== 0n && feeNoteOwner !== senderAddress && feeNoteOwner !== recipientAddress) {
      feeEntry = await getUserRegistryEntryCachedOrChain(provider, feeNoteOwner);
      feeSiblings = await readTreeSiblings(
        provider,
        POOL_ADDRESS,
        loadPoolStorageLayout().userTreeNodesSlot,
        feeNoteOwner & ((1n << 160n) - 1n),
        PROTOCOL_REGISTRY_TREE_DEPTH,
        userEmptyHashes
      );
      feeDeliveryKey = await getDeliveryPubKey(provider, feeNoteOwner);
    }

    const proofParams: TxProofParams = {
      mode: 'transfer',
      senderAddress: normalizeAddress(senderAddress),
      recipientAddress: normalizeAddress(recipientAddress),
      amount: params.amount,
      tokenAddress: params.tokenAddress ?? '0',
      feeRecipientAddress: params.feeRecipientAddress,
      feeAmount: params.feeAmount,
      feeNoteOwner: params.feeNoteOwner,
      nullifierKey: params.nullifierKey,
      outputSecret: params.outputSecret,
      policyVersion: params.policyVersion ?? '1',
      originMode: params.originMode,
      nonce: params.nonce,
      validUntilSeconds: params.validUntilSeconds,
      executionChainId: params.executionChainId,
      commitmentRoot: hex(state.commitRoot),
      userRegistryRoot: hex(state.userRegRoot),
      authPolicyRoot: hex(state.authPolicyRoot),
      inputLeafIndex: note.leafIndex.toString(),
      inputAmount: note.amount,
      inputRandomness: note.randomness,
      inputOriginTag: note.originTag,
      recipientNkHash: recipientEntry?.nkHash,
      recipientOsHash: recipientEntry?.osHash,
      changeAmount: (BigInt(note.amount) - amount - feeAmount).toString(),
      inputSiblings: commitmentTree.generateProof(note.leafIndex).map(hex),
      userSiblings: state.userSiblings,
      recipientSiblings,
      authSiblings: state.authSiblings,
      feeNkHash: feeEntry?.nkHash,
      feeOsHash: feeEntry?.osHash,
      feeSiblings,
      deliverySchemeId: senderDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      deliveryPubKey: deliveryKeyHex(senderDeliveryKey),
      recipientDeliverySchemeId: recipientDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      recipientDeliveryPubKey: deliveryKeyHex(recipientDeliveryKey),
      changeDeliverySchemeId: senderDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      changeDeliveryPubKey: deliveryKeyHex(senderDeliveryKey),
      feeDeliverySchemeId: feeDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      feeDeliveryPubKey: deliveryKeyHex(feeDeliveryKey ?? null),
      executionConstraints: params.executionConstraints,
    };

    const result = await withCircuitLock(async () => {
      const common = buildCommonTxArtifacts(proofParams, { h2, pHash });
      const proofResult = proveSingleSigTransaction(common, params.signature);
      addNonDummyOutputNotes(common);
      noteStore.markSpent(common.nullifier0);
      return proofResult;
    });

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`Transfer proof generated in ${elapsed}s`);
    return { ...result, provingTime: elapsed };
  } catch (e: any) {
    console.error('Prove error:', e.stderr?.toString()?.slice(0, 500) || e.message);
    reply.code(500);
    return { error: e.message?.slice(0, 500) };
  }
});

// ==================== POST /prove/withdraw ====================

app.post('/prove/withdraw', async (request, reply) => {
  const params = request.body as WithdrawProofRequest;
  try {
    const startTime = Date.now();
    console.log('=== Withdraw proof request ===');

    const senderAddress = BigInt(params.senderAddress);
    const publicRecipient = BigInt(params.recipientAddress);
    const amount = BigInt(params.amount);
    const tokenAddress = BigInt(params.tokenAddress || '0');
    const nullifierKey = BigInt(params.nullifierKey);
    const outputSecret = BigInt(params.outputSecret);
    const deliverySecret = BigInt(params.deliverySecret);
    const feeAmount = BigInt(params.feeAmount ?? '0');
    const feeNoteOwner = BigInt(params.feeNoteOwner ?? params.feeRecipientAddress ?? '0');
    const senderNkHash = pHash([NK_DOMAIN, nullifierKey]);
    const senderOsHash = pHash([OUTPUT_SECRET_DOMAIN, outputSecret]);

    const unspent = await noteStore.getUnspentNotes(senderAddress, nullifierKey, deliverySecret);
    const note = unspent.find(
      n => BigInt(n.amount) >= amount + feeAmount && n.tokenAddress === hex(tokenAddress),
    );
    if (!note) {
      reply.code(400);
      return { error: `No unspent note with sufficient balance. Have: ${unspent.map(n => n.amount).join(', ')}` };
    }
    const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
    const state = await readContractState(provider, senderAddress);
    const senderDeliveryKey = await getDeliveryPubKey(provider, senderAddress);

    let feeEntry: UserRegistryEntry | null = null;
    let feeSiblings: string[] | undefined;
    let feeDeliveryKey: Uint8Array | null | undefined;
    if (feeAmount !== 0n && feeNoteOwner !== 0n && feeNoteOwner !== senderAddress) {
      feeEntry = await getUserRegistryEntryCachedOrChain(provider, feeNoteOwner);
      feeSiblings = await readTreeSiblings(
        provider,
        POOL_ADDRESS,
        loadPoolStorageLayout().userTreeNodesSlot,
        feeNoteOwner & ((1n << 160n) - 1n),
        PROTOCOL_REGISTRY_TREE_DEPTH,
        userEmptyHashes
      );
      feeDeliveryKey = await getDeliveryPubKey(provider, feeNoteOwner);
    }

    const proofParams: TxProofParams = {
      mode: 'withdraw',
      senderAddress: normalizeAddress(senderAddress),
      recipientAddress: normalizeAddress(publicRecipient),
      amount: params.amount,
      tokenAddress: params.tokenAddress ?? '0',
      feeRecipientAddress: params.feeRecipientAddress,
      feeAmount: params.feeAmount,
      feeNoteOwner: params.feeNoteOwner,
      nullifierKey: params.nullifierKey,
      outputSecret: params.outputSecret,
      policyVersion: params.policyVersion ?? '1',
      originMode: params.originMode,
      nonce: params.nonce,
      validUntilSeconds: params.validUntilSeconds,
      executionChainId: params.executionChainId,
      commitmentRoot: hex(state.commitRoot),
      userRegistryRoot: hex(state.userRegRoot),
      authPolicyRoot: hex(state.authPolicyRoot),
      inputLeafIndex: note.leafIndex.toString(),
      inputAmount: note.amount,
      inputRandomness: note.randomness,
      inputOriginTag: note.originTag,
      recipientNkHash: hex(senderNkHash),
      recipientOsHash: hex(senderOsHash),
      changeAmount: (BigInt(note.amount) - amount - feeAmount).toString(),
      inputSiblings: commitmentTree.generateProof(note.leafIndex).map(hex),
      userSiblings: state.userSiblings,
      recipientSiblings: state.userSiblings,
      authSiblings: state.authSiblings,
      feeNkHash: feeEntry?.nkHash,
      feeOsHash: feeEntry?.osHash,
      feeSiblings,
      deliverySchemeId: senderDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      deliveryPubKey: deliveryKeyHex(senderDeliveryKey),
      feeDeliverySchemeId: feeDeliveryKey ? DELIVERY_SCHEME_X_WING.toString() : undefined,
      feeDeliveryPubKey: deliveryKeyHex(feeDeliveryKey ?? null),
      executionConstraints: params.executionConstraints,
    };

    const result = await withCircuitLock(async () => {
      const common = buildCommonTxArtifacts(proofParams, { h2, pHash });
      const proofResult = proveSingleSigTransaction(common, params.signature);
      addNonDummyOutputNotes(common);
      noteStore.markSpent(common.nullifier0);
      return proofResult;
    });

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`Withdraw proof generated in ${elapsed}s`);
    return { ...result, provingTime: elapsed };
  } catch (e: any) {
    console.error('Prove error:', e.stderr?.toString()?.slice(0, 500) || e.message);
    reply.code(500);
    return { error: e.message?.slice(0, 500) };
  }
});

await app.listen({ port: PORT, host: '0.0.0.0' });
console.log(`Prover server listening on port ${PORT}`);
console.log(`Pool: ${POOL_ADDRESS} | RPC: ${RPC_URL}`);
