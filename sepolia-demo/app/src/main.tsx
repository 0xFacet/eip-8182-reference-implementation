import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ConnectButton, RainbowKitProvider, lightTheme } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';
import { WagmiProvider, useAccount, useChainId, useWalletClient } from 'wagmi';
import {
  authIntentTypedData,
  authIntentDigest,
  createDeterministicDemoProfile,
  fieldToHex,
  finalizeDeterministicProfileAuth,
  getPoolAuthPolicySetLogs,
  getPoolDepositLogs,
  getPoolTransactLogs,
  hasProfileAuth,
  loadDemoProfile,
  noteBodyCommitment,
  normalizeAddress,
  nullifier,
  ownerCommitment,
  prepareDemoPrivateTransfer,
  prepareEncryptedOutputNoteData,
  profileField,
  profilePublicKey,
  profileSecretKey,
  profileDerivationMessage,
  profileStorageKey,
  randomField,
  readAuthPolicyEntry,
  readCurrentRoots,
  readNullifierSpent,
  readRecipient,
  recoverPublicKey,
  saveDemoProfile,
  sendClearRecipient,
  sendDeposit,
  sendPublishRecipient,
  sendSetAuthPolicy,
  sendTransact,
  signProfileMessage,
  waitForTransactionReceipt,
  SepoliaDemoIndexer,
  jsonStringifyTypedData,
  type ChainRoots,
  type DemoPoolPublicInputs,
  type DemoProfile,
  type Eip1193Provider,
  type HexAddress,
  type IndexedNote,
  type ShieldedPoolTransactEvent,
} from '../../src/index.js';
import { addressesConfigured, authVerifierConfigured, demoAddresses, deploymentBlock, SEPOLIA_CHAIN_ID } from './demoConfig';
import { proveTransferInBrowser, type BrowserProverResponse } from './proverClient';
import { rainbowWagmiConfig } from './wagmi';
import './styles.css';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const;

type BusyAction = 'profile' | 'publish' | 'clear' | 'auth' | 'deposit' | 'scan' | 'transfer' | '';

type ActivityItem = {
  id: string;
  kind: 'deposit' | 'transfer';
  status: 'pending' | 'confirmed' | 'failed';
  amountWei: string;
  timestamp: number;
  txHash?: `0x${string}`;
  recipient?: HexAddress;
};

type TransferDebug = {
  inputLeaf: string;
  inputAmountWei: string;
  transferAmountWei: string;
  recipient: HexAddress;
  changeAmountWei: string;
  intentReplayId: bigint;
  transactionIntentDigest: bigint;
  recipientOutputHash: bigint;
  changeOutputHash: bigint;
  dummyOutputHash: bigint;
  poolProveMs?: number;
  authProveMs?: number;
  txHash?: `0x${string}`;
};

function App() {
  const { address: connectedAddress, chainId: connectedAccountChainId } = useAccount();
  const configuredChainId = useChainId();
  const { data: walletClient } = useWalletClient();
  const configured = addressesConfigured();
  const authReady = authVerifierConfigured();
  const lastWalletKey = useRef('');
  const [provider, setProvider] = useState<Eip1193Provider | null>(null);
  const [account, setAccount] = useState<HexAddress | ''>('');
  const [chainId, setChainId] = useState<bigint | null>(null);
  const [profile, setProfile] = useState<DemoProfile | null>(null);
  const [registryOwnerHash, setRegistryOwnerHash] = useState<bigint | null>(null);
  const [authPolicyOwnerHash, setAuthPolicyOwnerHash] = useState<bigint | null>(null);
  const [authRegistered, setAuthRegistered] = useState(false);
  const [roots, setRoots] = useState<ChainRoots | null>(null);
  const [notes, setNotes] = useState<IndexedNote[]>([]);
  const [depositAmount, setDepositAmount] = useState('0.001');
  const [recipientAddress, setRecipientAddress] = useState('');
  const [transferAmount, setTransferAmount] = useState('0.0005');
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [lastTransferDebug, setLastTransferDebug] = useState<TransferDebug | null>(null);
  const [transferPhase, setTransferPhase] = useState('');
  const [transferStartedAt, setTransferStartedAt] = useState<number | null>(null);
  const [transferElapsedMs, setTransferElapsedMs] = useState(0);
  const [busy, setBusy] = useState<BusyAction>('');
  const [status, setStatus] = useState('Connect a Sepolia wallet to start.');
  const [log, setLog] = useState<string[]>([]);

  const profileReady = profile !== null;
  const profileSigned = profile !== null && hasProfileAuth(profile);
  const profileOwnerHash = profile === null ? null : BigInt(profile.ownerNullifierKeyHash);
  const recipientPublished = profileOwnerHash !== null && registryOwnerHash === profileOwnerHash;
  const recipientProfileMismatch = profileOwnerHash !== null
    && registryOwnerHash !== null
    && registryOwnerHash !== profileOwnerHash;
  const authPolicyProfileMismatch = profileOwnerHash !== null
    && authPolicyOwnerHash !== null
    && authPolicyOwnerHash !== profileOwnerHash;
  const setupComplete = profileSigned && recipientPublished && authRegistered;
  const spendableNotes = useMemo(
    () => notes.filter((note) => note.status === 'decrypted' && (note.payload?.amount ?? 0n) > 0n),
    [notes],
  );
  const privateBalance = useMemo(
    () => spendableNotes.reduce((sum, note) => sum + (note.payload?.amount ?? 0n), 0n),
    [spendableNotes],
  );
  const transferAmountWei = useMemo(() => parseEthOrNull(transferAmount), [transferAmount]);
  const selectedNote = chooseSpendableNote(spendableNotes, transferAmountWei);
  const ownedNotes = notes.filter((note) => note.status !== 'pending');
  const encryptedNoteCount = notes.filter((note) => note.status === 'pending').length;
  const spentNoteCount = notes.filter((note) => note.status === 'spent').length;
  const walletReady = provider !== null && account !== '' && chainId === BigInt(SEPOLIA_CHAIN_ID);

  useEffect(() => {
    if (busy !== 'transfer' || transferStartedAt === null) return undefined;
    setTransferElapsedMs(Date.now() - transferStartedAt);
    const interval = window.setInterval(() => {
      setTransferElapsedMs(Date.now() - transferStartedAt);
    }, 250);
    return () => window.clearInterval(interval);
  }, [busy, transferStartedAt]);

  useEffect(() => {
    let cancelled = false;

    async function syncConnectedWallet() {
      if (connectedAddress === undefined || walletClient === undefined) {
        lastWalletKey.current = '';
        setProvider(null);
        setAccount('');
        setChainId(null);
        setProfile(null);
        setRegistryOwnerHash(null);
        setAuthPolicyOwnerHash(null);
        setAuthRegistered(false);
        setNotes([]);
        setActivity([]);
        setLastTransferDebug(null);
        setStatus('Connect a Sepolia wallet to start.');
        return;
      }

      const wallet = walletClient as unknown as Eip1193Provider;
      const walletAccount = normalizeAddress(connectedAddress, 'account');
      const nextChainId = BigInt(connectedAccountChainId ?? configuredChainId);
      const walletKey = `${walletAccount}:${nextChainId.toString()}`;
      setProvider(wallet);
      setAccount(walletAccount);
      setChainId(nextChainId);
      setActivity(loadActivity(window.localStorage, activityStorageKey(walletAccount)));

      if (lastWalletKey.current !== walletKey) {
        lastWalletKey.current = walletKey;
        setRecipientAddress(walletAccount);
        setLastTransferDebug(null);
        appendLog(`connected ${shortAddress(walletAccount)}`);
      }

      if (nextChainId !== BigInt(SEPOLIA_CHAIN_ID)) {
        setProfile(null);
        setRegistryOwnerHash(null);
        setAuthPolicyOwnerHash(null);
        setAuthRegistered(false);
        setNotes([]);
        setStatus('Switch wallet to Sepolia to use the demo.');
        return;
      }

      if (!configured) return;
      const key = profileStorageKey(SEPOLIA_CHAIN_ID, demoAddresses.pool, walletAccount);
      const stored = loadDemoProfile(window.localStorage, key);
      if (cancelled) return;
      setProfile(stored);
      if (stored === null) {
        setRegistryOwnerHash(null);
        setAuthPolicyOwnerHash(null);
        setAuthRegistered(false);
        setNotes([]);
        setStatus(`Connected ${shortAddress(walletAccount)} on Sepolia.`);
        return;
      }

      appendLog('loaded local profile');
      await refreshSetupState(wallet, walletAccount, stored);
      if (cancelled) return;
      await scanNotesForProfile(wallet, stored);
    }

    syncConnectedWallet().catch((error) => {
      if (!cancelled) setStatus(error instanceof Error ? error.message : String(error));
    });

    return () => {
      cancelled = true;
    };
  }, [connectedAddress, connectedAccountChainId, configuredChainId, walletClient, configured]);

  async function run(action: BusyAction, work: () => Promise<void>) {
    setBusy(action);
    try {
      await work();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy('');
    }
  }

  function appendLog(line: string) {
    setLog((existing) => [line, ...existing].slice(0, 10));
  }

  function recordActivity(walletAccount: HexAddress, item: ActivityItem) {
    setActivity((existing) => {
      const next = [item, ...existing.filter((candidate) => candidate.id !== item.id)].slice(0, 24);
      saveActivity(window.localStorage, activityStorageKey(walletAccount), next);
      return next;
    });
  }

  function updateActivity(
    walletAccount: HexAddress,
    id: string,
    patch: Partial<Pick<ActivityItem, 'status' | 'txHash' | 'timestamp'>>,
  ) {
    setActivity((existing) => {
      const next = existing.map((item) => item.id === id ? { ...item, ...patch } : item);
      saveActivity(window.localStorage, activityStorageKey(walletAccount), next);
      return next;
    });
  }

  async function createOrSignProfile() {
    await run('profile', async () => {
      const { wallet, walletAccount } = requireWallet();
      if (!configured) throw new Error('Configure deployment addresses first.');
      const key = profileStorageKey(SEPOLIA_CHAIN_ID, demoAddresses.pool, walletAccount);
      const derivationMessage = profileDerivationMessage({
        chainId: SEPOLIA_CHAIN_ID,
        poolAddress: demoAddresses.pool,
        account: walletAccount,
        authVerifier: demoAddresses.authVerifier,
      });
      const signature = await signProfileMessage(wallet, walletAccount, derivationMessage);
      const draft = createDeterministicDemoProfile({
        chainId: SEPOLIA_CHAIN_ID,
        poolAddress: demoAddresses.pool,
        account: walletAccount,
        authVerifier: demoAddresses.authVerifier,
        derivationSignature: signature,
      });
      const signed = finalizeDeterministicProfileAuth(draft, {
        authVerifier: demoAddresses.authVerifier,
        profileSignature: signature,
      });
      saveDemoProfile(window.localStorage, key, signed);
      setProfile(signed);
      setLastTransferDebug(null);
      await refreshSetupState(wallet, walletAccount, signed);
      setStatus('Local profile signed and saved in this browser.');
      appendLog(`profile signed ${shortField(BigInt(signed.ownerNullifierKeyHash))}`);
    });
  }

  async function publishProfile() {
    await run('publish', async () => {
      const { wallet, walletAccount, localProfile } = requireProfile();
      const ownerHash = BigInt(localProfile.ownerNullifierKeyHash);
      const existing = await readRecipient(wallet, demoAddresses.recipientRegistry, walletAccount);
      if (existing.registered) {
        setRegistryOwnerHash(existing.ownerNullifierKeyHash);
        if (existing.ownerNullifierKeyHash === ownerHash) {
          setStatus('Recipient keys are already published for this profile.');
          return;
        }
        throw new Error(`This wallet already published recipient keys for another local profile (${shortField(existing.ownerNullifierKeyHash)}). Clear old keys, or restore the browser profile that owns that hash.`);
      }
      const tx = await sendPublishRecipient(
        wallet,
        walletAccount,
        demoAddresses.recipientRegistry,
        localProfile.ownerNullifierKeyHash,
        profilePublicKey(localProfile),
      );
      appendLog(`publish tx ${shortHash(tx)}`);
      await waitForTransactionReceipt(wallet, tx);
      setRegistryOwnerHash(ownerHash);
      setStatus('Recipient profile published to the demo registry.');
    });
  }

  async function clearPublishedProfile() {
    await run('clear', async () => {
      const { wallet, walletAccount } = requireWallet();
      const existing = await readRecipient(wallet, demoAddresses.recipientRegistry, walletAccount);
      if (!existing.registered) {
        setRegistryOwnerHash(null);
        setStatus('No recipient keys are published for this wallet.');
        return;
      }
      const tx = await sendClearRecipient(wallet, walletAccount, demoAddresses.recipientRegistry);
      appendLog(`clear keys tx ${shortHash(tx)}`);
      await waitForTransactionReceipt(wallet, tx);
      setRegistryOwnerHash(null);
      setAuthRegistered(false);
      setStatus('Old recipient keys cleared. Publish the current profile keys next.');
    });
  }

  async function registerAuthPolicy() {
    await run('auth', async () => {
      const { wallet, walletAccount, localProfile } = requireProfile();
      if (!authReady) throw new Error('Auth verifier is not deployed/configured yet.');
      if (!hasProfileAuth(localProfile)) throw new Error('Sign the local profile before registering auth policy.');
      const ownerHash = BigInt(localProfile.ownerNullifierKeyHash);
      const existing = await readAuthPolicyEntry(wallet, demoAddresses.pool, walletAccount);
      if (existing.registered) {
        setAuthPolicyOwnerHash(existing.ownerNullifierKeyHash);
        if (existing.ownerNullifierKeyHash !== ownerHash) {
          throw new Error(`This wallet already registered pool auth for another local profile (${shortField(existing.ownerNullifierKeyHash)}). Restore that browser profile, switch wallet accounts, or deploy a fresh demo pool.`);
        }
        if (
          existing.noteSecretSeedHash === BigInt(localProfile.noteSecretSeedHash)
            && existing.policySetCommitment === BigInt(localProfile.policySetCommitment)
        ) {
          setAuthRegistered(true);
          setStatus('Auth policy is already registered for this profile.');
          return;
        }
      }
      const tx = await sendSetAuthPolicy(
        wallet,
        walletAccount,
        demoAddresses.pool,
        localProfile.ownerNullifierKeyHash,
        localProfile.noteSecretSeedHash,
        localProfile.policySetCommitment,
      );
      appendLog(`auth policy tx ${shortHash(tx)}`);
      await waitForTransactionReceipt(wallet, tx);
      const nextRoots = await readCurrentRoots(wallet, demoAddresses.pool);
      setRoots(nextRoots);
      setAuthPolicyOwnerHash(ownerHash);
      setAuthRegistered(true);
      setStatus('Auth policy registered in the demo pool.');
    });
  }

  async function depositToPool() {
    await run('deposit', async () => {
      const { wallet, walletAccount, localProfile } = requireProfile();
      if (!setupComplete) throw new Error('Finish setup before depositing.');
      const amount = parseEth(depositAmount);
      if (amount === 0n) throw new Error('Deposit amount must be greater than zero.');
      const noteSecret = randomField();
      const ownerHash = profileField(localProfile, 'ownerNullifierKeyHash');
      const noteOwnerCommitment = ownerCommitment(ownerHash, noteSecret);
      const body = noteBodyCommitment(noteOwnerCommitment, amount, ZERO_ADDRESS);
      const encrypted = await prepareEncryptedOutputNoteData({
        recipient: profilePublicKey(localProfile),
        payload: {
          kind: 'deposit',
          chainId: SEPOLIA_CHAIN_ID,
          poolAddress: demoAddresses.pool,
          tokenAddress: ZERO_ADDRESS,
          amount,
          ownerNullifierKeyHash: ownerHash,
          noteSecret,
          noteBodyCommitment: body,
          memo: 'self deposit',
        },
      });
      const tx = await sendDeposit(
        wallet,
        walletAccount,
        demoAddresses.pool,
        ZERO_ADDRESS,
        amount,
        noteOwnerCommitment,
        encrypted.outputNoteData,
      );
      const activityId = activityIdFor('deposit', tx);
      recordActivity(walletAccount, {
        id: activityId,
        kind: 'deposit',
        status: 'pending',
        amountWei: amount.toString(10),
        timestamp: Date.now(),
        txHash: tx,
      });
      appendLog(`deposit tx ${shortHash(tx)}`);
      try {
        await waitForTransactionReceipt(wallet, tx);
        updateActivity(walletAccount, activityId, { status: 'confirmed' });
      } catch (error) {
        updateActivity(walletAccount, activityId, { status: 'failed' });
        throw error;
      }
      setStatus('Deposit confirmed. Refreshing private balance.');
      await scanNotesForProfile(wallet, localProfile);
    });
  }

  async function refreshSetupState(
    wallet: Eip1193Provider,
    walletAccount: HexAddress,
    localProfile: DemoProfile,
  ): Promise<{ recipientPublished: boolean; authRegistered: boolean }> {
    const ownerHash = BigInt(localProfile.ownerNullifierKeyHash);
    const noteSeedHash = BigInt(localProfile.noteSecretSeedHash);
    const policySet = hasProfileAuth(localProfile) ? BigInt(localProfile.policySetCommitment) : 0n;
    const [recipientRecord, authEntry] = await Promise.all([
      readRecipient(wallet, demoAddresses.recipientRegistry, walletAccount),
      readAuthPolicyEntry(wallet, demoAddresses.pool, walletAccount),
    ]);
    const nextRegistryOwnerHash = recipientRecord.registered ? recipientRecord.ownerNullifierKeyHash : null;
    const nextRecipientPublished = nextRegistryOwnerHash === ownerHash;
    const nextAuthRegistered = hasProfileAuth(localProfile)
      && authEntry.registered
      && authEntry.ownerNullifierKeyHash === ownerHash
      && authEntry.noteSecretSeedHash === noteSeedHash
      && authEntry.policySetCommitment === policySet;
    setRegistryOwnerHash(nextRegistryOwnerHash);
    setAuthPolicyOwnerHash(authEntry.registered ? authEntry.ownerNullifierKeyHash : null);
    setAuthRegistered(nextAuthRegistered);
    return {
      recipientPublished: nextRecipientPublished,
      authRegistered: nextAuthRegistered,
    };
  }

  async function scanNotesForProfile(
    wallet: Eip1193Provider,
    localProfile: DemoProfile,
  ): Promise<IndexedNote[]> {
    const [nextRoots, deposits, transacts] = await Promise.all([
      readCurrentRoots(wallet, demoAddresses.pool),
      getPoolDepositLogs(wallet, demoAddresses.pool, deploymentBlock),
      getPoolTransactLogs(wallet, demoAddresses.pool, deploymentBlock),
    ]);
    setRoots(nextRoots);
    const indexer = new SepoliaDemoIndexer({
      chainId: SEPOLIA_CHAIN_ID,
      poolAddress: demoAddresses.pool,
      candidates: [{ id: 'local profile', secretKey: profileSecretKey(localProfile) }],
    });
    for (const deposit of deposits) {
      await indexer.ingestDeposit(deposit);
    }
    for (const transact of transacts) {
      await indexer.ingestTransact(transact);
    }
    const indexed = markSpentNotes(indexer.store.all(), transacts, localProfile);
    setNotes(indexed);
    const nextBalance = sumSpendableAmount(indexed);
    setStatus(`Private balance refreshed: ${formatEth(nextBalance)} ETH spendable.`);
    appendLog(`scan found ${indexed.length} pool outputs`);
    return indexed;
  }

  async function sendPrivateTransfer() {
    await run('transfer', async () => {
      setTransferStartedAt(Date.now());
      setTransferElapsedMs(0);
      setTransferPhase('Checking private balance.');
      setLastTransferDebug(null);
      const phase = (message: string) => {
        setTransferPhase(message);
        setStatus(message);
      };
      try {
        const { wallet, walletAccount, localProfile } = requireProfile();
        if (!authReady) throw new Error('Auth verifier is not deployed/configured yet.');
        if (!hasProfileAuth(localProfile)) throw new Error('Sign and register the local auth profile before sending.');
        const setup = setupComplete
          ? { recipientPublished, authRegistered }
          : await refreshSetupState(wallet, walletAccount, localProfile);
        if (!setup.recipientPublished || !setup.authRegistered) throw new Error('Finish setup before sending.');
        const amount = parseEth(transferAmount);
        if (amount === 0n) throw new Error('Transfer amount must be greater than zero.');
        phase('Scanning private balance.');
        const indexed = await scanNotesForProfile(wallet, localProfile);
        const inputNote = chooseSpendableNote(
          indexed.filter((note) => note.status === 'decrypted' && (note.payload?.amount ?? 0n) > 0n),
          amount,
        );
        if (inputNote === undefined) {
          throw new Error(`No single spendable note covers ${formatEth(amount)} ETH. Deposit a larger note or transfer a smaller amount.`);
        }
        await assertSelectedNoteUnspent(wallet, localProfile, inputNote);
        const recipient = normalizeAddressInput(recipientAddress);
        phase('Looking up recipient encryption keys.');
        const registryRecord = await readRecipient(wallet, demoAddresses.recipientRegistry, recipient);
        if (!registryRecord.registered) throw new Error('Recipient is not published in the demo registry.');
        const nextRoots = await readCurrentRoots(wallet, demoAddresses.pool);
        setRoots(nextRoots);
        phase('Preparing encrypted outputs.');
        const transfer = await prepareDemoPrivateTransfer({
          chainId: SEPOLIA_CHAIN_ID,
          poolAddress: demoAddresses.pool,
          authVerifier: demoAddresses.authVerifier,
          sender: localProfile,
          inputNote,
          recipient: {
            ownerNullifierKeyHash: registryRecord.ownerNullifierKeyHash,
            publicKey: registryRecord.publicKey,
          },
          amount,
          noteCommitmentRoot: nextRoots.noteCommitmentRoot,
          authPolicyRoot: nextRoots.authPolicyRoot,
        });
        if (!transfer.proverStatus.ready) throw new Error(transfer.proverStatus.reason);
        setLastTransferDebug({
          inputLeaf: inputNote.leafIndex.toString(),
          inputAmountWei: (inputNote.payload?.amount ?? 0n).toString(10),
          transferAmountWei: transfer.transferAmount.toString(10),
          recipient,
          changeAmountWei: transfer.changeAmount.toString(10),
          intentReplayId: transfer.intentReplayId,
          transactionIntentDigest: transfer.transactionIntentDigest,
          recipientOutputHash: transfer.outputSlots[0].outputNoteDataHash,
          changeOutputHash: transfer.outputSlots[1].outputNoteDataHash,
          dummyOutputHash: transfer.outputSlots[2].outputNoteDataHash,
        });
        appendLog(`prepared transfer ${formatEth(transfer.transferAmount)} ETH`);

        const typedData = authIntentTypedData(transfer, walletAccount);
        phase('Requesting wallet signature.');
        const authSignature = await wallet.request({
          method: 'eth_signTypedData_v4',
          params: [walletAccount, jsonStringifyTypedData(typedData)],
        });
        if (typeof authSignature !== 'string') throw new Error('Wallet returned invalid auth signature.');
        const recoveredAuthSigner = recoverPublicKey(
          authIntentDigest(transfer, walletAccount),
          authSignature,
        ).address;
        if (recoveredAuthSigner !== walletAccount) {
          throw new Error(`Wallet returned an EIP-712 signature from ${recoveredAuthSigner}, but this profile is for ${walletAccount}. Switch the wallet to that signing account and reconnect, or create/register a profile with the account that signs typed data.`);
        }

        phase('Indexing Sepolia events for browser proving.');
        const [proofRoots, deposits, transacts, authEvents] = await Promise.all([
          readCurrentRoots(wallet, demoAddresses.pool),
          getPoolDepositLogs(wallet, demoAddresses.pool, deploymentBlock),
          getPoolTransactLogs(wallet, demoAddresses.pool, deploymentBlock),
          getPoolAuthPolicySetLogs(wallet, demoAddresses.pool, deploymentBlock),
        ]);
        setRoots(proofRoots);

        phase('Generating browser proofs.');
        const proofJson = await proveTransferInBrowser({
          chainId: SEPOLIA_CHAIN_ID,
          poolAddress: demoAddresses.pool,
          authVerifier: demoAddresses.authVerifier,
          account: walletAccount,
          roots: proofRoots,
          profile: localProfile,
          inputNote,
          preparedTransfer: transfer,
          authSignature: authSignature as `0x${string}`,
          deposits,
          transacts,
          authEvents,
        }, (message) => {
          phase(message);
        });
        setLastTransferDebug((existing) => existing === null ? existing : {
          ...existing,
          poolProveMs: proofJson.timings.poolProveMs,
          authProveMs: proofJson.timings.authProveMs,
        });
        appendLog(`proved pool ${proofJson.timings.poolProveMs}ms auth ${proofJson.timings.authProveMs}ms`);

        phase('Submitting private transfer transaction.');
        const tx = await sendTransact(wallet, walletAccount, demoAddresses.pool, {
          poolProof: proofJson.poolProofHex,
          authProof: proofJson.authProofHex,
          publicInputs: revivePublicInputs(proofJson.publicInputs),
          outputNoteData0: proofJson.outputNoteData0Hex,
          outputNoteData1: proofJson.outputNoteData1Hex,
          outputNoteData2: proofJson.outputNoteData2Hex,
        });
        const activityId = activityIdFor('transfer', tx);
        recordActivity(walletAccount, {
          id: activityId,
          kind: 'transfer',
          status: 'pending',
          amountWei: amount.toString(10),
          timestamp: Date.now(),
          txHash: tx,
          recipient,
        });
        setLastTransferDebug((existing) => existing === null ? existing : { ...existing, txHash: tx });
        appendLog(`transact tx ${shortHash(tx)}`);
        phase('Waiting for confirmation.');
        try {
          await waitForTransactionReceipt(wallet, tx, { timeoutMs: 240_000 });
          updateActivity(walletAccount, activityId, { status: 'confirmed' });
        } catch (error) {
          updateActivity(walletAccount, activityId, { status: 'failed' });
          throw error;
        }
        phase('Refreshing private balance.');
        await scanNotesForProfile(wallet, localProfile);
        setStatus(`Sent ${formatEth(amount)} ETH privately to ${shortAddress(recipient)}.`);
      } finally {
        setTransferStartedAt(null);
        setTransferPhase('');
      }
    });
  }

  function requireWallet(): { wallet: Eip1193Provider; walletAccount: HexAddress } {
    if (provider === null || account === '') throw new Error('Connect a wallet first.');
    if (chainId !== BigInt(SEPOLIA_CHAIN_ID)) throw new Error('Switch wallet to Sepolia to use the demo.');
    return { wallet: provider, walletAccount: account };
  }

  function requireProfile(): { wallet: Eip1193Provider; walletAccount: HexAddress; localProfile: DemoProfile } {
    const walletState = requireWallet();
    if (profile === null) throw new Error('Create and sign a local profile first.');
    return { ...walletState, localProfile: profile };
  }

  async function assertSelectedNoteUnspent(
    wallet: Eip1193Provider,
    localProfile: DemoProfile,
    note: IndexedNote,
  ): Promise<void> {
    if (note.status === 'spent') throw new Error(`Selected note leaf ${note.leafIndex.toString()} is already spent. Scan notes or deposit a fresh note.`);
    const noteNullifier = nullifier(note.noteCommitment, profileField(localProfile, 'ownerNullifierKey'));
    if (await readNullifierSpent(wallet, demoAddresses.pool, noteNullifier)) {
      setNotes((existing) => existing.map((candidate) => (
        candidate.id === note.id ? { ...candidate, status: 'spent' as const } : candidate
      )));
      throw new Error(`Selected note leaf ${note.leafIndex.toString()} is already spent on-chain. Scan notes or deposit a fresh note.`);
    }
  }

  return (
    <main>
      <header className="topbar">
        <div className="brandBlock">
          <div className="eyebrow">Sepolia demo</div>
          <h1>Private transfer app demo</h1>
          <p>
            This is an example app built on <a href="https://eip8182.com" target="_blank" rel="noreferrer">EIP-8182</a>. It lets you set up a wallet-authenticated profile, publish post-quantum receive keys, shield Sepolia ETH, and prove a private transfer entirely in this browser.
          </p>
          <div className="heroTags" aria-label="Demo capabilities">
            <span>ML-KEM-768 delivery</span>
            <span>ECDSA auth method</span>
            <span>WASM proving</span>
          </div>
        </div>
        <div className="walletControl">
          <ConnectButton showBalance={false} chainStatus="icon" accountStatus="address" />
        </div>
      </header>

      {!configured && (
        <section className="notice">
          Deployment addresses are not configured. Update <code>app/src/demoConfig.ts</code> after the Sepolia demo contracts are deployed.
        </section>
      )}
      {configured && !authReady && (
        <section className="notice">
          The auth verifier address is not configured, so private transfer submission is disabled.
        </section>
      )}

      <section className="protocolSplit" aria-label="Protocol versus demo app choices">
        <div className="protocolSplitHeader">
          <span>Protocol vs app</span>
          <p>EIP-8182 defines the shared pool and proof interface. This demo makes opinionated product choices around that core.</p>
        </div>
        <div className="protocolRows">
          <div className="protocolColumnHeader" aria-hidden="true">
            <span>Area</span>
            <span>Protocol</span>
            <span>This app</span>
          </div>
          <div className="protocolRow">
            <strong>Note payload encryption</strong>
            <p>Output note data is opaque bytes; the pool only checks its hash.</p>
            <p>Uses a public registry to find receive keys, then encrypts note details with ML-KEM-768 plus X25519.</p>
          </div>
          <div className="protocolRow">
            <strong>Auth method</strong>
            <p>Users can register, rotate, or revoke permissionless auth methods.</p>
            <p>Uses ECDSA wallet signatures proven with UltraHonk. That flow is user-friendly, but costs more gas than a leaner auth method.</p>
          </div>
          <div className="protocolRow">
            <strong>Proving</strong>
            <p>Requires valid pool and auth proofs, but does not require where they are generated.</p>
            <p>Proves locally in browser WASM so there is no prover server.</p>
          </div>
          <div className="protocolRow">
            <strong>Transaction sender</strong>
            <p>Hides in-pool sender, recipient, amount, spent note, and change.</p>
            <p>Submits from your wallet directly, so relayers or AA would be needed to hide the public tx sender.</p>
          </div>
        </div>
      </section>

      <section className="workflow" aria-label="Demo workflow">
        <section className={`stepPanel ${setupComplete ? 'complete' : ''}`}>
          <div className="stepNumber">1</div>
          <div className="stepBody">
            <div className="stepHeader">
              <div>
                <span className="stepKicker">Identity and delivery</span>
                <h2>Set up your private profile</h2>
              </div>
              <span>{setupComplete ? 'ready' : 'required'}</span>
            </div>
            <p className="stepIntro">
              One wallet signature deterministically creates this demo profile. It gives the browser private spending material and receive keys. The public keys are posted only so this demo can discover recipients without invite strings.
            </p>
            {setupComplete ? (
              <details className="setupDetails">
                <summary>Profile ready</summary>
                <dl className="addresses compact">
                  <div><dt>Owner hash</dt><dd>{profile ? shortField(BigInt(profile.ownerNullifierKeyHash)) : '-'}</dd></div>
                  <div><dt>PQ key</dt><dd>{profile ? profile.encryptionPublicKey.keyId : '-'}</dd></div>
                </dl>
              </details>
            ) : (
              <div className="setupList">
                <div className="setupRow">
                  <div>
                    <strong>Sign local profile</strong>
                    <span>Derives your spend key, note-secret seed, and receive keys from a wallet signature. The secrets stay in local storage.</span>
                  </div>
                  <span className="setupState">{profileSigned ? 'signed' : profileReady ? 'created' : 'needed'}</span>
                  <button type="button" onClick={createOrSignProfile} disabled={!walletReady || !configured || busy !== ''}>
                    {profileSigned ? 'Re-sign' : profileReady ? 'Sign profile' : 'Create profile'}
                  </button>
                </div>
                <div className="setupRow">
                  <div>
                    <strong>Post PQ receive keys</strong>
                    <span>Publishes your ML-KEM-768 and X25519 public keys to the demo registry. Senders use them for trial-encryptable note delivery; the pool still treats note data as opaque bytes.</span>
                  </div>
                  <span className="setupState">{recipientProfileMismatch ? 'different profile' : recipientPublished ? 'published' : 'needed'}</span>
                  <div className="setupActions">
                    <button type="button" onClick={publishProfile} disabled={!profileSigned || recipientPublished || recipientProfileMismatch || busy !== ''}>
                      Post keys
                    </button>
                    {recipientProfileMismatch && (
                      <button type="button" onClick={clearPublishedProfile} disabled={busy !== ''}>
                        Clear old keys
                      </button>
                    )}
                  </div>
                </div>
                {recipientProfileMismatch && (
                  <p className="inlineWarning">
                    This wallet has registry keys for owner hash {shortField(registryOwnerHash)}. Clear old keys only if you do not need this address to receive notes for that old browser profile.
                  </p>
                )}
                <div className="setupRow">
                  <div>
                    <strong>Register auth method</strong>
                    <span>Records a hidden ECDSA auth-policy commitment in the pool. Later, the wallet signs the transfer intent and the browser proves that signature. Real wallets can rotate or deactivate methods by updating the policy set.</span>
                  </div>
                  <span className="setupState">{authPolicyProfileMismatch ? 'different profile' : authRegistered ? 'registered' : 'needed'}</span>
                  <button type="button" onClick={registerAuthPolicy} disabled={!profileSigned || !recipientPublished || authRegistered || authPolicyProfileMismatch || !authReady || busy !== ''}>
                    Register auth
                  </button>
                </div>
                {authPolicyProfileMismatch && (
                  <p className="inlineWarning">
                    This wallet has pool auth for owner hash {shortField(authPolicyOwnerHash)}. The owner hash is permanent for this address; restore that browser profile, switch wallet accounts, or use a fresh demo pool. Auth methods can be rotated, but that does not replace the registered owner hash.
                  </p>
                )}
              </div>
            )}
          </div>
        </section>

        <section className="stepPanel">
          <div className="stepNumber">2</div>
          <div className="stepBody">
            <div className="stepHeader">
              <div>
                <span className="stepKicker">Private balance</span>
                <h2>Shield ETH</h2>
              </div>
              <span>Sepolia ETH</span>
            </div>
            <p className="stepIntro">
              Shielding creates a note owned by your posted keys. Sepolia sees the depositor and deposit amount; your browser scans events and decrypts only the note payloads it can spend.
            </p>
            <label>
              Amount
              <input value={depositAmount} onChange={(event) => setDepositAmount(event.target.value)} inputMode="decimal" />
            </label>
            <button type="button" onClick={depositToPool} disabled={!setupComplete || busy !== ''}>
              Shield ETH
            </button>
          </div>
        </section>

        <section className="stepPanel">
          <div className="stepNumber">3</div>
          <div className="stepBody">
            <div className="stepHeader">
              <div>
                <span className="stepKicker">Spend privately</span>
                <h2>Send a private transfer</h2>
              </div>
              <span>{formatEth(privateBalance)} ETH private</span>
            </div>
            <p className="stepIntro">
              Send looks up app-layer receive keys, encrypts the recipient and change note details, asks the wallet to sign the minimal intent, proves pool plus auth in WASM, and submits one transaction. Without a relayer, your address is still visible as the transaction sender.
            </p>
            <label>
              Recipient
              <input
                value={recipientAddress}
                onChange={(event) => setRecipientAddress(event.target.value)}
                placeholder="0x..."
              />
              <span className="fieldHint">
                Demo recipients must have posted receive keys first. We prefill your connected address so you can send to yourself; use 0xc2172a6315c1d7f6855768f843c420ebb36eda97 or another registered Sepolia address to send to someone else.
              </span>
            </label>
            <label>
              Amount
              <input
                value={transferAmount}
                onChange={(event) => setTransferAmount(event.target.value)}
                inputMode="decimal"
              />
            </label>
            <div className="selectionLine">
              {transferSelectionText(selectedNote, transferAmountWei, spendableNotes)}
            </div>
            <div className="actions">
              <button
                className="primaryAction"
                type="button"
                onClick={sendPrivateTransfer}
                disabled={!setupComplete || busy !== '' || selectedNote === undefined}
              >
                {busy === 'transfer' ? 'Sending' : 'Send'}
              </button>
            </div>
          </div>
        </section>
      </section>

      <section className={`statusLine ${busy === 'transfer' ? 'active' : ''}`}>
        <div className="statusTitle">
          <span>Live status</span>
          {busy && <strong>{busy}</strong>}
        </div>
        <p>{status}</p>
        {busy === 'transfer' && transferStartedAt !== null && (
          <div className="progressBox">
            <div className="progressHeader">
              <span>{transferPhase || 'Sending private transfer.'}</span>
              <span>{formatElapsed(transferElapsedMs)}</span>
            </div>
            <div className="progressTrack"><div /></div>
          </div>
        )}
      </section>

      <section className="panel activityPanel">
        <div className="panelHeader">
          <div>
            <span className="stepKicker">Local receipt trail</span>
            <h2>History</h2>
          </div>
          <span>{activity.length} local</span>
        </div>
        <div className="activityList">
          {activity.length === 0 && <div className="empty">No activity in this browser yet.</div>}
          {activity.map((item) => (
            <div className="activityRow" key={item.id}>
              <div>
                <strong>{activityTitle(item)}</strong>
                <span>{activitySubtitle(item)}</span>
              </div>
              <span className={`activityStatus ${item.status}`}>{item.status}</span>
              {item.txHash ? (
                <a href={sepoliaTxUrl(item.txHash)} target="_blank" rel="noreferrer">{shortHash(item.txHash)}</a>
              ) : (
                <span />
              )}
            </div>
          ))}
        </div>
      </section>

      <footer className="technicalFooter">
        <details>
          <summary>Technical details: contract addresses, proofs, notes, and logs</summary>
          <div className="technicalSections">
            <section>
              <h3>Runtime</h3>
              <dl className="addresses">
                <div><dt>Chain</dt><dd>{chainId === null ? 'wallet disconnected' : chainId.toString()}</dd></div>
                <div><dt>Pool</dt><dd>{demoAddresses.pool}</dd></div>
                <div><dt>Registry</dt><dd>{demoAddresses.recipientRegistry}</dd></div>
                <div><dt>Auth verifier</dt><dd>{authReady ? demoAddresses.authVerifier : 'not configured'}</dd></div>
                {roots !== null && (
                  <>
                    <div><dt>Note root</dt><dd>{shortField(roots.noteCommitmentRoot)}</dd></div>
                    <div><dt>Auth root</dt><dd>{shortField(roots.authPolicyRoot)}</dd></div>
                  </>
                )}
              </dl>
            </section>

            <section>
              <h3>Last transfer internals</h3>
              {lastTransferDebug === null ? (
                <div className="empty">No transfer prepared in this session.</div>
              ) : (
                <dl className="addresses">
                  <div><dt>Input leaf</dt><dd>{lastTransferDebug.inputLeaf} · {formatEth(BigInt(lastTransferDebug.inputAmountWei))} ETH</dd></div>
                  <div><dt>Recipient</dt><dd>{lastTransferDebug.recipient} · {formatEth(BigInt(lastTransferDebug.transferAmountWei))} ETH</dd></div>
                  <div><dt>Change</dt><dd>{formatEth(BigInt(lastTransferDebug.changeAmountWei))} ETH · {shortField(lastTransferDebug.changeOutputHash)}</dd></div>
                  <div><dt>Output hashes</dt><dd>{shortField(lastTransferDebug.recipientOutputHash)} · {shortField(lastTransferDebug.dummyOutputHash)}</dd></div>
                  <div><dt>Intent</dt><dd>{shortField(lastTransferDebug.intentReplayId)}</dd></div>
                  <div><dt>Digest</dt><dd>{shortField(lastTransferDebug.transactionIntentDigest)}</dd></div>
                  <div><dt>Proofs</dt><dd>{formatProofTimings(lastTransferDebug)}</dd></div>
                  <div><dt>Tx</dt><dd>{lastTransferDebug.txHash ? shortHash(lastTransferDebug.txHash) : '-'}</dd></div>
                </dl>
              )}
            </section>

            <section>
              <h3>Private notes</h3>
              <div className="technicalCounts">{ownedNotes.length} local · {encryptedNoteCount} encrypted · {spentNoteCount} spent</div>
              <div className="noteTable">
                <div className="noteRow heading"><span>Leaf</span><span>Status</span><span>Amount</span><span>Commitment</span></div>
                {ownedNotes.length === 0 && <div className="empty">No decrypted notes in this browser.</div>}
                {ownedNotes.map((note) => (
                  <div className="noteRow" key={note.id}>
                    <span>{note.leafIndex.toString()}</span>
                    <span>{noteStatusLabel(note.status)}</span>
                    <span>{note.payload ? `${formatEth(note.payload.amount)} ETH` : '-'}</span>
                    <span>{shortField(note.noteCommitment)}</span>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h3>Log</h3>
              <div className="log">
                {log.length === 0 && <div className="empty">No technical events yet.</div>}
                {log.map((line, index) => <div key={`${index}:${line}`}>{line}</div>)}
              </div>
            </section>
          </div>
        </details>
      </footer>
    </main>
  );
}

function activityStorageKey(account: HexAddress): string {
  return `eip8182-demo:activity:v1:${SEPOLIA_CHAIN_ID}:${demoAddresses.pool}:${account}`;
}

function activityIdFor(kind: ActivityItem['kind'], txHash: string): string {
  return `${kind}:${txHash.toLowerCase()}`;
}

function loadActivity(storage: Storage, key: string): ActivityItem[] {
  try {
    const raw = storage.getItem(key);
    if (raw === null) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isActivityItem).slice(0, 24);
  } catch {
    return [];
  }
}

function saveActivity(storage: Storage, key: string, activity: ActivityItem[]) {
  storage.setItem(key, JSON.stringify(activity.slice(0, 24)));
}

function isActivityItem(value: unknown): value is ActivityItem {
  if (value === null || typeof value !== 'object') return false;
  const item = value as Partial<ActivityItem>;
  const kindOk = item.kind === 'deposit' || item.kind === 'transfer';
  const statusOk = item.status === 'pending' || item.status === 'confirmed' || item.status === 'failed';
  const txOk = item.txHash === undefined || /^0x[0-9a-fA-F]+$/.test(item.txHash);
  const recipientOk = item.recipient === undefined || /^0x[0-9a-fA-F]{40}$/.test(item.recipient);
  return typeof item.id === 'string'
    && kindOk
    && statusOk
    && typeof item.amountWei === 'string'
    && /^[0-9]+$/.test(item.amountWei)
    && typeof item.timestamp === 'number'
    && Number.isFinite(item.timestamp)
    && txOk
    && recipientOk;
}

function normalizeAddressInput(value: string): HexAddress {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value.trim())) throw new Error('Recipient must be a 20-byte hex address.');
  return value.trim().toLowerCase() as HexAddress;
}

function parseEth(value: string): bigint {
  const trimmed = value.trim();
  if (!/^(0|[1-9][0-9]*)(\.[0-9]{0,18})?$/.test(trimmed)) throw new Error('Amount must be a decimal with at most 18 places.');
  const parts = trimmed.split('.');
  const whole = parts[0] ?? '0';
  const fraction = parts[1] ?? '';
  return BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
}

function parseEthOrNull(value: string): bigint | null {
  try {
    return parseEth(value);
  } catch {
    return null;
  }
}

function formatEth(wei: bigint): string {
  const whole = wei / 10n ** 18n;
  const fraction = (wei % 10n ** 18n).toString().padStart(18, '0').replace(/0+$/, '');
  return fraction ? `${whole.toString()}.${fraction}` : whole.toString();
}

function chooseSpendableNote(notes: IndexedNote[], amount: bigint | null): IndexedNote | undefined {
  if (amount === null || amount === 0n) return undefined;
  return [...notes]
    .sort((a, b) => {
      const amountA = a.payload?.amount ?? 0n;
      const amountB = b.payload?.amount ?? 0n;
      if (amountA !== amountB) return amountA < amountB ? -1 : 1;
      if (a.leafIndex !== b.leafIndex) return a.leafIndex < b.leafIndex ? -1 : 1;
      return a.outputIndex - b.outputIndex;
    })
    .find((note) => (note.payload?.amount ?? 0n) >= amount);
}

function sumSpendableAmount(notes: IndexedNote[]): bigint {
  return notes.reduce((sum, note) => (
    note.status === 'decrypted' ? sum + (note.payload?.amount ?? 0n) : sum
  ), 0n);
}

function transferSelectionText(
  note: IndexedNote | undefined,
  amount: bigint | null,
  spendableNotes: IndexedNote[],
): string {
  if (amount === null) return 'Enter a valid transfer amount.';
  if (amount === 0n) return 'Enter an amount greater than zero.';
  if (note !== undefined) return 'Ready to send from your private balance.';
  if (spendableNotes.length === 0) return 'No spendable private notes yet.';
  return `No single spendable note covers ${formatEth(amount)} ETH.`;
}

function activityTitle(item: ActivityItem): string {
  const amount = `${formatEth(BigInt(item.amountWei))} ETH`;
  return item.kind === 'deposit' ? `Deposit ${amount}` : `Send ${amount}`;
}

function activitySubtitle(item: ActivityItem): string {
  const time = formatTimestamp(item.timestamp);
  if (item.kind === 'transfer' && item.recipient) return `To ${shortAddress(item.recipient)} · ${time}`;
  return `Private balance · ${time}`;
}

function formatTimestamp(timestamp: number): string {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(timestamp));
}

function sepoliaTxUrl(txHash: string): string {
  return `https://sepolia.etherscan.io/tx/${txHash}`;
}

function formatElapsed(milliseconds: number): string {
  return `${(milliseconds / 1000).toFixed(1)}s`;
}

function formatProofTimings(debug: TransferDebug): string {
  if (debug.poolProveMs === undefined || debug.authProveMs === undefined) return '-';
  return `pool ${formatElapsed(debug.poolProveMs)} · auth ${formatElapsed(debug.authProveMs)}`;
}

function noteStatusLabel(status: IndexedNote['status']): string {
  if (status === 'decrypted') return 'spendable';
  if (status === 'pending') return 'encrypted';
  return status;
}

function shortAddress(address: string): string {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function shortHash(hash: string): string {
  return `${hash.slice(0, 10)}...${hash.slice(-6)}`;
}

function shortField(value: bigint): string {
  const hex = fieldToHex(value);
  return `${hex.slice(0, 10)}...${hex.slice(-6)}`;
}

function markSpentNotes(
  notes: IndexedNote[],
  transacts: ShieldedPoolTransactEvent[],
  localProfile: DemoProfile,
): IndexedNote[] {
  const ownerNullifierKey = profileField(localProfile, 'ownerNullifierKey');
  const spentNullifiers = new Set<string>();
  for (const event of transacts) {
    if (event.nullifier0 !== undefined) spentNullifiers.add(fieldBigInt(event.nullifier0).toString(10));
    if (event.nullifier1 !== undefined) spentNullifiers.add(fieldBigInt(event.nullifier1).toString(10));
  }
  return notes.map((note) => {
    if (note.status !== 'decrypted') return note;
    const noteNullifier = nullifier(note.noteCommitment, ownerNullifierKey);
    return spentNullifiers.has(noteNullifier.toString(10))
      ? { ...note, status: 'spent' as const }
      : note;
  });
}

function fieldBigInt(value: bigint | number | string): bigint {
  return typeof value === 'bigint' ? value : BigInt(value);
}

function revivePublicInputs(input: BrowserProverResponse['publicInputs']): DemoPoolPublicInputs {
  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => [key, BigInt(value)]),
  ) as unknown as DemoPoolPublicInputs;
}

const queryClient = new QueryClient();

createRoot(document.getElementById('root')!).render(
  <WagmiProvider config={rainbowWagmiConfig}>
    <QueryClientProvider client={queryClient}>
      <RainbowKitProvider
        theme={lightTheme({
          accentColor: '#050505',
          accentColorForeground: '#faff00',
          borderRadius: 'small',
          fontStack: 'system',
        })}
      >
        <App />
      </RainbowKitProvider>
    </QueryClientProvider>
  </WagmiProvider>,
);
