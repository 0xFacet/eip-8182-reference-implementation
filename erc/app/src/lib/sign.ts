// Sign the 20-field EIP-712 PrivateTransferIntent with the connected wallet and
// recover the secp256k1 public key coordinates the Noir auth circuit needs. Uses
// the wallet's own signTypedData — no private key ever leaves the wallet.

import { recoverPublicKey } from "viem";
import type { Account, WalletClient } from "viem";
import { EIP712_TYPES, eip712Domain, hashPrivateTransferIntent, intentMessage } from "../../../sdk/src/eip712.ts";
import type { SignedIntent } from "../../../sdk/src/eip712.ts";
import type { IntentFields } from "../../../sdk/src/derivations.ts";
import { parseSignature } from "viem";

export function makeIntentSigner(wallet: WalletClient, account: Account) {
  return async function signIntent(fields: IntentFields, policyDataHash: bigint): Promise<SignedIntent> {
    const domain = eip712Domain(fields.executionChainId, fields.poolAddress);
    const message = intentMessage(fields, policyDataHash);
    const digest = hashPrivateTransferIntent(fields, policyDataHash);
    const signature = await wallet.signTypedData({
      account,
      domain,
      types: EIP712_TYPES,
      primaryType: "PrivateTransferIntent",
      message,
    });
    const parsed = parseSignature(signature);
    const pub = await recoverPublicKey({ hash: digest, signature }); // 0x04 || x || y
    return {
      digest,
      signature,
      r: parsed.r,
      s: parsed.s,
      v: Number(parsed.v ?? (parsed.yParity === 0 ? 27n : 28n)),
      publicKeyX: `0x${pub.slice(4, 68)}`,
      publicKeyY: `0x${pub.slice(68, 132)}`,
    };
  };
}
