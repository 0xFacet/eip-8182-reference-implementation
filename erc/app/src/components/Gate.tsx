import { ConnectButton } from "@rainbow-me/rainbowkit";
import type { ReactNode } from "react";

/** A soft lock prompt for sections that need a wallet + a registered identity. */
export function Gate({ reason, children }: { reason: "connect" | "identity" | "deployment"; children?: ReactNode }) {
  const copy = {
    connect: { title: "Connect a wallet", body: "This is a vault. Connect an anvil account to continue." },
    identity: { title: "Set up your privacy identity", body: "Derive your shielded keys under Identity before using the pools." },
    deployment: { title: "Unsupported network", body: "Switch to a supported network — anvil dev chain (31337) or Sepolia (11155111) — to reach the deployed contracts." },
  }[reason];
  return (
    <div className="gate">
      <div className="gate-glyph" aria-hidden>◌</div>
      <h2 className="gate-title">{copy.title}</h2>
      <p className="gate-body">{copy.body}</p>
      {reason === "connect" ? <ConnectButton /> : null}
      {children}
    </div>
  );
}
