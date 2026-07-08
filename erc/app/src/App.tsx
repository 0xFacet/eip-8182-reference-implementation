import { useState } from "react";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { useAccount } from "wagmi";
import { AnimatePresence, motion } from "framer-motion";
import { ANVIL_CHAIN_ID, SEPOLIA_CHAIN_ID, getDeployment } from "./config/deployment.ts";
import { useIdentity } from "./state/identity.tsx";
import { Overview } from "./sections/Overview.tsx";
import { Learn } from "./sections/Learn.tsx";
import { Identity } from "./sections/Identity.tsx";
import { Pools } from "./sections/Pools.tsx";
import { Send } from "./sections/Send.tsx";
import { Move } from "./sections/Move.tsx";
import { Activity } from "./sections/Activity.tsx";

type SectionId = "overview" | "learn" | "identity" | "pools" | "send" | "move" | "activity";

const SECTIONS: Array<{ id: SectionId; label: string; gated: boolean }> = [
  { id: "overview", label: "Overview", gated: false },
  { id: "learn", label: "How it works", gated: false },
  { id: "identity", label: "Identity", gated: false },
  { id: "pools", label: "Pools", gated: true },
  { id: "send", label: "Send", gated: true },
  { id: "move", label: "Move", gated: true },
  { id: "activity", label: "Activity", gated: true },
];

export function App() {
  const [section, setSection] = useState<SectionId>("overview");
  const { isConnected, chainId } = useAccount();
  const { secrets } = useIdentity();
  const deployment = getDeployment(chainId);
  const hasIdentity = Boolean(secrets);
  const deploymentLabel =
    deployment?.chainId === ANVIL_CHAIN_ID ? "anvil" : deployment?.chainId === SEPOLIA_CHAIN_ID ? "sepolia" : "configured";

  const locked = (s: (typeof SECTIONS)[number]) => s.gated && (!isConnected || !hasIdentity || !deployment);

  return (
    <div className="app-root">
      <div className="grain" aria-hidden />
      <div className="vignette" aria-hidden />

      <header className="topbar">
        <div className="brand" onClick={() => setSection("overview")} role="button" tabIndex={0}>
          <span className="brand-mark" aria-hidden>
            <span className="brand-ring" />
            <span className="brand-dot" />
          </span>
          <span className="brand-text">
            Shielded<span className="brand-accent">Terminal</span>
          </span>
        </div>
        <div className="topbar-right">
          <a className="topbar-link" href="/spec.html" target="_blank" rel="noreferrer">
            Draft spec ↗
          </a>
          {deployment ? (
            <span className="chain-badge">{deploymentLabel} · {deployment.chainId}</span>
          ) : chainId ? (
            <span className="chain-badge warn">unknown chain · {chainId}</span>
          ) : null}
          <ConnectButton chainStatus="none" accountStatus="address" showBalance={false} />
        </div>
      </header>

      <div className="shell">
        <nav className="rail">
          {SECTIONS.map((s, i) => {
            const isLocked = locked(s);
            return (
              <button
                key={s.id}
                className={`rail-item${section === s.id ? " active" : ""}${isLocked ? " locked" : ""}`}
                onClick={() => setSection(s.id)}
              >
                <span className="rail-index">{String(i + 1).padStart(2, "0")}</span>
                <span className="rail-label">{s.label}</span>
                {isLocked ? <span className="rail-lock" aria-label="locked">◌</span> : null}
              </button>
            );
          })}
          <div className="rail-foot">
            <a href="https://github.com/0xFacet/eip-8182-reference-implementation/tree/main/erc" target="_blank" rel="noreferrer" className="rail-src">SOURCE CODE</a>
          </div>
        </nav>

        <main className="main">
          <AnimatePresence mode="wait">
            <motion.div
              key={section}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            >
              {section === "overview" && <Overview onNavigate={setSection} />}
              {section === "learn" && <Learn onNavigate={setSection} />}
              {section === "identity" && <Identity />}
              {section === "pools" && <Pools />}
              {section === "send" && <Send />}
              {section === "move" && <Move />}
              {section === "activity" && <Activity />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
