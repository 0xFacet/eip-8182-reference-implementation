import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useAccount } from "wagmi";
import {
  type DerivedIdentity,
  type IdentitySecrets,
  clearIdentity,
  expandIdentity,
  loadIdentity,
  saveIdentity,
} from "../lib/identity.ts";
import { getDeployment } from "../config/deployment.ts";

interface IdentityContextValue {
  secrets: IdentitySecrets | null;
  derived: DerivedIdentity | null;
  save: (next: IdentitySecrets) => void;
  clear: () => void;
  reload: () => void;
}

const IdentityContext = createContext<IdentityContextValue | null>(null);

export function IdentityProvider({ children }: { children: ReactNode }) {
  const { address, chainId } = useAccount();
  const registry = getDeployment(chainId)?.registry;
  const [secrets, setSecrets] = useState<IdentitySecrets | null>(null);

  const reload = useCallback(() => {
    if (address && chainId && registry) setSecrets(loadIdentity(chainId, address, registry));
    else setSecrets(null);
  }, [address, chainId, registry]);

  useEffect(() => reload(), [reload]);

  const save = useCallback((next: IdentitySecrets) => {
    if (!registry) return;
    saveIdentity(next, registry);
    setSecrets({ ...next });
  }, [registry]);

  const clear = useCallback(() => {
    if (address && chainId && registry) clearIdentity(chainId, address, registry);
    setSecrets(null);
  }, [address, chainId, registry]);

  const derived = useMemo(() => (secrets ? expandIdentity(secrets) : null), [secrets]);

  const value = useMemo<IdentityContextValue>(() => ({ secrets, derived, save, clear, reload }), [secrets, derived, save, clear, reload]);
  return <IdentityContext.Provider value={value}>{children}</IdentityContext.Provider>;
}

export function useIdentity(): IdentityContextValue {
  const ctx = useContext(IdentityContext);
  if (!ctx) throw new Error("useIdentity must be used within IdentityProvider");
  return ctx;
}
