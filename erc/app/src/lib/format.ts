import { formatEther } from "viem";

export function shortHex(value: string, lead = 6, tail = 4): string {
  if (!value.startsWith("0x")) value = `0x${value}`;
  if (value.length <= lead + tail + 2) return value;
  return `${value.slice(0, lead + 2)}…${value.slice(-tail)}`;
}

export function fieldToHex(value: bigint): `0x${string}` {
  return `0x${value.toString(16).padStart(64, "0")}`;
}

export function shortField(value: bigint): string {
  return shortHex(fieldToHex(value), 6, 6);
}

/** Human ETH string from a wei bigint, trimmed. */
export function ethOf(wei: bigint): string {
  const s = formatEther(wei);
  return s.replace(/\.?0+$/, (m) => (m.includes(".") ? "" : m));
}

export function weiLabel(wei: bigint): string {
  if (wei === 0n) return "0";
  if (wei < 1_000_000n) return `${wei.toString()} wei`;
  return `${ethOf(wei)} ETH`;
}
