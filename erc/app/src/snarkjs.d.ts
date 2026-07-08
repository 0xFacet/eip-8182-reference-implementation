declare module "snarkjs" {
  export const groth16: {
    fullProve(input: unknown, wasm: string, zkey: string): Promise<{ proof: unknown; publicSignals: string[] }>;
    verify(vkey: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  };
  const _default: { groth16: typeof groth16 };
  export default _default;
}
