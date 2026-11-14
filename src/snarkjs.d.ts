declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    verify(vk: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  };
  export const wtns: {
    calculate(input: Record<string, unknown>, wasmPath: string, wtnsPath: string): Promise<void>;
  };
}
