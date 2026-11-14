declare module "circomlibjs" {
  export interface PoseidonField {
    toString(a: unknown): string;
  }
  export interface Poseidon {
    (inputs: (bigint | number | string)[]): bigint;
    F: PoseidonField;
  }
  export function buildPoseidon(): Promise<Poseidon>;
}
