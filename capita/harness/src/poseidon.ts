import { Barretenberg } from "@aztec/bb.js";

// @aztec/bb.js exposes no free-standing `poseidon2Hash` function -- the real
// API is instance-based: construct a Barretenberg instance, then call
// `.poseidon2Hash({ inputs: Uint8Array[] })`, which resolves to
// `{ hash: Uint8Array }` (a single 32-byte big-endian field element). This
// module hides that shape behind a plain bigint-in/bigint-out `p2()`, using
// the same byte conversion as tests/toolchain.test.ts.
//
// Constructing a Barretenberg instance is expensive (it spins up the
// underlying WASM/native backend), so it is created at most once per
// process and memoized as a promise: every call to `p2()` before the first
// instance resolves awaits that same in-flight construction instead of
// racing to start several.
let bbInstance: Promise<Barretenberg> | undefined;

function getBarretenberg(): Promise<Barretenberg> {
  if (!bbInstance) {
    bbInstance = Barretenberg.new();
  }
  return bbInstance;
}

function toBytes32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function fromBytes32(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/** Poseidon2 hash over the BN254 scalar field. */
export async function p2(inputs: bigint[]): Promise<bigint> {
  const bb = await getBarretenberg();
  const { hash } = await bb.poseidon2Hash({ inputs: inputs.map(toBytes32) });
  return fromBytes32(hash);
}

/**
 * Releases the memoized Barretenberg instance, if `p2()` ever created one.
 * Tests must call this from an `afterAll` hook so the process can exit
 * cleanly instead of hanging on an open WASM handle.
 */
export async function closePoseidon(): Promise<void> {
  if (!bbInstance) return;
  const bb = await bbInstance;
  bbInstance = undefined;
  await bb.destroy();
}
