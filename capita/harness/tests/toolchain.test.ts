import { afterAll, beforeAll, expect, test } from "vitest";
import { Barretenberg } from "@aztec/bb.js";
import { P } from "../src/constants.js";

// The brief's original test assumed a free `poseidon2Hash(bigint[])` export from
// @aztec/bb.js. The installed version (5.1.0) exposes poseidon2Hash as a method on
// a Barretenberg instance, taking { inputs: Uint8Array[] } and returning
// { hash: Uint8Array } (32-byte big-endian field elements), not bigints directly.
// This wrapper adapts the call shape only; the three behavioral assertions below
// (determinism, order-sensitivity, field-bounded) are unchanged from the brief.

let bb: Barretenberg;

beforeAll(async () => {
  bb = await Barretenberg.new();
});

afterAll(async () => {
  await bb.destroy();
});

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

async function poseidon2Hash(inputs: bigint[]): Promise<bigint> {
  const { hash } = await bb.poseidon2Hash({ inputs: inputs.map(toBytes32) });
  return fromBytes32(hash);
}

test("poseidon2 is available, deterministic, field-bounded", async () => {
  const a = await poseidon2Hash([1n, 2n]);
  const b = await poseidon2Hash([1n, 2n]);
  const c = await poseidon2Hash([2n, 1n]);
  expect(a).toBe(b);
  expect(a).not.toBe(c);
  expect(a < P).toBe(true);
});
