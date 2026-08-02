import { afterAll, expect, test } from "vitest";
import { P } from "../src/constants.js";
import { closePoseidon, p2 } from "../src/poseidon.js";
import { G, GRUMPKIN_ORDER, INF, add, isOnCurve, mul, negate } from "../src/grumpkin.js";
import { decrypt, encrypt, keygen } from "../src/elgamal.js";

afterAll(async () => {
  await closePoseidon();
});

// The brief's three required tests, verbatim.

test("elgamal roundtrip", async () => {
  const ask = 123456789n, apk = keygen(ask);
  const msg: [bigint,bigint,bigint,bigint] = [1n, 999n, 10500n, 20666n];
  const memo = await encrypt(msg, apk, 42n);
  expect(await decrypt(memo, ask)).toEqual(msg);
});

test("wrong key garbles", async () => {
  const memo = await encrypt([1n,2n,3n,4n], keygen(5n), 42n);
  expect(await decrypt(memo, 6n)).not.toEqual([1n,2n,3n,4n]);
});

test("curve sanity: G on curve, mul(2,G)=add(G,G)", () => {
  expect(((G.y*G.y) % P)).toBe((((G.x**3n % P) - 17n % P) + P) % P);
  expect(mul(2n, G)).toEqual(add(G, G));
});

// Beyond the brief: curve-arithmetic edge cases. Wrong infinity handling and
// double-and-add bugs are the classic curve failure modes, and they hide from
// test suites that only ever exercise the happy path above.

test("identity cases: mul(0,G) is infinity, mul(1,G)=G, add with infinity is a no-op", () => {
  expect(mul(0n, G).inf).toBe(true);
  expect(mul(1n, G)).toEqual(G);
  expect(add(G, INF)).toEqual(G);
  expect(add(INF, G)).toEqual(G);
  expect(add(INF, INF).inf).toBe(true);
  expect(isOnCurve(INF)).toBe(true);
});

test("inverse: adding a point to its negation gives infinity", () => {
  expect(add(G, negate(G)).inf).toBe(true);
  const Q = mul(7n, G);
  expect(add(Q, negate(Q)).inf).toBe(true);
});

test("scalar distributivity: mul(a+b,G) = add(mul(a,G), mul(b,G)), all results on curve", () => {
  // Distributivity exercises every add/double path of double-and-add in a way
  // a lone on-curve check cannot: a formula bug usually still lands *on* the
  // curve, just on the wrong point. The third pair uses scalars near the group
  // order so the doubling chain runs its full 254-bit length.
  const pairs: [bigint, bigint][] = [
    [3n, 4n],
    [123456789n, 987654321n],
    [GRUMPKIN_ORDER / 3n, GRUMPKIN_ORDER / 5n],
  ];
  for (const [a, b] of pairs) {
    const aG = mul(a, G), bG = mul(b, G);
    const lhs = mul(a + b, G);
    const rhs = add(aG, bG);
    expect(lhs).toEqual(rhs);
    for (const pt of [aG, bG, lhs]) {
      expect(isOnCurve(pt)).toBe(true);
    }
  }
});

test("group order: mul(GRUMPKIN_ORDER-1, G) = negate(G)", () => {
  // mul() reduces its scalar mod GRUMPKIN_ORDER, so mul(GRUMPKIN_ORDER, G)
  // would trivially return infinity without proving anything. ORDER-1 is
  // below the modulus -- no reduction happens -- so this genuinely verifies
  // that the constant is the order of G on this curve.
  expect(mul(GRUMPKIN_ORDER - 1n, G)).toEqual(negate(G));
});

// Beyond the brief: ElGamal structural properties.

test("elgamal: identical plaintext limbs still produce four distinct ciphertext slots", async () => {
  // The limb index i sits *inside* the hash (pad_i = p2([S.x, S.y, i])), so
  // equal plaintexts must not leak equality through equal ciphertexts.
  const memo = await encrypt([7n, 7n, 7n, 7n], keygen(11n), 13n);
  expect(new Set(memo.ct).size).toBe(4);
});

test("elgamal: c1 is on the curve", async () => {
  const memo = await encrypt([1n, 2n, 3n, 4n], keygen(5n), 42n);
  expect(isOnCurve(memo.c1)).toBe(true);
  expect(memo.c1.inf).toBe(false);
});

// Guard contract pinned for Tasks 5/8: the throws below are documented
// behavior (fail loudly rather than emit a memo padded with p2([0, 0, i])
// that anyone can strip, or a limb that silently decrypts to limb mod P).
// Without these tests a refactor could drop the guards with the suite
// staying green.

test("encrypt rejects a plaintext limb outside [0, P)", async () => {
  const apk = keygen(5n);
  await expect(encrypt([P, 0n, 0n, 0n], apk, 42n)).rejects.toThrow(RangeError);
  await expect(encrypt([P, 0n, 0n, 0n], apk, 42n)).rejects.toThrow(/^encrypt: plaintext limb out of field range/);
  await expect(encrypt([0n, 0n, 0n, -1n], apk, 42n)).rejects.toThrow(RangeError);
});

test("encrypt rejects rEnc = 0 (degenerate shared secret)", async () => {
  const apk = keygen(5n);
  await expect(encrypt([1n, 2n, 3n, 4n], apk, 0n)).rejects.toThrow(/^encrypt: degenerate shared secret/);
  // Any multiple of the group order reduces to the same degenerate case.
  await expect(encrypt([1n, 2n, 3n, 4n], apk, GRUMPKIN_ORDER)).rejects.toThrow(/^encrypt: degenerate shared secret/);
});

test("encrypt rejects apk = INF (degenerate shared secret)", async () => {
  await expect(encrypt([1n, 2n, 3n, 4n], INF, 42n)).rejects.toThrow(/^encrypt: degenerate shared secret/);
});

test("decrypt rejects ask = 0 (degenerate shared secret)", async () => {
  const memo = await encrypt([1n, 2n, 3n, 4n], keygen(5n), 42n);
  await expect(decrypt(memo, 0n)).rejects.toThrow(/^decrypt: degenerate shared secret/);
});

// Range guard on p2: Grumpkin scalars live mod GRUMPKIN_ORDER, which is
// LARGER than P, so a raw scalar fed to p2() would silently misencode. The
// guard turns that whole class of silent corruption into a loud failure.

test("p2 range guard: rejects P and -1n, accepts P-1", async () => {
  await expect(p2([P])).rejects.toThrow(/out of field range/);
  await expect(p2([-1n])).rejects.toThrow(/out of field range/);
  await expect(p2([1n, P])).rejects.toThrow(/out of field range/);
  expect(typeof (await p2([P - 1n]))).toBe("bigint");
});
