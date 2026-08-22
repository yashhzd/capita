import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { compile, execute, prove, verify, closeProver } from "../src/prove.js";
import { closePoseidon } from "../src/poseidon.js";
import { ownerPk, personId } from "../src/notes.js";
import { Pool, type EnrollOutput } from "../src/pool.js";
import { P, T_THRESHOLD } from "../src/constants.js";
import { GRUMPKIN_ORDER } from "../src/grumpkin.js";
import { encrypt, keygen, type Limbs } from "../src/elgamal.js";

// Real UltraHonk proving, closing the boundary every other test in this
// suite deliberately stands on the far side of: everywhere else, an
// executed witness stands in for a verified proof (see the note atop
// pool.ts). This file is where that stand-in is checked against the real
// thing -- one enrollment proof, one spend proof, both generated and
// verified through bb.js against the compiled circuits, over a live pool's
// Merkle state exactly as the harness would build them for a real
// submission.
//
// The tamper test is the one that matters most: it is the difference
// between "verify() returns a boolean" and "verify() checks anything".
// Mutating a public input after the proof was generated must make
// verification FAIL, not throw -- a thrown error would mean the input
// failed to parse, which proves nothing about whether the proof was
// checked. A returned `false` is what proves the check ran and rejected
// the mismatch.

const SPEND_DIR = fileURLToPath(new URL("../../circuits/spend/", import.meta.url));
const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);
const toHex = (v: bigint) => "0x" + v.toString(16);
const MASK_128 = (1n << 128n) - 1n;

const DAY = 900n;
const ASK = 271828n;
const APK = keygen(ASK);
const PERSON_SECRET = 7_000_001n;

beforeAll(() => {
  compile(ENROLLMENT_DIR);
  compile(SPEND_DIR);
}, 240_000);

afterAll(async () => {
  await closeProver();
  await closePoseidon();
});

/**
 * Bumps a bb.js public-input hex string to a DIFFERENT valid field element,
 * preserving its digit width -- publicInputs entries are fixed-width, and a
 * width change would make this a shape failure rather than a value one.
 */
function tamperHex(hex: string): string {
  const digits = hex.length - 2;
  const bumped = (BigInt(hex) + 1n) % P;
  return "0x" + bumped.toString(16).padStart(digits, "0");
}

test(
  "a real enrollment proof verifies, with public inputs in ABI order",
  { timeout: 300_000 },
  async () => {
    const { witness, returnValue } = await execute(ENROLLMENT_DIR, {
      person_secret: toHex(PERSON_SECRET),
      r_t: toHex(111n),
      d_now: toHex(DAY),
    });
    const [e, cT] = (returnValue as [string, string]).map(BigInt);

    const { proof, publicInputs } = await prove(ENROLLMENT_DIR, witness);

    // The enrollment ABI is one public param (d_now) then a two-element
    // public return ((Field, Field)): three public inputs total, in that
    // order. Checked explicitly rather than assumed, since indexing into
    // this array by a wrong assumption would silently test the wrong slot.
    expect(publicInputs.map(BigInt)).toEqual([DAY, e, cT]);

    expect(await verify(ENROLLMENT_DIR, proof, publicInputs)).toBe(true);
  },
);

test(
  "a real spend proof verifies over live pool state, and a tampered public input fails verification",
  { timeout: 300_000 },
  async () => {
    const pool = new Pool(DAY);
    const { witness: enrollWitness, returnValue: enrollReturn } = await execute(
      ENROLLMENT_DIR,
      { person_secret: toHex(PERSON_SECRET), r_t: toHex(222n), d_now: toHex(DAY) },
    );
    const [e, cTGenesis] = (enrollReturn as [string, string]).map(BigInt);
    const enrollment: EnrollOutput = { E: e, cT: cTGenesis, dNow: DAY };
    await pool.enroll(enrollment);

    const ownerSk = 1_800_001n;
    const pk = await ownerPk(ownerSk);
    const recipientPk = await ownerPk(1_800_002n);
    const { index } = await pool.deposit(20_000n, pk);
    const root = pool.tree.root();

    const v1 = 6_000n;
    const v2 = 14_000n;
    const sOld = 0n;
    const dOld = DAY;
    const rEnc = 909_001n;
    const msg: Limbs = [0n, 0n, 0n, 0n]; // v1 stays under T, dummy memo.
    const memo = await encrypt(msg, APK, rEnc);
    const rEncCanonical = ((rEnc % GRUMPKIN_ORDER) + GRUMPKIN_ORDER) % GRUMPKIN_ORDER;

    const { witness, returnValue } = await execute(SPEND_DIR, {
      person_secret: toHex(PERSON_SECRET),
      v_in: toHex(20_000n),
      owner_sk: toHex(ownerSk),
      r_in: toHex(BigInt(index)),
      path_in_siblings: pool.tree.path(index).siblings.map(toHex),
      path_in_indices: pool.tree.path(index).indices.map((bit) => bit === 1),
      v1: toHex(v1),
      pk1: toHex(recipientPk),
      r1: toHex(333n),
      v2: toHex(v2),
      r2: toHex(444n),
      s_old: toHex(sOld),
      d_old: toHex(dOld),
      r_t: toHex(222n),
      path_t_siblings: pool.tree.path(0).siblings.map(toHex),
      path_t_indices: pool.tree.path(0).indices.map((bit) => bit === 1),
      r_t_new: toHex(555n),
      r_enc_lo: toHex(rEncCanonical & MASK_128),
      r_enc_hi: toHex(rEncCanonical >> 128n),
      root: toHex(root),
      d_now: toHex(DAY),
      t_threshold: toHex(T_THRESHOLD),
      apk_x: toHex(APK.x),
      apk_y: toHex(APK.y),
      c1: [toHex(memo.c1.x), toHex(memo.c1.y)],
      ct: memo.ct.map(toHex),
    });
    const [nPay, nTally, cOut1, cOut2, cTallyNew] = (
      returnValue as [string, string, string, string, string]
    ).map(BigInt);

    const { proof, publicInputs, proofBytes } = await (async () => {
      const result = await prove(SPEND_DIR, witness);
      return { ...result, proofBytes: result.proof.length };
    })();

    // Spend's ABI: 11 public params (root, d_now, t_threshold, apk_x,
    // apk_y, c1[2], ct[4]) then the 5-element public return, in that order
    // -- 16 total. Checked explicitly, same reasoning as the enrollment
    // test: an index used below to locate `c_tally_new` must be verified,
    // not assumed.
    const expectedPublicInputs = [
      root,
      DAY,
      T_THRESHOLD,
      APK.x,
      APK.y,
      memo.c1.x,
      memo.c1.y,
      ...memo.ct,
      nPay,
      nTally,
      cOut1,
      cOut2,
      cTallyNew,
    ];
    expect(publicInputs).toHaveLength(16);
    expect(publicInputs.map(BigInt)).toEqual(expectedPublicInputs);

    expect(await verify(SPEND_DIR, proof, publicInputs)).toBe(true);

    // The tamper test. c_tally_new is the last public input; bump it to a
    // different valid field element and re-verify the SAME proof against
    // the mutated list. A proof binds its public inputs cryptographically,
    // so this must fail, and it must fail by returning false -- not by
    // throwing, which would only prove the shape parsed, not that the
    // binding was checked.
    const tampered = [...publicInputs];
    const lastIndex = tampered.length - 1;
    tampered[lastIndex] = tamperHex(tampered[lastIndex]);
    expect(tampered[lastIndex]).not.toBe(publicInputs[lastIndex]);

    await expect(verify(SPEND_DIR, proof, tampered)).resolves.toBe(false);

    // Record sizes, per the plan's "record proof sizes" step. Printed
    // rather than asserted to an exact byte count: UltraHonk proof/VK
    // sizes are a function of the backend version, not a protocol
    // invariant this test should pin.
    console.log(`spend proof: ${proofBytes} bytes, ${publicInputs.length} public inputs`);
  },
);
