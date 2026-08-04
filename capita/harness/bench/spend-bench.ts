/**
 * Evaluation benchmark: end-to-end UltraHonk proving and verification for
 * the enrollment and spend circuits, over live pool state.
 *
 * This is the measurement that backs the paper's evaluation table. It
 * deliberately reuses the same flow the tests exercise (enroll -> deposit
 * -> spend) rather than a synthetic witness, so the reported cost is the
 * cost of a real transaction: Merkle membership from openings, the tally
 * consume/update, and the uniform disclosure memo all included.
 *
 * Both threshold positions are measured. They must cost the same -- the
 * memo is uniform by construction, so an under-threshold spend and an
 * over-threshold spend execute identical constraint systems and differ
 * only in witness values. A gap here would be a privacy bug, not a
 * performance note, so the numbers are reported side by side.
 *
 * Run: npx tsx bench/spend-bench.ts
 */
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend } from "@aztec/bb.js";
import { compile, execute } from "../src/prove.js";
import { closePoseidon, p2 } from "../src/poseidon.js";
import { MerkleTree, type Path } from "../src/merkle.js";
import { ownerPk, personId } from "../src/notes.js";
import { Pool, type EnrollOutput } from "../src/pool.js";
import { MERKLE_DEPTH, T_THRESHOLD } from "../src/constants.js";
import { GRUMPKIN_ORDER } from "../src/grumpkin.js";
import { encrypt, keygen, type Limbs } from "../src/elgamal.js";

const SPEND_DIR = fileURLToPath(new URL("../../circuits/spend/", import.meta.url));
const ENROLLMENT_DIR = fileURLToPath(
  new URL("../../circuits/enrollment/", import.meta.url),
);

const toHex = (v: bigint) => "0x" + v.toString(16);
const MASK_128 = (1n << 128n) - 1n;
const DAY = 20260802n;
const ASK = 271828n;
const APK = keygen(ASK);
const REPS = Number(process.env.BENCH_REPS ?? 10);

function artifact(dir: string, name: string): string {
  const j = JSON.parse(readFileSync(`${dir}target/${name}.json`, "utf8"));
  return j.bytecode as string;
}

/** Median is reported rather than mean: proving is jitter-prone under
 *  background load, and the median is the honest single-number summary. */
function stats(samples: number[]) {
  const s = [...samples].sort((a, b) => a - b);
  const median = s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
  return { median, min: s[0], max: s[s.length - 1] };
}

async function runEnrollment(
  personSecret: bigint,
  rT: bigint,
  dNow: bigint,
): Promise<{ out: EnrollOutput; witness: Uint8Array }> {
  const { returnValue, witness } = await execute(ENROLLMENT_DIR, {
    person_secret: toHex(personSecret),
    r_t: toHex(rT),
    d_now: toHex(dNow),
  });
  const [e, cT] = (returnValue as [string, string]).map(BigInt);
  return { out: { E: e, cT, dNow }, witness };
}

interface SpendWitness {
  personSecret: bigint; vIn: bigint; ownerSk: bigint; rIn: bigint; pathIn: Path;
  v1: bigint; pk1: bigint; r1: bigint; v2: bigint; r2: bigint;
  sOld: bigint; dOld: bigint; rT: bigint; pathT: Path; rTNew: bigint;
  rEnc: bigint; root: bigint; dNow: bigint;
}

async function executeSpend(w: SpendWitness) {
  const sNew = w.dNow === w.dOld ? w.sOld + w.v1 : w.v1;
  const msg: Limbs =
    sNew > T_THRESHOLD
      ? [1n, await personId(w.personSecret), sNew, w.dNow]
      : [0n, 0n, 0n, 0n];
  const memo = await encrypt(msg, APK, w.rEnc);
  const rEncCanonical = ((w.rEnc % GRUMPKIN_ORDER) + GRUMPKIN_ORDER) % GRUMPKIN_ORDER;
  return execute(SPEND_DIR, {
    person_secret: toHex(w.personSecret),
    v_in: toHex(w.vIn),
    owner_sk: toHex(w.ownerSk),
    r_in: toHex(w.rIn),
    path_in_siblings: w.pathIn.siblings.map(toHex),
    path_in_indices: w.pathIn.indices.map((bit) => bit === 1),
    v1: toHex(w.v1), pk1: toHex(w.pk1), r1: toHex(w.r1),
    v2: toHex(w.v2), r2: toHex(w.r2),
    s_old: toHex(w.sOld), d_old: toHex(w.dOld), r_t: toHex(w.rT),
    path_t_siblings: w.pathT.siblings.map(toHex),
    path_t_indices: w.pathT.indices.map((bit) => bit === 1),
    r_t_new: toHex(w.rTNew),
    r_enc_lo: toHex(rEncCanonical & MASK_128),
    r_enc_hi: toHex(rEncCanonical >> 128n),
    root: toHex(w.root), d_now: toHex(w.dNow),
    t_threshold: toHex(T_THRESHOLD),
    apk_x: toHex(APK.x), apk_y: toHex(APK.y),
    c1: [toHex(memo.c1.x), toHex(memo.c1.y)],
    ct: memo.ct.map(toHex),
  });
}

/** Builds a live pool and returns a spend witness at the requested
 *  threshold position. `v1` drives it: 6000 stays under T, 15000 crosses. */
async function spendWitnessAt(v1: bigint, personSecret: bigint) {
  const pool = new Pool(DAY);
  const rT = 71n;
  const aliceSk = 1111n;
  const alicePk = await ownerPk(aliceSk);
  const bobPk = await ownerPk(2222n);
  const { out: enrollment } = await runEnrollment(personSecret, rT, DAY);
  await pool.enroll(enrollment);
  const { index } = await pool.deposit(20000n, alicePk);
  const root = pool.tree.root();
  return executeSpend({
    personSecret, vIn: 20000n, ownerSk: aliceSk, rIn: BigInt(index),
    pathIn: pool.tree.path(index),
    v1, pk1: bobPk, r1: 333n, v2: 20000n - v1, r2: 444n,
    sOld: 0n, dOld: DAY, rT, pathT: pool.tree.path(0), rTNew: 555n,
    rEnc: 501n, root, dNow: DAY,
  });
}

async function measure(
  label: string,
  dir: string,
  pkg: string,
  witness: Uint8Array,
  api: Barretenberg,
  results: Record<string, unknown>[],
) {
  const backend = new UltraHonkBackend(artifact(dir, pkg), api);
  // The verification key is a per-circuit setup artifact, computed once by
  // whoever deploys the verifier -- not per transaction. UltraHonkBackend's
  // own verifyProof recomputes it on every call (its source flags this as
  // suboptimal), which would fold a setup cost into the per-proof number
  // and overstate verification by orders of magnitude. Precompute it and
  // verify through the explicit-VK path so the figure means what the paper
  // says it means.
  const verificationKey = await backend.getVerificationKey();
  const verifier = new UltraHonkVerifierBackend(api);

  // One warm-up outside the timed loop: the first proof pays for SRS
  // loading and WASM warm-up, which is a one-time process cost, not a
  // per-transaction cost. Reporting it as per-transaction would overstate.
  const warm = await backend.generateProof(witness);

  const proveMs: number[] = [];
  const verifyMs: number[] = [];
  let ok = true;
  for (let i = 0; i < REPS; i++) {
    const t0 = performance.now();
    const p = await backend.generateProof(witness);
    proveMs.push(performance.now() - t0);

    const t1 = performance.now();
    const verified = await verifier.verifyProof({ ...p, verificationKey });
    verifyMs.push(performance.now() - t1);
    ok = verified && ok;
  }
  const pv = stats(proveMs);
  const vv = stats(verifyMs);
  results.push({
    circuit: label,
    verified: ok,
    proofBytes: warm.proof.length,
    publicInputs: warm.publicInputs.length,
    vkBytes: verificationKey.length,
    proveMedianMs: +pv.median.toFixed(1),
    proveMinMs: +pv.min.toFixed(1),
    proveMaxMs: +pv.max.toFixed(1),
    verifyMedianMs: +vv.median.toFixed(2),
    verifyMinMs: +vv.min.toFixed(2),
    verifyMaxMs: +vv.max.toFixed(2),
    reps: REPS,
  });
}

async function main() {
  compile(ENROLLMENT_DIR);
  compile(SPEND_DIR);

  const api = await Barretenberg.new();
  const results: Record<string, unknown>[] = [];

  const { witness: enrollWitness } = await runEnrollment(9001n, 71n, DAY);
  await measure("enrollment", ENROLLMENT_DIR, "enrollment", enrollWitness, api, results);

  const under = await spendWitnessAt(6000n, 9001n);
  await measure("spend (below threshold, dummy memo)", SPEND_DIR, "spend", under.witness, api, results);

  const over = await spendWitnessAt(15000n, 9002n);
  await measure("spend (above threshold, real memo)", SPEND_DIR, "spend", over.witness, api, results);

  console.log("\n===BENCH_RESULTS===");
  for (const r of results) console.log(JSON.stringify(r));

  await api.destroy();
  await closePoseidon();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
