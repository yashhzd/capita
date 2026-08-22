import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import {
  Barretenberg,
  UltraHonkBackend,
  UltraHonkVerifierBackend,
  type ProofData,
} from "@aztec/bb.js";

// noir_js re-exports InputMap but not InputValue, so recover the return
// value's type from the Noir class itself rather than reaching into the
// transitive noirc_abi package.
type InputValue = Awaited<ReturnType<Noir["execute"]>>["returnValue"];

// Bridge between the TypeScript harness and nargo-compiled circuits.
// execute() is the workhorse from Task 5 onward: it loads (compiling on
// demand) the artifact for a circuit directory and runs witness generation
// through noir_js, returning the solved witness and the circuit's return
// value. prove()/verify() are the UltraHonk half of the interface, added in
// Task 11: real proof generation and verification against bb.js.
//
// Input encoding: noir_js accepts field elements as 0x-hex strings (bigint
// is not part of its InputMap type), booleans for bool, and nested arrays
// matching the ABI. Grumpkin scalars never travel as a single field --
// they are reduced to the canonical value mod the group order and split
// into 128-bit limbs (lo + 2^128 * hi), matching Noir's
// EmbeddedCurveScalar; see circuits/common elgamal_encrypt.

export interface ExecuteResult {
  witness: Uint8Array;
  returnValue: InputValue;
}

// nargo is not npm-managed (see capita/README.md for the pinned
// toolchain), so resolve it the way a developer shell would: an explicit
// NARGO_BIN wins, then PATH, then the default noirup install location.
let resolvedNargo: string | undefined;

function nargoBin(): string {
  if (resolvedNargo) return resolvedNargo;
  const candidates = [
    process.env.NARGO_BIN,
    "nargo",
    join(homedir(), ".nargo", "bin", "nargo"),
  ].filter((c): c is string => Boolean(c));
  for (const candidate of candidates) {
    try {
      execFileSync(candidate, ["--version"], { stdio: "ignore" });
      resolvedNargo = candidate;
      return candidate;
    } catch {
      // try the next candidate
    }
  }
  throw new Error(
    "nargo not found (tried NARGO_BIN, PATH, ~/.nargo/bin/nargo); " +
      "install the pinned toolchain per capita/README.md",
  );
}

/** Runs `nargo compile` in the given circuit directory. */
export function compile(circuitDir: string): void {
  execFileSync(nargoBin(), ["compile", "--silence-warnings"], {
    cwd: circuitDir,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/**
 * Compiles the circuit and returns nargo's printed ACIR listing. Tests use
 * this to pin the compiled circuit's SHAPE -- properties like "this witness
 * carries a standalone range opcode" that witness execution cannot observe
 * (the ACVM solver enforces blackbox input widths at witness generation
 * whether or not the opcode exists, but the ACIR is what gets proven).
 */
export function printAcir(circuitDir: string): string {
  return execFileSync(
    nargoBin(),
    ["compile", "--print-acir", "--silence-warnings"],
    { cwd: circuitDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
}

function artifactPath(circuitDir: string): string {
  // nargo names the artifact after the package, not the directory.
  const manifest = readFileSync(join(circuitDir, "Nargo.toml"), "utf8");
  const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(manifest)?.[1] ?? basename(circuitDir);
  return join(circuitDir, "target", `${name}.json`);
}

/**
 * Executes a circuit's witness generation via noir_js against the nargo
 * compile artifact in `<circuitDir>/target/`, compiling first if the
 * artifact does not exist yet. Callers that must not risk a stale artifact
 * (the consistency gate) call compile() explicitly beforehand.
 */
export async function execute(
  circuitDir: string,
  inputs: InputMap,
): Promise<ExecuteResult> {
  const artifact = artifactPath(circuitDir);
  if (!existsSync(artifact)) {
    compile(circuitDir);
  }
  const circuit = JSON.parse(readFileSync(artifact, "utf8")) as CompiledCircuit;
  const noir = new Noir(circuit);
  const { witness, returnValue } = await noir.execute(inputs);
  return { witness, returnValue };
}

// UltraHonk proving and verification. bb.js exposes no free-standing
// prove/verify pair -- construction is instance-based and expensive (it
// spins up the underlying WASM backend), so the `Barretenberg` instance is
// created at most once per process and memoized, mirroring poseidon.ts's
// `p2()`/`closePoseidon()` pattern exactly. A second cache, keyed by circuit
// directory, holds the compiled `UltraHonkBackend` and its verification key:
// the key is a per-circuit deployment artifact, not a per-proof one, and
// `UltraHonkBackend`'s own `verifyProof` recomputes it on every call (its
// own source flags this as suboptimal) -- folding a setup cost into every
// verification would overstate it by orders of magnitude. This is the same
// precomputed-VK discipline `bench/spend-bench.ts` established.

let bbInstance: Promise<Barretenberg> | undefined;

function getBarretenberg(): Promise<Barretenberg> {
  if (!bbInstance) {
    bbInstance = Barretenberg.new();
  }
  return bbInstance;
}

/**
 * Releases every resource `prove()`/`verify()` may have created: the
 * memoized `Barretenberg` instance and any cached per-circuit backend.
 * Tests must call this from an `afterAll` hook so the process can exit
 * cleanly instead of hanging on an open WASM handle.
 */
export async function closeProver(): Promise<void> {
  backends.clear();
  if (!bbInstance) return;
  const bb = await bbInstance;
  bbInstance = undefined;
  await bb.destroy();
}

interface CircuitBackend {
  backend: UltraHonkBackend;
  verificationKey: Uint8Array;
}

const backends = new Map<string, Promise<CircuitBackend>>();

function bytecodeOf(circuitDir: string): string {
  const artifact = artifactPath(circuitDir);
  if (!existsSync(artifact)) {
    compile(circuitDir);
  }
  const { bytecode } = JSON.parse(readFileSync(artifact, "utf8")) as { bytecode: string };
  return bytecode;
}

function getBackend(circuitDir: string): Promise<CircuitBackend> {
  let cached = backends.get(circuitDir);
  if (!cached) {
    cached = (async () => {
      const api = await getBarretenberg();
      const backend = new UltraHonkBackend(bytecodeOf(circuitDir), api);
      const verificationKey = await backend.getVerificationKey();
      return { backend, verificationKey };
    })();
    backends.set(circuitDir, cached);
  }
  return cached;
}

/**
 * Generates a real UltraHonk proof for a witness already solved by
 * `execute()`. Returns the proof bytes and the circuit's public inputs (the
 * declared `pub` parameters followed by the `pub` return values, in ABI
 * declaration order, each a 0x-prefixed hex field element) exactly as
 * `verify()` requires them back.
 */
export async function prove(circuitDir: string, witness: Uint8Array): Promise<ProofData> {
  const { backend } = await getBackend(circuitDir);
  return backend.generateProof(witness);
}

/**
 * Verifies an UltraHonk proof against the circuit's precomputed
 * verification key. Returns `false` -- never throws -- for a
 * cryptographically invalid proof, including one whose public inputs were
 * tampered with after generation; a malformed shape (wrong element count,
 * bytes that do not parse as the expected fields) is a distinct failure
 * from an unsatisfied proof and callers should not conflate the two.
 */
export async function verify(
  circuitDir: string,
  proof: Uint8Array,
  publicInputs: string[],
): Promise<boolean> {
  const { verificationKey } = await getBackend(circuitDir);
  const api = await getBarretenberg();
  const verifier = new UltraHonkVerifierBackend(api);
  return verifier.verifyProof({ proof, publicInputs, verificationKey });
}
