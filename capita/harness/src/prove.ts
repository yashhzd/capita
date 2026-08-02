import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";

// noir_js re-exports InputMap but not InputValue, so recover the return
// value's type from the Noir class itself rather than reaching into the
// transitive noirc_abi package.
type InputValue = Awaited<ReturnType<Noir["execute"]>>["returnValue"];

// Bridge between the TypeScript harness and nargo-compiled circuits.
// execute() is the workhorse from Task 5 onward: it loads (compiling on
// demand) the artifact for a circuit directory and runs witness generation
// through noir_js, returning the solved witness and the circuit's return
// value. prove()/verify() are the UltraHonk half of the interface; they
// land in Task 11 and throw until then.
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

/** UltraHonk proving -- lands in Task 11. */
export async function prove(
  _circuitDir: string,
  _witness: Uint8Array,
): Promise<never> {
  throw new Error("prove() is implemented in Task 11 (UltraHonk via bb); Task 5 ships witness execution only");
}

/** UltraHonk verification -- lands in Task 11. */
export async function verify(
  _circuitDir: string,
  _proof: Uint8Array,
  _publicInputs: string[],
): Promise<never> {
  throw new Error("verify() is implemented in Task 11 (UltraHonk via bb); Task 5 ships witness execution only");
}
