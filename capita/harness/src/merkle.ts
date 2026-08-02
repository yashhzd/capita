import { MERKLE_DEPTH } from "./constants.js";
import { p2 } from "./poseidon.js";

export interface Path {
  siblings: bigint[];
  indices: number[];
}

async function computeZeroHashes(depth: number): Promise<bigint[]> {
  const zeros: bigint[] = [0n];
  for (let level = 1; level <= depth; level++) {
    const z = zeros[level - 1];
    zeros.push(await p2([z, z]));
  }
  return zeros;
}

// zeros[k] is the root of an empty subtree of height k (zeros[0] is the
// empty-leaf value 0n itself, per the brief). This depends only on
// MERKLE_DEPTH and the hash function, so it is computed once at module load
// and shared by every MerkleTree instance. That sharing is what lets a
// brand-new tree's root() return the correct value synchronously -- with no
// insert having happened yet -- and stay identical across instances.
const ZERO_HASHES: bigint[] = await computeZeroHashes(MERKLE_DEPTH);

/**
 * Incremental Merkle tree over Poseidon2, fixed at depth MERKLE_DEPTH.
 *
 * Fold-order convention (must match the Noir circuits exactly -- see
 * Task 5's merkle_verify):
 *   - Empty leaf = 0n.
 *   - Internal node = p2([left, right]).
 *   - path(index) returns siblings/indices, both length MERKLE_DEPTH,
 *     ordered leaf-level first: index 0 is the sibling nearest the leaf.
 *   - indices[k] === 1 means the current node at level k is the RIGHT
 *     child, so folding at that level uses p2([sibling, current]).
 *   - indices[k] === 0 means the current node is the LEFT child, so
 *     folding at that level uses p2([current, sibling]).
 *
 * root() and path() are plain synchronous reads. Poseidon2 hashing is only
 * ever performed inside insert() (and verify()), which are async -- so
 * insert() fully rebuilds the cached level arrays from `leaves` every call
 * (O(n * MERKLE_DEPTH) per insert) rather than updating a spine
 * incrementally. That is deliberately simpler than the classic
 * filled-subtrees scheme: at PoC scale, obviously-correct code that's easy
 * to eyeball for off-by-one errors is worth more than the saved hashing.
 */
export class MerkleTree {
  private leaves: bigint[] = [];
  // levels[0] holds the real leaves inserted so far; levels[k] holds the
  // internal nodes at height k, derived from levels[k-1]; levels[MERKLE_DEPTH]
  // is a single-element array holding the current root once at least one
  // leaf has been inserted.
  private levels: bigint[][] = [[]];
  private cachedRoot: bigint = ZERO_HASHES[MERKLE_DEPTH];

  async insert(leaf: bigint): Promise<number> {
    const capacity = 2 ** MERKLE_DEPTH;
    if (this.leaves.length >= capacity) {
      throw new Error(`MerkleTree is full (max ${capacity} leaves)`);
    }
    const index = this.leaves.length;
    this.leaves.push(leaf);
    await this.rebuild();
    return index;
  }

  root(): bigint {
    return this.cachedRoot;
  }

  path(index: number): Path {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`index ${index} out of range for a tree with ${this.leaves.length} leaves`);
    }
    const siblings: bigint[] = [];
    const indices: number[] = [];
    let pos = index;
    for (let level = 0; level < MERKLE_DEPTH; level++) {
      const isRight = pos & 1;
      const siblingPos = isRight ? pos - 1 : pos + 1;
      const levelNodes = this.levels[level];
      siblings.push(siblingPos < levelNodes.length ? levelNodes[siblingPos] : ZERO_HASHES[level]);
      indices.push(isRight);
      pos >>= 1;
    }
    return { siblings, indices };
  }

  static async verify(root: bigint, leaf: bigint, path: Path): Promise<boolean> {
    let current = leaf;
    for (let level = 0; level < path.siblings.length; level++) {
      const sibling = path.siblings[level];
      current = path.indices[level] ? await p2([sibling, current]) : await p2([current, sibling]);
    }
    return current === root;
  }

  private async rebuild(): Promise<void> {
    const levels: bigint[][] = [this.leaves.slice()];
    for (let level = 1; level <= MERKLE_DEPTH; level++) {
      const prev = levels[level - 1];
      const cur: bigint[] = [];
      for (let i = 0; i < prev.length; i += 2) {
        const left = prev[i];
        const right = i + 1 < prev.length ? prev[i + 1] : ZERO_HASHES[level - 1];
        cur.push(await p2([left, right]));
      }
      levels.push(cur);
    }
    this.levels = levels;
    // insert() always pushes the new leaf before calling rebuild(), so
    // levels[0] (and therefore every level above it) is never empty here.
    this.cachedRoot = levels[MERKLE_DEPTH][0];
  }
}
