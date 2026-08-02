# Capita

Shielded payment pool with person-bound spending limits (zero-knowledge research prototype).

- `harness/` — TypeScript test harness, shared protocol constants, and (from Task 2 onward) crypto wrappers used by both the test suite and benchmarks.
- `circuits/` — Noir circuits (added starting Task 5/6).

## Toolchain

Installed via the official installer scripts (the `noirup.dev` / `bbup.dev` vanity redirects were unreachable from this machine's network path; the underlying scripts at `raw.githubusercontent.com/noir-lang/noirup` and `raw.githubusercontent.com/AztecProtocol/aztec-packages` were used instead — same installers, same result):

```
$ nargo --version
nargo version = 1.0.0-beta.22
noirc version = 1.0.0-beta.22+c57152f91260ecdb9faad4efc20abb14b6d2ece7
(git version hash: c57152f91260ecdb9faad4efc20abb14b6d2ece7, is dirty: false)

$ bb --version
5.0.0-nightly.20260522
```

**Version pinning note:** `noirup` with no arguments installs the latest nargo (`1.0.0-beta.26` at the time of this setup). `bbup`'s auto-detection resolves a compatible `bb` version from a `noir-version -> bb-version` map published by the Barretenberg team; that map's newest entry was `1.0.0-beta.22 -> 5.0.0-nightly.20260522`, so `bbup` failed against `1.0.0-beta.26` with "couldn't determine version from noir." Rather than forcing an unverified `bb` version against the newest `nargo`, this setup pins to the newest *matched* pair: `noirup -v 1.0.0-beta.22` followed by a plain `bbup`. `@noir-lang/noir_js` (npm) is pinned to the exact same `1.0.0-beta.22` (not `^1.0.0-beta.22` — semver prerelease ranges of the form `^1.0.0-beta.22` still admit `1.0.0-beta.26`, which would silently reintroduce the mismatch) so the harness's ACIR execution stays in lockstep with what `nargo` compiles. `@aztec/bb.js` (npm, `5.1.0`) is left on its normal caret range: it's only used here for the `poseidon2Hash` primitive, which is not version-sensitive to `nargo`'s ACIR format the way `noir_js` is.

If a later task bumps `nargo`, re-run `bbup` (no args) first and check it resolves — if it fails the same way, repeat this pinning process against whatever the map's newest entry is, and update `@noir-lang/noir_js` to match.

| Tool | Version |
|---|---|
| nargo / noirc | 1.0.0-beta.22 |
| bb (native) | 5.0.0-nightly.20260522 |
| @aztec/bb.js (npm) | 5.1.0 |
| @noir-lang/noir_js (npm) | 1.0.0-beta.22 (exact) |
| Node.js | v22.14.0 |
| npm | 10.9.2 |
| TypeScript | 7.0.2 |
| vitest | 4.1.10 |

### Machine

- Mac Studio, Apple M4 Max, arm64
- macOS 26.5.2 (build 25F84), Darwin kernel 25.5.0
