export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const DOMAIN_PAYMENT = 1n, DOMAIN_TALLY = 2n, DOMAIN_ENROLL = 3n, DOMAIN_NULLIFIER = 4n;
export const APP_SCOPE = 0xca717an;
export const T_THRESHOLD = 10000n;
export const MERKLE_DEPTH = 16;
// Period indices are range-checked to this width in the spend circuit
// (circuits/spend/src/main.nr), so a valid day lies in [0, 2^DAY_BITS).
export const DAY_BITS = 32;
