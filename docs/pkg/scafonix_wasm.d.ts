/* tslint:disable */
/* eslint-disable */

/**
 * Computes the deterministic canonical policy hash h_p
 */
export function compute_policy_hash_wasm(policy_json: string): string;

/**
 * Computes the joint vault EOA address from Q_A and Q_B
 */
export function compute_vault_address_wasm(qa_hex: string, qb_hex: string): string;

/**
 * Decrypts the Share C emergency voucher
 */
export function decrypt_recovery_voucher_wasm(voucher_c: string, password: string): string;

/**
 * Evaluates a transaction against an IAM policy document
 */
export function evaluate_policy_wasm(policy_json: string, tx_json: string): boolean;

/**
 * Generates a new Client Share A and public key Q_A using browser WebCrypto / CSPRNG
 */
export function generate_client_keypair(): any;

/**
 * Executes the Patent Zero-Assembly Local Signature (10-2026-0134084)
 */
export function patent_emergency_sign_wasm(sk_a_hex: string, sk_b_hex: string, msg_hash_hex: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly compute_policy_hash_wasm: (a: number, b: number) => [number, number, number, number];
    readonly compute_vault_address_wasm: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decrypt_recovery_voucher_wasm: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly evaluate_policy_wasm: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly generate_client_keypair: () => [number, number, number];
    readonly patent_emergency_sign_wasm: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
