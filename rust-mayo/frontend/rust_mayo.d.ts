/* tslint:disable */
/* eslint-disable */
export function generate_keypair_wasm(param_set_name: string): any;
export function generate_mayo_keypair(param_set_name: string): any;
export function sign_with_mayo(param_set_name: string, secret_key: Uint8Array, message: Uint8Array): Uint8Array;
export function verify_with_mayo(param_set_name: string, public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly generate_keypair_wasm: (a: number, b: number) => [number, number, number];
  readonly sign_with_mayo: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly verify_with_mayo: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
  readonly generate_mayo_keypair: (a: number, b: number) => [number, number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
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
