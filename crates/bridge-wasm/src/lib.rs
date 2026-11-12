//! The sandbox for foreign code (docs/09 §10, ADR 0020): WebAssembly with wasmi - an interpreter without JIT, fuel
//! counts every step, memory is capped, and a module sees nothing but the capabilities it was granted.
//!
//! **ABI**: the module exports `memory`, `alloc(len: i32) -> i32` and an entry `(ptr: i32, len: i32) -> i64` that
//! returns `ptr << 32 | len` of its output in its memory. Imports only from the module `bridge`, only functions of
//! granted capabilities ([`Grants`]); anything else and the module does not start.
//!
//! Host functions (all `i32` lengths; negative = refused):
//! - `log(ptr, len)` - one line (≤ 1 KiB, cut) ([`Grants::log`]);
//! - `caller(out, max) -> len` - the caller's ID ([`Grants::caller`]);
//! - `kv_get(kptr, klen, out, max) -> len` (-1 none, -2 too large) and `kv_put(kptr, klen, vptr, vlen) -> 0/-1`
//!   ([`Grants::kv`]);
//! - `event_append(ptr, len) -> 0/-1`, `event_count() -> i64`, `event_read(index: i64, out, max) -> len`
//!   ([`Grants::events`]).
//!
//! Every limit is an error ([`WasmError::Limit`]), a trap is [`WasmError::Trap`] - never a panic of the host. Callers
//! run [`run`] in a blocking thread.

#![forbid(unsafe_code)]

use thiserror::Error;
use wasmi::{
    Caller, CompilationMode, Config, Engine, ExternType, Instance, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

/// Most fuel one call may get.
pub const MAX_FUEL: u64 = 10_000_000_000;
/// Default fuel of a call.
pub const DEFAULT_FUEL: u64 = 100_000_000;
/// Largest module.
pub const MAX_MODULE_BYTES: usize = 4 * 1024 * 1024;
/// Largest memory of a module (256 pages).
pub const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;
/// Largest input and output.
pub const MAX_IO_BYTES: usize = 1024 * 1024;
/// Longest log line.
const MAX_LOG_BYTES: usize = 1024;
/// Largest key of `kv`.
pub const MAX_KEY_BYTES: usize = 256;
/// Largest value of `kv` and largest event.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;
/// Most table elements.
const MAX_TABLE_ELEMENTS: usize = 10_000;
/// Most host function calls per run: a host call costs the host more than its few steps of fuel (a disk write, a
/// signature) - beyond this budget every host function refuses (`-4`, `log` is ignored).
pub const MAX_HOST_CALLS: u32 = 1000;

/// What went wrong.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WasmError {
    /// The module is no valid module for this ABI (format, imports, exports).
    #[error("INVALID: {0}")]
    Invalid(String),
    /// A limit was hit (fuel, memory, sizes).
    #[error("LIMIT: {0}")]
    Limit(String),
    /// The module trapped (unreachable, out of bounds, …).
    #[error("TRAP: {0}")]
    Trap(String),
}

/// Limits of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Fuel (steps), at most [`MAX_FUEL`].
    pub fuel: u64,
    /// Memory in bytes, at most [`MAX_MEMORY_BYTES`].
    pub memory_bytes: usize,
    /// Input and output, at most [`MAX_IO_BYTES`].
    pub io_bytes: usize,
    /// Deterministic: no floating point (compute results are checked by recomputing them, docs/09 §11).
    pub deterministic: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self { fuel: DEFAULT_FUEL, memory_bytes: MAX_MEMORY_BYTES, io_bytes: MAX_IO_BYTES, deterministic: true }
    }
}

/// The capabilities granted to a module.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Grants {
    /// `log`.
    pub log: bool,
    /// `caller`.
    pub caller: bool,
    /// `kv_get`, `kv_put`.
    pub kv: bool,
    /// `event_append`, `event_count`, `event_read`.
    pub events: bool,
}

/// What the host gives a module (only the granted parts are reachable). Defaults refuse everything.
pub trait Host: Send + 'static {
    /// A log line of the module.
    fn log(&mut self, _line: &str) {}
    /// The caller's ID.
    fn caller(&self) -> Option<Vec<u8>> {
        None
    }
    /// A value of the module's own key-value store.
    fn kv_get(&mut self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }
    /// Stores a value (an error refuses it, e.g. the quota is full).
    fn kv_put(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), String> {
        Err("kv not available".into())
    }
    /// Appends an event.
    fn event_append(&mut self, _data: &[u8]) -> Result<(), String> {
        Err("events not available".into())
    }
    /// Number of events.
    fn event_count(&self) -> u64 {
        0
    }
    /// Event number `index` in the agreed order.
    fn event_read(&self, _index: u64) -> Option<Vec<u8>> {
        None
    }
}

/// A host without capabilities (pure functions).
#[derive(Debug, Default)]
pub struct NoHost;

impl Host for NoHost {}

/// The result of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The output.
    pub output: Vec<u8>,
    /// Fuel used.
    pub fuel_used: u64,
}

struct State<H: Host> {
    limits: StoreLimits,
    host: H,
    io_bytes: usize,
    calls: u32,
}

impl<H: Host> State<H> {
    /// Counts a host call; `false` once the budget is used up.
    fn tick(&mut self) -> bool {
        self.calls = self.calls.saturating_add(1);
        self.calls <= MAX_HOST_CALLS
    }
}

const ALL_IMPORTS: [&str; 7] = ["log", "caller", "kv_get", "kv_put", "event_append", "event_count", "event_read"];

fn granted(grants: Grants, name: &str) -> bool {
    match name {
        "log" => grants.log,
        "caller" => grants.caller,
        "kv_get" | "kv_put" => grants.kv,
        "event_append" | "event_count" | "event_read" => grants.events,
        _ => false,
    }
}

fn trap(error: wasmi::Error) -> WasmError {
    let text = error.to_string();
    if text.contains("fuel") {
        WasmError::Limit(format!("fuel: {text}"))
    } else if text.contains("memory") && (text.contains("grow") || text.contains("limit")) {
        WasmError::Limit(format!("memory: {text}"))
    } else {
        WasmError::Trap(text)
    }
}

fn memory_of<H: Host>(caller: &Caller<'_, State<H>>) -> Option<Memory> {
    caller.get_export("memory").and_then(wasmi::Extern::into_memory)
}

/// Reads `len` bytes at `ptr` of the module's memory (bounded by `max`).
fn read<H: Host>(caller: &Caller<'_, State<H>>, ptr: i32, len: i32, max: usize) -> Option<Vec<u8>> {
    let (ptr, len) = (usize::try_from(ptr).ok()?, usize::try_from(len).ok()?);
    if len > max {
        return None;
    }
    let mut buffer = vec![0u8; len];
    memory_of(caller)?.read(caller, ptr, &mut buffer).ok()?;
    Some(buffer)
}

/// Writes `data` at `out` if it fits in `max`: its length, `-2` if too large, `-3` if out of bounds.
fn write<H: Host>(caller: &mut Caller<'_, State<H>>, out: i32, max: i32, data: &[u8]) -> i32 {
    let (Ok(out), Ok(max)) = (usize::try_from(out), usize::try_from(max)) else { return -3 };
    if data.len() > max {
        return -2;
    }
    let Some(memory) = memory_of(caller) else { return -3 };
    match memory.write(caller, out, data) {
        Ok(()) => i32::try_from(data.len()).unwrap_or(-2),
        Err(_) => -3,
    }
}

fn link<H: Host>(linker: &mut Linker<State<H>>, grants: Grants) -> Result<(), WasmError> {
    let invalid = |error: wasmi::errors::LinkerError| WasmError::Invalid(error.to_string());
    if grants.log {
        linker
            .func_wrap("bridge", "log", |mut caller: Caller<'_, State<H>>, ptr: i32, len: i32| {
                if !caller.data_mut().tick() {
                    return;
                }
                if let Some(bytes) = read(&caller, ptr, len.min(MAX_LOG_BYTES as i32), MAX_LOG_BYTES) {
                    let line = String::from_utf8_lossy(&bytes).replace(char::is_control, " ");
                    caller.data_mut().host.log(&line);
                }
            })
            .map_err(invalid)?;
    }
    if grants.caller {
        linker
            .func_wrap("bridge", "caller", |mut caller: Caller<'_, State<H>>, out: i32, max: i32| -> i32 {
                if !caller.data_mut().tick() {
                    return -4;
                }
                match caller.data().host.caller() {
                    Some(id) => write(&mut caller, out, max, &id),
                    None => -1,
                }
            })
            .map_err(invalid)?;
    }
    if grants.kv {
        linker
            .func_wrap(
                "bridge",
                "kv_get",
                |mut caller: Caller<'_, State<H>>, kptr: i32, klen: i32, out: i32, max: i32| -> i32 {
                    if !caller.data_mut().tick() {
                        return -4;
                    }
                    let Some(key) = read(&caller, kptr, klen, MAX_KEY_BYTES) else { return -3 };
                    match caller.data_mut().host.kv_get(&key) {
                        Some(value) => write(&mut caller, out, max, &value),
                        None => -1,
                    }
                },
            )
            .map_err(invalid)?;
        linker
            .func_wrap(
                "bridge",
                "kv_put",
                |mut caller: Caller<'_, State<H>>, kptr: i32, klen: i32, vptr: i32, vlen: i32| -> i32 {
                    if !caller.data_mut().tick() {
                        return -4;
                    }
                    let (Some(key), Some(value)) =
                        (read(&caller, kptr, klen, MAX_KEY_BYTES), read(&caller, vptr, vlen, MAX_VALUE_BYTES))
                    else {
                        return -3;
                    };
                    if caller.data_mut().host.kv_put(&key, &value).is_ok() { 0 } else { -1 }
                },
            )
            .map_err(invalid)?;
    }
    if grants.events {
        linker
            .func_wrap("bridge", "event_append", |mut caller: Caller<'_, State<H>>, ptr: i32, len: i32| -> i32 {
                if !caller.data_mut().tick() {
                    return -4;
                }
                let Some(data) = read(&caller, ptr, len, MAX_VALUE_BYTES) else { return -3 };
                if caller.data_mut().host.event_append(&data).is_ok() { 0 } else { -1 }
            })
            .map_err(invalid)?;
        linker
            .func_wrap("bridge", "event_count", |mut caller: Caller<'_, State<H>>| -> i64 {
                if !caller.data_mut().tick() {
                    return -4;
                }
                i64::try_from(caller.data().host.event_count()).unwrap_or(i64::MAX)
            })
            .map_err(invalid)?;
        linker
            .func_wrap(
                "bridge",
                "event_read",
                |mut caller: Caller<'_, State<H>>, index: i64, out: i32, max: i32| -> i32 {
                    if !caller.data_mut().tick() {
                        return -4;
                    }
                    let Ok(index) = u64::try_from(index) else { return -1 };
                    match caller.data().host.event_read(index) {
                        Some(event) => write(&mut caller, out, max, &event),
                        None => -1,
                    }
                },
            )
            .map_err(invalid)?;
    }
    Ok(())
}

/// Checks a module against the ABI without running it: valid WebAssembly, imports only granted `bridge` functions,
/// exports `memory`, `alloc` and `entry`.
pub fn check(module: &[u8], entry: &str, grants: Grants, limits: Limits) -> Result<(), WasmError> {
    let engine = engine(limits)?;
    let module = compile(&engine, module)?;
    check_module(&module, entry, grants)
}

fn engine(limits: Limits) -> Result<Engine, WasmError> {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .floats(!limits.deterministic)
        // SIMD and memory64 are not compiled in (crate features); multiple memories and references are off.
        .wasm_multi_memory(false)
        .wasm_reference_types(false)
        .set_max_recursion_depth(1024)
        .compilation_mode(CompilationMode::Lazy);
    Ok(Engine::new(&config))
}

fn compile(engine: &Engine, module: &[u8]) -> Result<Module, WasmError> {
    if module.len() > MAX_MODULE_BYTES {
        return Err(WasmError::Limit("module larger than 4 MiB".into()));
    }
    Module::new(engine, module).map_err(|error| WasmError::Invalid(error.to_string()))
}

fn check_module(module: &Module, entry: &str, grants: Grants) -> Result<(), WasmError> {
    for import in module.imports() {
        let ok = import.module() == "bridge"
            && ALL_IMPORTS.contains(&import.name())
            && granted(grants, import.name())
            && matches!(import.ty(), ExternType::Func(_));
        if !ok {
            return Err(WasmError::Invalid(format!(
                "import {}.{} is not granted (only bridge.* of the granted capabilities)",
                import.module(),
                import.name()
            )));
        }
    }
    for name in ["memory", "alloc", entry] {
        if module.get_export(name).is_none() {
            return Err(WasmError::Invalid(format!("export {name} missing")));
        }
    }
    Ok(())
}

/// Runs `entry` of `module` with `input` under `limits`, with the capabilities `grants` served by `host`.
pub fn run<H: Host>(
    module: &[u8],
    entry: &str,
    input: &[u8],
    limits: Limits,
    grants: Grants,
    host: H,
) -> Result<(Outcome, H), WasmError> {
    if limits.fuel == 0 || limits.fuel > MAX_FUEL {
        return Err(WasmError::Limit(format!("fuel: 1..={MAX_FUEL}")));
    }
    if limits.memory_bytes > MAX_MEMORY_BYTES || limits.io_bytes > MAX_IO_BYTES {
        return Err(WasmError::Limit("memory or I/O above the maximum".into()));
    }
    if input.len() > limits.io_bytes {
        return Err(WasmError::Limit("input too large".into()));
    }
    let engine = engine(limits)?;
    let module = compile(&engine, module)?;
    check_module(&module, entry, grants)?;
    let store_limits = StoreLimitsBuilder::new()
        .memory_size(limits.memory_bytes)
        .table_elements(MAX_TABLE_ELEMENTS)
        .instances(1)
        .tables(1)
        .memories(1)
        .trap_on_grow_failure(false)
        .build();
    let mut store = Store::new(&engine, State { limits: store_limits, host, io_bytes: limits.io_bytes, calls: 0 });
    store.limiter(|state| &mut state.limits);
    store.set_fuel(limits.fuel).map_err(|error| WasmError::Limit(error.to_string()))?;
    let mut linker = <Linker<State<H>>>::new(&engine);
    link(&mut linker, grants)?;
    let instance: Instance = linker.instantiate_and_start(&mut store, &module).map_err(trap)?;
    let memory = instance.get_memory(&store, "memory").ok_or_else(|| WasmError::Invalid("no memory".into()))?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "alloc")
        .map_err(|_| WasmError::Invalid("alloc: (i32) -> i32".into()))?;
    let call = instance
        .get_typed_func::<(i32, i32), i64>(&store, entry)
        .map_err(|_| WasmError::Invalid(format!("{entry}: (i32, i32) -> i64")))?;
    let len = i32::try_from(input.len()).map_err(|_| WasmError::Limit("input too large".into()))?;
    let ptr = alloc.call(&mut store, len).map_err(trap)?;
    let at = usize::try_from(ptr).map_err(|_| WasmError::Trap("alloc returned a negative pointer".into()))?;
    memory.write(&mut store, at, input).map_err(|_| WasmError::Trap("alloc returned memory out of bounds".into()))?;
    let packed = call.call(&mut store, (ptr, len)).map_err(trap)?;
    let packed = packed as u64;
    let (out_ptr, out_len) = ((packed >> 32) as usize, (packed & 0xFFFF_FFFF) as usize);
    if out_len > store.data().io_bytes {
        return Err(WasmError::Limit("output too large".into()));
    }
    let mut output = vec![0u8; out_len];
    memory.read(&store, out_ptr, &mut output).map_err(|_| WasmError::Trap("output out of bounds".into()))?;
    let left = store.get_fuel().unwrap_or(0);
    let fuel_used = limits.fuel.saturating_sub(left);
    let State { host, .. } = store.into_data();
    Ok((Outcome { output, fuel_used }, host))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// A module: `alloc` hands out memory from offset 1024; `run` returns the input reversed; `spin` loops forever;
    /// `grow` grows the memory by 1000 pages; `kv` stores the input under "k" and returns what was there.
    const MODULE: &str = r#"
      (module
        (import "bridge" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
        (import "bridge" "kv_put" (func $kv_put (param i32 i32 i32 i32) (result i32)))
        (import "bridge" "log" (func $log (param i32 i32)))
        (memory (export "memory") 1 1000)
        (data (i32.const 16) "k")
        (func (export "alloc") (param i32) (result i32) i32.const 1024)
        (func (export "run") (param $p i32) (param $l i32) (result i64)
          (local $i i32)
          (loop $copy
            (if (i32.lt_u (local.get $i) (local.get $l))
              (then
                (i32.store8
                  (i32.add (i32.const 8192) (local.get $i))
                  (i32.load8_u (i32.sub (i32.add (local.get $p) (local.get $l)) (i32.add (local.get $i) (i32.const 1)))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $copy))))
          (call $log (local.get $p) (local.get $l))
          (i64.or (i64.shl (i64.const 8192) (i64.const 32)) (i64.extend_i32_u (local.get $l))))
        (func (export "spin") (param i32 i32) (result i64) (loop (br 0)) i64.const 0)
        (func (export "grow") (param i32 i32) (result i64) (drop (memory.grow (i32.const 1000))) i64.const 0)
        (func (export "kv") (param $p i32) (param $l i32) (result i64)
          (local $n i32)
          (local.set $n (call $kv_get (i32.const 16) (i32.const 1) (i32.const 4096) (i32.const 100)))
          (drop (call $kv_put (i32.const 16) (i32.const 1) (local.get $p) (local.get $l)))
          (if (i32.lt_s (local.get $n) (i32.const 0)) (then (local.set $n (i32.const 0))))
          (i64.or (i64.shl (i64.const 4096) (i64.const 32)) (i64.extend_i32_u (local.get $n)))))"#;

    #[derive(Default)]
    struct TestHost {
        kv: BTreeMap<Vec<u8>, Vec<u8>>,
        lines: Vec<String>,
    }

    impl Host for TestHost {
        fn log(&mut self, line: &str) {
            self.lines.push(line.to_owned());
        }
        fn kv_get(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            self.kv.get(key).cloned()
        }
        fn kv_put(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.kv.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
    }

    fn module() -> Vec<u8> {
        wat::parse_str(MODULE).unwrap_or_default()
    }

    const ALL: Grants = Grants { log: true, caller: false, kv: true, events: false };

    #[test]
    fn runs_with_its_capabilities() -> Result<(), WasmError> {
        let (outcome, host) = run(&module(), "run", b"hallo", Limits::default(), ALL, TestHost::default())?;
        assert_eq!(outcome.output, b"ollah");
        assert!(outcome.fuel_used > 0);
        assert_eq!(host.lines, ["hallo"]);
        let (first, host) = run(&module(), "kv", b"eins", Limits::default(), ALL, host)?;
        assert_eq!(first.output, b"");
        let (second, _) = run(&module(), "kv", b"zwei", Limits::default(), ALL, host)?;
        assert_eq!(second.output, b"eins", "the store keeps what the module put");
        Ok(())
    }

    /// The same call gives the same output and the same fuel (compute results are checked by recomputing them).
    #[test]
    fn deterministic() -> Result<(), WasmError> {
        let a = run(&module(), "run", b"abc", Limits::default(), ALL, TestHost::default())?.0;
        let b = run(&module(), "run", b"abc", Limits::default(), ALL, TestHost::default())?.0;
        assert_eq!(a, b);
        Ok(())
    }

    /// Attack: endless loops, memory growth, ungranted imports, foreign imports, garbage, oversize input.
    #[test]
    fn limits_and_refusals() {
        let limits = Limits { fuel: 1_000_000, ..Limits::default() };
        assert!(matches!(run(&module(), "spin", b"", limits, ALL, TestHost::default()), Err(WasmError::Limit(_))));
        let small = Limits { memory_bytes: 2 * 65_536, ..Limits::default() };
        // memory.grow beyond the limit returns -1 (no trap) - the module cannot get more.
        assert!(run(&module(), "grow", b"", small, ALL, TestHost::default()).is_ok());
        let no_kv = Grants { kv: false, ..ALL };
        assert!(matches!(run(&module(), "run", b"x", Limits::default(), no_kv, NoHost), Err(WasmError::Invalid(_))));
        let foreign = wat::parse_str(
            r#"(module (import "wasi" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
                 (memory (export "memory") 1) (func (export "alloc") (param i32) (result i32) i32.const 0)
                 (func (export "run") (param i32 i32) (result i64) i64.const 0))"#,
        )
        .unwrap_or_default();
        assert!(matches!(run(&foreign, "run", b"", Limits::default(), ALL, NoHost), Err(WasmError::Invalid(_))));
        assert!(matches!(
            run(b"\0asm garbage", "run", b"", Limits::default(), ALL, NoHost),
            Err(WasmError::Invalid(_))
        ));
        let big = vec![0u8; MAX_IO_BYTES + 1];
        assert!(matches!(
            run(&module(), "run", &big, Limits::default(), ALL, TestHost::default()),
            Err(WasmError::Limit(_))
        ));
        assert!(run(&module(), "run", b"", Limits { fuel: 0, ..Limits::default() }, ALL, TestHost::default()).is_err());
        assert!(run(&module(), "nope", b"", Limits::default(), ALL, TestHost::default()).is_err());
        // Floating point is refused in the deterministic mode.
        let floats = wat::parse_str(
            r#"(module (memory (export "memory") 1) (func (export "alloc") (param i32) (result i32) i32.const 0)
                 (func (export "run") (param i32 i32) (result i64) f64.const 1.5 f64.const 2 f64.add drop i64.const 0))"#,
        )
        .unwrap_or_default();
        assert!(run(&floats, "run", b"", Limits::default(), Grants::default(), NoHost).is_err());
        let relaxed = Limits { deterministic: false, ..Limits::default() };
        assert!(run(&floats, "run", b"", relaxed, Grants::default(), NoHost).is_ok());
    }

    /// Attack: a module that calls the host in a tight loop (cheap in fuel, dear for the host) - after
    /// [`MAX_HOST_CALLS`] every call is refused.
    #[test]
    fn host_calls_are_budgeted() -> Result<(), WasmError> {
        let looping = wat::parse_str(
            r#"(module
                 (import "bridge" "kv_put" (func $put (param i32 i32 i32 i32) (result i32)))
                 (memory (export "memory") 1)
                 (func (export "alloc") (param i32) (result i32) i32.const 0)
                 (func (export "run") (param i32 i32) (result i64)
                   (local $i i32) (local $refused i32)
                   (loop $again
                     (if (i32.eq (call $put (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 1)) (i32.const -4))
                       (then (local.set $refused (i32.add (local.get $refused) (i32.const 1)))))
                     (local.set $i (i32.add (local.get $i) (i32.const 1)))
                     (br_if $again (i32.lt_u (local.get $i) (i32.const 2000))))
                   (i32.store (i32.const 100) (local.get $refused))
                   (i64.or (i64.shl (i64.const 100) (i64.const 32)) (i64.const 4))))"#,
        )
        .unwrap_or_default();
        let grants = Grants { kv: true, ..Grants::default() };
        let (outcome, host) = run(&looping, "run", b"", Limits::default(), grants, TestHost::default())?;
        assert_eq!(outcome.output, 1000u32.to_le_bytes(), "the second thousand is refused");
        assert_eq!(host.kv.len(), 1);
        Ok(())
    }

    #[test]
    fn output_out_of_bounds_is_a_trap() {
        let bad = wat::parse_str(
            r#"(module (memory (export "memory") 1) (func (export "alloc") (param i32) (result i32) i32.const 0)
                 (func (export "run") (param i32 i32) (result i64) i64.const 0x7FFFFFF000000100))"#,
        )
        .unwrap_or_default();
        assert!(run(&bad, "run", b"", Limits::default(), Grants::default(), NoHost).is_err());
    }
}
