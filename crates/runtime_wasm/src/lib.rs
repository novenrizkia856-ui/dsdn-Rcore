//! # runtime_wasm — WASM Runtime with Execution Commitment (14C.B)
//!
//! A wrapper around wasmtime to run WASM/WASI modules under resource limits,
//! with deterministic execution commitment production for fraud-proof
//! reproducibility.
//!
//! ## Core API
//!
//! - `run_wasm(module_bytes, input_bytes, limits, host_io_callback)` → `Result<Output>`
//!   Low-level WASM execution with resource limits and host I/O callback.
//!
//! ## Execution Commitment Pipeline
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                WASM EXECUTION COMMITMENT PIPELINE                   │
//! │                                                                     │
//! │  module_bytes + input_bytes                                         │
//! │       │                                                             │
//! │       ▼                                                             │
//! │  ┌─────────────────┐                                               │
//! │  │   run_wasm()    │──── wasmtime execution                        │
//! │  └────────┬────────┘                                               │
//! │           │ stdout, resource usage                                  │
//! │           ▼                                                         │
//! │  ┌─────────────────────────────────────────────────────┐           │
//! │  │            WasmExecutionResult                       │           │
//! │  │  input_hash ── SHA3-256(input)                      │           │
//! │  │  output_hash ── SHA3-256(output)                    │           │
//! │  │  state_root_before ── hash(pre-exec state)          │           │
//! │  │  state_root_after ── hash(post-exec state)          │           │
//! │  │  execution_trace_merkle_root ── binary Merkle tree  │           │
//! │  │  resource_usage ── cpu, memory, time                │           │
//! │  └────────────────────┬────────────────────────────────┘           │
//! │                       │                                             │
//! │                       ▼                                             │
//! │              ExecutionCommitment                                    │
//! │              (dsdn_common native type)                              │
//! │                       │                                             │
//! │                       ▼                                             │
//! │              Coordinator receipt signing                            │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | `execution_result` | `WasmExecutionResult` and `ResourceUsage` types (14C.B.1) |
//! | `merkle` | Deterministic binary Merkle tree over execution traces (14C.B.1) |
//! | `state_capture` | Domain-separated SHA3-256 hashing for input, output, memory (14C.B.2) |
//!
//! ## Merkle Tree — Cross-Crate Compatibility
//!
//! `merkle::compute_trace_merkle_root` implements the **exact same algorithm**
//! as `coordinator::execution::compute_trace_merkle_root`:
//!
//! - Leaf: `SHA3-256(step_bytes)`
//! - Parent: `SHA3-256(left ‖ right)`
//! - Odd count: duplicate last node
//! - Empty: `[0u8; 32]`
//!
//! This is consensus-critical. Any byte-level divergence between the runtime
//! and coordinator Merkle implementations breaks fraud-proof reproducibility.
//!
//! ## Determinism Requirements
//!
//! For fraud-proof verification, WASM execution must be deterministic:
//! same module + same input → same `WasmExecutionResult` → same
//! `ExecutionCommitment`. All hash functions use SHA3-256 with fixed
//! domain separators. No randomness, no system time dependency in
//! commitment-critical paths.

use anyhow::Result as AnyResult;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::sync::mpsc;
use thiserror::Error;
use wasmtime::{Engine, Module, Store, Linker, Caller, Extern};
use wasmtime_wasi::{WasiCtxBuilder, WasiCtx};
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════════════════════════════════════════
// EXECUTION COMMITMENT MODULES (14C.B.1)
// ════════════════════════════════════════════════════════════════════════════════

/// Execution result types for committed WASM execution.
pub mod execution_result;

/// Deterministic binary Merkle tree (SHA3-256).
/// Algorithm identical to coordinator's `compute_trace_merkle_root`.
pub mod merkle;

/// Domain-separated SHA3-256 hashing for WASM execution state (14C.B.2).
///
/// Provides three pure hashing functions with distinct domain prefixes:
/// - `hash_input`: prefix `DSDN:wasm_input:v1:` — hash workload input before execution
/// - `hash_output`: prefix `DSDN:wasm_output:v1:` — hash captured stdout after execution
/// - `hash_memory_snapshot`: prefix `DSDN:wasm_memory:v1:` — hash WASM linear memory
///
/// Domain separation prevents cross-context collisions: identical bytes
/// hashed as "input" vs "output" produce different digests. The `v1`
/// version tag enables future scheme changes without breaking existing
/// commitments.
///
/// These hashes feed directly into [`WasmExecutionResult`] fields
/// (`input_hash`, `output_hash`, `state_root_before`, `state_root_after`)
/// and must be deterministic for fraud-proof reproducibility.
pub mod state_capture;

pub use execution_result::{WasmExecutionResult, ResourceUsage};
pub use merkle::compute_trace_merkle_root;
pub use state_capture::{hash_input, hash_output, hash_memory_snapshot};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeLimits {
    /// maximum execution time (wall clock) in milliseconds
    pub timeout_ms: u64,
    /// maximum initial linear memory in bytes allowed for module (we enforce after instantiation)
    pub max_memory_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        RuntimeLimits {
            timeout_ms: 2000,
            max_memory_bytes: 16 * 1024 * 1024, // 16 MiB default
        }
    }
}

#[derive(Debug, Clone)]
pub struct Output {
    /// bytes that guest wrote via host write callback
    pub stdout: Vec<u8>,
}

/// Errors from runtime
#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("wasm validation/compile error: {0}")]
    CompileError(String),

    #[error("module requested too much memory: {0} bytes (limit {1})")]
    MemoryLimitExceeded(usize, usize),

    #[error("execution timeout after {0}ms")]
    Timeout(u64),

    #[error("guest runtime error: {0}")]
    Trap(String),

    #[error("host error: {0}")]
    Host(String),
}

/// Type alias
pub type RuntimeResult<T> = std::result::Result<T, RuntimeError>;

/// Run a WASM/WASI module with given limits and a host callback function used for "write" syscall.
///
/// Implementation:
/// - compile module
/// - instantiate with wasi + host fn env::write(ptr,len)
/// - after instantiation, check exported memory size (pages -> bytes)
/// - run exported "run" or "_start" in spawned thread; wait with recv_timeout for wall timeout
pub fn run_wasm<F>(
    module_bytes: &[u8],
    _input: &[u8],
    limits: RuntimeLimits,
    mut host_write: F,
) -> RuntimeResult<Output>
where
    F: FnMut(&[u8]) -> AnyResult<()> + Send + 'static,
{
    // compile module first (syntax/validation)
    let engine = Engine::default();
    let _module = Module::new(&engine, module_bytes)
        .map_err(|e| RuntimeError::CompileError(format!("failed to compile module: {}", e)))?;

    // channel for thread result
    let (tx, rx) = mpsc::sync_channel::<Result<Output, RuntimeError>>(1);

    // Move bytes into thread
    let module_owned = module_bytes.to_vec();

    thread::spawn(move || {
        let res = (|| -> RuntimeResult<Output> {
            // re-create engine/module in thread to avoid sharing store across threads
            let engine = Engine::default();
            let module = Module::new(&engine, &module_owned)
                .map_err(|e| RuntimeError::CompileError(format!("compile error(thread): {}", e)))?;

            // prepare linker + wasi
            let mut linker = Linker::new(&engine);

            // host-captured output buffer (thread-local)
            let out_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
            let out_clone = out_buf.clone();

            // host function env::write(ptr: i32, len: i32)
            // we will panic!() on error so that wasmtime yields a trap (panics inside host func -> trap)
            linker.func_wrap(
                "env",
                "write",
                move |mut caller: Caller<'_, WasiCtx>, ptr: i32, len: i32| {
                    // get memory export
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(m)) => m,
                        _ => panic!("wasm guest expects exported memory"),
                    };

                    let start = ptr as usize;
                    let len = len as usize;
                    let mut tmp = vec![0u8; len];
                    // read using caller as context
                    mem.read(&mut caller, start, &mut tmp)
                        .expect("memory read failed");
                    // append to buffer
                    let mut guard = out_clone.lock().expect("lock poisoned");
                    guard.extend_from_slice(&tmp);
                },
            ).map_err(|e| RuntimeError::Host(format!("failed to add host func: {}", e)))?;

            // wasi ctx
            let wasi = WasiCtxBuilder::new().inherit_stdout().inherit_stderr().build();
            wasmtime_wasi::add_to_linker(&mut linker, |s: &mut WasiCtx| s)
                .map_err(|e| RuntimeError::Host(format!("wasi linker failed: {}", e)))?;

            // create store with wasi ctx
            let mut store = Store::new(&engine, wasi);

            // instantiate
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| RuntimeError::Trap(format!("instantiate error: {}", e)))?;

            // after instantiation, check memory size (if any)
            if let Some(mem) = instance.get_memory(&mut store, "memory") {
                // memory.size returns pages (u64)
                let pages = mem.size(&mut store);
                // pages * 65536 -> bytes
                let bytes_needed = pages as usize * 65536usize;
                if bytes_needed > limits.max_memory_bytes {
                    return Err(RuntimeError::MemoryLimitExceeded(bytes_needed, limits.max_memory_bytes));
                }
            }

            // call exported function "run" if exists, else call "_start" if exists
            if let Some(func) = instance.get_func(&mut store, "run") {
                // try call run()
                let call_res = func.call(&mut store, &[], &mut []);
                if let Err(e) = call_res {
                    return Err(RuntimeError::Trap(format!("run trap: {}", e)));
                }
            } else if let Some(start) = instance.get_func(&mut store, "_start") {
                let call_res = start.call(&mut store, &[], &mut []);
                if let Err(e) = call_res {
                    return Err(RuntimeError::Trap(format!("_start trap: {}", e)));
                }
            } else {
                // nothing to call — allowed
            }

            // collect output
            let out_vec = match out_buf.lock() {
                Ok(g) => g.clone(),
                Err(_) => vec![],
            };

            Ok(Output { stdout: out_vec })
        })();

        // send back result (ignore send error)
        let _ = tx.send(res);
    });

    // wait with timeout
    let timeout = Duration::from_millis(limits.timeout_ms);
    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            // call host_write with captured stdout (user callback)
            if !output.stdout.is_empty() {
                if let Err(e) = host_write(&output.stdout) {
                    return Err(RuntimeError::Host(format!("host callback error: {}", e)));
                }
            }
            Ok(output)
        }
        Ok(Err(e)) => Err(e),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(RuntimeError::Timeout(limits.timeout_ms)),
        Err(e) => Err(RuntimeError::Host(format!("recv error: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use wat::parse_str;

    #[test]
    fn test_run_hello() {
        let wat = r#"
        (module
            (import "env" "write" (func $write (param i32 i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "Hello from WASM!")
            (func (export "run")
                i32.const 0
                i32.const 16
                call $write
            )
        )
        "#;
        let wasm = parse_str(wat).expect("wat->wasm");

        let limits = RuntimeLimits {
            timeout_ms: 1500,
            max_memory_bytes: 1 * 65536,
        };

        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let cap_clone = captured.clone();

        let res = run_wasm(&wasm, &[], limits.clone(), move |out: &[u8]| {
            let mut g = cap_clone.lock().map_err(|e| anyhow::anyhow!("lock err: {}", e))?;
            g.extend_from_slice(out);
            Ok(())
        });

        assert!(res.is_ok());

        let got = captured.lock().unwrap();
        let s = String::from_utf8_lossy(&got);

        assert_eq!(&s[..], "Hello from WASM!");
    }


    #[test]
    fn test_timeout() {
        let wat = r#"
        (module
            (func (export "run")
                (loop
                    br 0
                )
            )
        )
        "#;
        let wasm = parse_str(wat).expect("wat->wasm");

        let limits = RuntimeLimits {
            timeout_ms: 50,
            max_memory_bytes: 64 * 1024,
        };

        let res = run_wasm(&wasm, &[], limits, |_out| Ok(()));
        match res {
            Err(RuntimeError::Timeout(_)) => {}
            _ => panic!("expected timeout"),
        }
    }

    #[test]
    fn test_memory_limit_exceeded_rejected() {
        // declare memory 1000 pages (~64MB)
        let wat = r#"
        (module
            (memory (export "memory") 1000)
            (func (export "run") )
        )
        "#;
        let wasm = parse_str(wat).expect("wat->wasm");
        let limits = RuntimeLimits {
            timeout_ms: 1000,
            max_memory_bytes: 16 * 1024 * 1024,
        };
        let res = run_wasm(&wasm, &[], limits, |_out| Ok(()));
        match res {
            Err(RuntimeError::MemoryLimitExceeded(_needed, _limit)) => {}
            _ => panic!("expected memory limit error"),
        }
    }
}