//! runtime_vm
//!
//! This crate defines a generic abstraction layer for running isolated
//! execution environments ("micro VMs") in a uniform and async-friendly way.
//!
//! The goal of this module is to decouple higher-level runtime logic
//! (e.g. task orchestration, sandbox execution, untrusted code handling)
//! from the underlying virtualization or process implementation.
//!
//! Instead of depending directly on a specific backend (Firecracker,
//! mock process, WASM runtime, etc.), the system interacts only with
//! the `MicroVM` trait defined here.
//!
//! Implementations:
//! - `MockVMController`
//!     A lightweight process-based implementation used for testing,
//!     development, and environments where real virtualization is not available.
//!
//! - `FirecrackerVM`
//!     A skeleton for a production-grade Linux microVM backend.
//!     Intended to wrap Firecracker via its API socket and vsock interface.
//!
//! This design enables:
//! - Backend-agnostic VM orchestration
//! - Clean separation of concerns
//! - Easy testing using MockVM
//! - Future extension to additional isolation technologies
//!   (e.g. WASM sandbox, container runtime, microVM variants)
//!
//! All VM implementations must follow the lifecycle contract defined
//! by the `MicroVM` trait below.

pub mod firecracker_vm;

use async_trait::async_trait;
use thiserror::Error;

/// Execution result from VM exec
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Error, Debug)]
pub enum MicroVmError {
    #[error("process error: {0}")]
    Process(String),

    #[error("not implemented: {0}")]
    NotImplemented(String),

    #[error("other error: {0}")]
    Other(String),
}
pub type MicroVmResult<T> = Result<T, MicroVmError>;

#[async_trait]
pub trait MicroVM: Send + Sync {
    /// Start the VM / agent. Mutable because it may set internal state (child handle).
    async fn start(&mut self) -> MicroVmResult<()>;

    /// Stop the VM (kill background process etc).
    async fn stop(&mut self) -> MicroVmResult<()>;

    /// Execute a command inside the VM (or mock). `timeout_ms` optional.
    async fn exec(&self, cmd: Vec<String>, timeout_ms: Option<u64>) -> MicroVmResult<ExecOutput>;
}

// Re-export mock implementation
pub mod mock_vm;
pub use mock_vm::{MockVMConfig, MockVMController};
