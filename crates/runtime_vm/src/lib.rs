//! runtime_vm public API
//! Defines the MicroVM trait and common types used by mock_vm and future real VM implementations.

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
