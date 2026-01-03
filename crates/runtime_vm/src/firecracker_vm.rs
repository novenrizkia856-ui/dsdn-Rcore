use crate::{MicroVM, MicroVmError, MicroVmResult, ExecOutput};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::path::PathBuf;

/// Simplified Firecracker config structure.
/// In production you'll want to provide kernel image, rootfs, machine config, network bridges, vsock ports etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerConfig {
    pub id: String,
    /// Path to firecracker binary (if empty, default "firecracker" is used)
    pub firecracker_bin: PathBuf,
    /// Path to kernel image (vmlinuz)
    pub kernel_image: PathBuf,
    /// Path to rootfs (ext4 or raw)
    pub rootfs: PathBuf,
    /// path to API unix socket (where firecracker listens for configuration)
    pub api_socket: PathBuf,
    /// memory in MiB
    pub mem_mib: u32,
    /// vcpu count
    pub vcpu_count: u8,
}

/// A minimal Firecracker VM controller skeleton.
/// This struct only contains config and placeholder state.
/// Implementing full lifecycle requires:
///  - starting firecracker process with --api-sock
///  - posting configuration to the API socket (machine-config, boot-source, rootfs, network)
///  - starting the microVM via /actions
///  - using vsock to execute commands inside the guest (e.g. a small agent listening on vsock)
///
/// This implementation is intentionally partial: it provides structure and proper error messages,
/// so you can extend it to a real Firecracker integration on Linux.
#[derive(Debug)]
pub struct FirecrackerVM {
    pub cfg: FirecrackerConfig,
    // TODO: store process handle, vsock client, status, pid, etc.
}

impl FirecrackerVM {
    pub fn new(cfg: FirecrackerConfig) -> Self {
        Self { cfg }
    }
}

#[async_trait]
impl MicroVM for FirecrackerVM {
    async fn start(&mut self) -> MicroVmResult<()> {
        // Production steps (outline):
        // 1. Spawn the firecracker binary with --api-sock <path>
        // 2. POST machine config, boot-source (kernel + boot args) and root-drive via the API socket
        // 3. POST /actions to start the microVM
        // 4. Wait for guest to boot and agent/listener inside guest to be available (vsock)
        //
        // Because Firecracker isn't available on all systems and requires kernel + rootfs,
        // we don't run it automatically here. Instead we return NotImplemented with detailed guidance.
        Err(MicroVmError::NotImplemented(
            "FirecrackerVM.start(): not implemented in this environment. \
             To implement: spawn firecracker binary, configure via API socket, start VM, and connect via vsock."
                .into(),
        ))
    }

    async fn stop(&mut self) -> MicroVmResult<()> {
        // Implementation would issue action to shutdown or kill the process if running.
        Err(MicroVmError::NotImplemented("FirecrackerVM.stop() not implemented".into()))
    }

    async fn exec(&self, _cmd: Vec<String>, _timeout_ms: Option<u64>) -> MicroVmResult<ExecOutput> {
        // Exec inside Firecracker typically requires an agent inside guest listening on vsock and executing commands on behalf of host.
        // The host would write a request to the vsock port, wait for response.
        Err(MicroVmError::NotImplemented("FirecrackerVM.exec() not implemented. Use vsock agent in guest.".into()))
    }
}
