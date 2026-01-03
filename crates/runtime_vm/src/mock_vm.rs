use crate::{MicroVM, MicroVmError, MicroVmResult, ExecOutput};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use tracing::{info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockVMConfig {
    pub name: String,
    pub background_sleep_seconds: u64,
}

impl Default for MockVMConfig {
    fn default() -> Self {
        MockVMConfig {
            name: "mockvm".into(),
            background_sleep_seconds: 3600,
        }
    }
}

#[derive(Clone)]
pub struct MockVMController {
    inner: Arc<Mutex<MockVMInner>>,
}

struct MockVMInner {
    config: MockVMConfig,
    child: Option<tokio::process::Child>,
}

impl MockVMController {
    pub fn new(config: MockVMConfig) -> Self {
        let inner = MockVMInner { config, child: None };
        Self { inner: Arc::new(Mutex::new(inner)) }
    }
}

#[async_trait]
impl MicroVM for MockVMController {
    async fn start(&mut self) -> MicroVmResult<()> {
        let mut inner = self.inner.lock().await;
        if inner.child.is_some() {
            return Ok(());
        }

        #[cfg(unix)]
        let mut cmd = {
            let s = format!("sleep {}", inner.config.background_sleep_seconds);
            let mut c = Command::new("sh");
            c.arg("-c").arg(s);
            c
        };

        #[cfg(windows)]
        let mut cmd = {
            let s = format!("Start-Sleep -Seconds {}", inner.config.background_sleep_seconds);
            let mut c = Command::new("powershell");
            c.arg("-NoProfile").arg("-Command").arg(s);
            c
        };

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                inner.child = Some(child);
                info!("MockVM started");
                Ok(())
            }
            Err(e) => Err(MicroVmError::Process(format!("spawn error: {}", e))),
        }
    }

    async fn stop(&mut self) -> MicroVmResult<()> {
        let mut inner = self.inner.lock().await;

        if let Some(mut c) = inner.child.take() {
            let _ = c.kill().await;
            let _ = c.wait().await;
        }

        Ok(())
    }

    async fn exec(&self, cmd: Vec<String>, timeout_ms: Option<u64>) -> MicroVmResult<ExecOutput> {
        if cmd.is_empty() {
            return Err(MicroVmError::Other("empty command".into()));
        }

        let program = &cmd[0];
        let args = &cmd[1..];

        let mut command = Command::new(program);
        for a in args {
            command.arg(a);
        }

        command.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // ---- spawn ----
        let child = command.spawn()
            .map_err(|e| MicroVmError::Process(format!("spawn failed: {}", e)))?;

        // CHILD DISIMPAN DALAM ARC<MUTEX<Option<Child>>>
        use tokio::sync::Mutex as TokioMutex;
        let child_box = Arc::new(TokioMutex::new(Some(child)));

        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        let child_box_clone = child_box.clone();

        // ---- TASK ----
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = kill_rx => {
                    let mut guard = child_box_clone.lock().await;

                    if let Some(mut c) = guard.take() {
                        let _ = c.kill().await;
                        let _ = c.wait().await;
                    }

                    Err(MicroVmError::Process("killed".into()))
                }

                output = async {
                    let mut guard = child_box_clone.lock().await;

                    if let Some(mut c) = guard.take() {
                        c.wait_with_output().await
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::Other, "child gone"))
                    }
                } => {
                    match output {
                        Ok(out) => Ok(out),
                        Err(e) => Err(MicroVmError::Process(format!("wait error: {}", e))),
                    }
                }
            }
        });

        // ---- TIMEOUT ----
        if let Some(ms) = timeout_ms {
            match timeout(Duration::from_millis(ms), task).await {
                Ok(join_out) => match join_out {
                    Ok(Ok(out)) => Ok(ExecOutput {
                        stdout: out.stdout,
                        stderr: out.stderr,
                        exit_code: out.status.code(),
                        timed_out: false,
                    }),
                    Ok(Err(e)) => Err(e),
                    Err(e) => Err(MicroVmError::Process(format!("join error: {}", e))),
                },
                Err(_) => {
                    let _ = kill_tx.send(());
                    Ok(ExecOutput {
                        stdout: vec![],
                        stderr: vec![],
                        exit_code: None,
                        timed_out: true,
                    })
                }
            }
        } else {
            match task.await {
                Ok(Ok(out)) => Ok(ExecOutput {
                    stdout: out.stdout,
                    stderr: out.stderr,
                    exit_code: out.status.code(),
                    timed_out: false,
                }),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(MicroVmError::Process(format!("task error: {}", e))),
            }
        }
    }


}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MicroVM;

    #[tokio::test]
    async fn test_mockvm_start_exec_stop() {
        let mut vm = MockVMController::new(MockVMConfig::default());
        vm.start().await.unwrap();

        #[cfg(windows)]
        let cmd = vec![
            "powershell".into(), "-NoProfile".into(), "-Command".into(),
            "Write-Output 'Hello from MockVM'".into()
        ];

        #[cfg(unix)]
        let cmd = vec![
            "sh".into(), "-c".into(), "echo Hello from MockVM".into()
        ];

        let out = vm.exec(cmd, Some(3000)).await.unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("Hello"));

        vm.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_mockvm_exec_timeout() {
        let mut vm = MockVMController::new(MockVMConfig::default());
        vm.start().await.unwrap();

        #[cfg(windows)]
        let cmd = vec![
            "powershell".into(), "-NoProfile".into(), "-Command".into(),
            "Start-Sleep -Seconds 10".into()
        ];

        #[cfg(unix)]
        let cmd = vec!["sh".into(), "-c".into(), "sleep 10".into()];

        let out = vm.exec(cmd, Some(100)).await.unwrap();
        assert!(out.timed_out);

        vm.stop().await.unwrap();
    }
}
