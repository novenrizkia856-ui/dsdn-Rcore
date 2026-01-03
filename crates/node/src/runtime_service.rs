// crates/node/src/runtime_service.rs

use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use anyhow::Result as AnyResult;

use dsdn_storage::proto::{
    RunWasmRequest, RunWasmResponse,
    runtime_server::Runtime,
};

use dsdn_storage::localfs::LocalFsStorage;
use crate::coordinator_client::CoordinatorClient;
use dsdn_storage::rpc as storage_rpc;
use dsdn_storage::store::Storage as StorageTrait;

use dsdn_runtime_wasm::{RuntimeLimits, run_wasm};

#[derive(Clone)]
pub struct RuntimeService {
    store: Arc<LocalFsStorage>,
    coord: Arc<CoordinatorClient>,
    node_id: String,
}

impl RuntimeService {
    pub fn new(
        store: Arc<LocalFsStorage>,
        coord: Arc<CoordinatorClient>,
        node_id: String,
    ) -> Self {
        Self { store, coord, node_id }
    }

    /// Try to get module bytes locally or from peers
    async fn fetch_module_bytes(&self, module_hash: &str) -> AnyResult<Vec<u8>> {
        // 1) local
        match self.store.get_chunk(module_hash) {
            Ok(Some(b)) => {
                info!("module {} found locally", module_hash);
                return Ok(b);
            }
            Ok(None) => {}
            Err(e) => return Err(anyhow::anyhow!("local get_chunk error: {}", e)),
        }

        // 2) peers
        let nodes = self.coord.list_nodes().await?;
        for n in nodes {
            if n.id == self.node_id {
                continue;
            }

            let addr = format!("http://{}", n.addr);
            info!("Try fetch {} from {}", module_hash, addr);

            match storage_rpc::client_get(addr.clone(), module_hash.to_string()).await {
                Ok(Some(data)) => {
                    info!("fetched {} from {}", module_hash, n.id);
                    return Ok(data);
                }
                Ok(None) => { /* node doesn't have it */ }
                Err(e) => warn!("fetch error from {}: {}", n.id, e),
            }
        }

        Err(anyhow::anyhow!("module {} not found on any node", module_hash))
    }
}

#[tonic::async_trait]
impl Runtime for RuntimeService {
    async fn run_wasm(
        &self,
        request: Request<RunWasmRequest>,
    ) -> Result<Response<RunWasmResponse>, Status> {
        let req = request.into_inner();
        let module_hash = req.module_hash;
        let input = req.input;
        let timeout_ms = if req.timeout_ms == 0 { 2000 } else { req.timeout_ms as u64 };
        let max_mem = if req.max_mem_bytes == 0 { 16 * 1024 * 1024 } else { req.max_mem_bytes as usize };

        info!(
            "RunWasm: hash={} timeout={} mem={}",
            module_hash, timeout_ms, max_mem
        );

        // 1) fetch module bytes
        let module_bytes = match self.fetch_module_bytes(&module_hash).await {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("module fetch error: {}", e);
                warn!("{}", msg);
                return Ok(Response::new(RunWasmResponse {
                    output: vec![],
                    status: msg,
                }));
            }
        };

        // 2) prepare callback storage
        let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
        let collected2 = collected.clone();

        // 3) run WASM (non-async)
        let limits = RuntimeLimits {
            timeout_ms,
            max_memory_bytes: max_mem,
        };

        let result = run_wasm(
            &module_bytes,
            &input,
            limits,
            move |data: &[u8]| -> anyhow::Result<()> {
                match collected2.lock() {
                    Ok(mut g) => {
                        g.extend_from_slice(data);
                        Ok(())
                    }
                    Err(_) => Err(anyhow::anyhow!("mutex poisoned")),
                }
            }
        );

        // 4) handle results
        match result {
            Ok(out) => {
                // WASM runtime also stores stdout inside `out.stdout`
                let mut v = collected.lock().unwrap().clone();
                if !out.stdout.is_empty() {
                    v.extend_from_slice(&out.stdout);
                }

                return Ok(Response::new(RunWasmResponse {
                    output: v,
                    status: "ok".into(),
                }));
            }
            Err(e) => {
                let msg = format!("runtime error: {}", e);
                warn!("{}", msg);

                let v = collected.lock().unwrap().clone();
                return Ok(Response::new(RunWasmResponse {
                    output: v,
                    status: msg,
                }));
            }
        }
    }
}
