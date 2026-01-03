use std::sync::Arc;
use tonic::{Request, Response, Status};
use tokio::sync::Notify;
use tonic::transport::Server;

use crate::proto::storage_server::{Storage, StorageServer};
use crate::proto::storage_client::StorageClient;
use crate::proto::{PutRequest, PutResponse, GetRequest, GetResponse};

use crate::localfs::LocalFsStorage;
use crate::store::Storage as StorageTrait;
use dsdn_common::cid::sha256_hex;

/// Struktur service utama untuk storage RPC.
#[derive(Clone)]
pub struct DsdnStorageService {
    store: Arc<LocalFsStorage>,
}

impl DsdnStorageService {
    pub fn new(store: Arc<LocalFsStorage>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl Storage for DsdnStorageService {
    async fn put(&self, request: Request<PutRequest>) -> Result<Response<PutResponse>, Status> {
        let inner = request.into_inner();

        // Hitung hash referensi dari data
        let computed = sha256_hex(&inner.data);

        // Kalau klien kirim hash manual, validasi dulu
        if !inner.hash.is_empty() && inner.hash != computed {
            let mismatch_msg = format!("hash_mismatch: expected {}, got {}", inner.hash, computed);
            return Ok(Response::new(PutResponse {
                hash: computed.clone(),
                status: mismatch_msg,
            }));
        }

        // Tentukan hash final (pakai yang dikirim atau hasil hitung)
        let final_hash = if inner.hash.is_empty() {
            computed.clone()
        } else {
            inner.hash.clone()
        };

        // Simpan chunk
        self.store
            .put_chunk(&final_hash, &inner.data)
            .map_err(|e| Status::internal(format!("storage error: {}", e)))?;

        Ok(Response::new(PutResponse {
            hash: final_hash,
            status: "ok".to_string(),
        }))
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let inner = request.into_inner();

        match self.store.get_chunk(&inner.hash) {
            Ok(Some(data)) => Ok(Response::new(GetResponse {
                data,
                status: "ok".to_string(),
            })),
            Ok(None) => Err(Status::not_found(format!("chunk not found: {}", inner.hash))),
            Err(e) => Err(Status::internal(format!("storage error: {}", e))),
        }
    }
}

/// Jalankan server gRPC untuk node storage.
/// Dipanggil di mode `server`.
pub async fn run_server(
    addr: std::net::SocketAddr,
    store: Arc<LocalFsStorage>,
    shutdown: Arc<Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let svc = DsdnStorageService::new(store);

    Server::builder()
        .add_service(StorageServer::new(svc))
        .serve_with_shutdown(addr, async {
            shutdown.notified().await;
        })
        .await?;

    Ok(())
}

/// Client helper untuk kirim chunk ke node lain (mirip seperti replikasi antar node).
pub async fn client_put(
    addr: String,
    hash: String,
    data: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut client = StorageClient::connect(addr).await?;
    let req = Request::new(PutRequest { hash, data });
    let resp = client.put(req).await?;
    Ok(resp.into_inner().hash)
}

/// Client helper untuk ambil chunk dari node lain.
pub async fn client_get(
    addr: String,
    hash: String,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut client = StorageClient::connect(addr).await?;
    let req = Request::new(GetRequest { hash });
    match client.get(req).await {
        Ok(resp) => Ok(Some(resp.into_inner().data)),
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Ok(None)
            } else {
                Err(Box::new(e))
            }
        }
    }
}
