mod state;
mod coordinator_client;
mod worker;
mod replicator;
mod runtime_service;

use std::sync::Arc;
use std::net::SocketAddr;
use std::env;
use uuid::Uuid;
use tracing::{info, error, Level};
use tracing_subscriber;
use tokio::sync::Notify;

use dsdn_storage::proto::storage_server::StorageServer as GeneratedStorageServer;
use dsdn_storage::proto::runtime_server::RuntimeServer as GeneratedRuntimeServer;

use dsdn_storage::rpc::DsdnStorageService;
use crate::runtime_service::RuntimeService;
use state::NodeState;
use coordinator_client::CoordinatorClient;
use dsdn_storage::localfs::LocalFsStorage;
use worker::Worker;

#[tokio::main]
async fn main() {
    // init tracing with INFO level by default (prints to stdout)
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        error!("Usage: dsdn-node <node-id|auto> <zone> <storage_port> <coordinator_base_url> <data_dir>");
        error!("Example: dsdn-node auto zone-a 50051 http://127.0.0.1:8080 ./data/node1");
        std::process::exit(2);
    }

    // parse args
    let node_id = if args[1] == "auto" {
        Uuid::new_v4().to_string()
    } else {
        args[1].clone()
    };
    let zone = args[2].clone();
    let storage_port: u16 = args[3].parse().expect("invalid port");
    let coord_base = args[4].clone();
    let data_dir = args[5].clone();

    let addr = format!("127.0.0.1:{}", storage_port);
    let storage_addr: SocketAddr = addr.parse().expect("invalid storage addr");
    let storage_http_addr = format!("127.0.0.1:{}", storage_port); // used for client connect "127.0.0.1:50051"

    info!("Starting node {} zone {} data_dir {}", node_id, zone, data_dir);

    // create localfs store and wrap in Arc
    let store = Arc::new(LocalFsStorage::new(&data_dir).expect("create store"));
    // register node to coordinator
    let coord = Arc::new(CoordinatorClient::new(coord_base.clone()));

    match coord.register_node(&node_id, &zone, &storage_http_addr, 100).await {
        Ok(_) => info!("registered node {} to coordinator {}", node_id, coord_base),
        Err(e) => error!("failed register node: {}", e),
    }

    // start combined storage gRPC + runtime gRPC server in background
    let shutdown_notify = Arc::new(Notify::new());
    let server_store = store.clone();
    let server_shutdown = shutdown_notify.clone();

    // storage service
    let storage_svc = dsdn_storage::rpc::DsdnStorageService::new(server_store.clone());
    // runtime service
    let runtime_svc = runtime_service::RuntimeService::new(
        server_store.clone(),
        coord.clone(),
        node_id.clone(),
    );

    let server_task = tokio::spawn(async move {
        let addr = storage_addr;
        info!("🚀 Starting combined gRPC server (Storage + Runtime) at {}", addr);

        let svc_storage = GeneratedStorageServer::new(storage_svc);
        let svc_runtime = GeneratedRuntimeServer::new(runtime_svc);

        tonic::transport::Server::builder()
            .add_service(svc_storage)
            .add_service(svc_runtime)
            .serve_with_shutdown(addr, async {
                server_shutdown.notified().await;
            })
            .await
            .unwrap_or_else(|e| error!("gRPC server error: {}", e));
    });

    // start worker
    let state = Arc::new(NodeState::new(node_id.clone(), data_dir.clone()));
    let worker = Arc::new(Worker::new(
        store.clone(),
        state.clone(),
        coord.clone(),
        node_id.clone(),
        3,      // rf
        6,      // interval seconds (small for dev)
        shutdown_notify.clone(),
    ));
    let worker_handle = worker.start();

    // listen for ctrl-c
    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    info!("shutdown requested");
    shutdown_notify.notify_waiters();

    // wait for tasks
    let _ = worker_handle.await;
    let _ = server_task.await;
    info!("node stopped");
}
