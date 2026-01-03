use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;
use anyhow::Result;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub zone: String,
    pub addr: String,
    pub capacity_gb: u64,
    pub meta: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub hash: String,
    pub size: u64,
    pub replicas: Vec<String>,
}

#[derive(Clone)]
pub struct CoordinatorClient {
    base: String,
    client: Client,
}

impl CoordinatorClient {
    pub fn new(base: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        CoordinatorClient {
            base: base.into(),
            client,
        }
    }

    pub async fn register_node(&self, id: &str, zone: &str, addr: &str, capacity_gb: u64) -> Result<()> {
        let url = format!("{}/register", self.base);
        let body = serde_json::json!({
            "id": id,
            "zone": zone,
            "addr": addr,
            "capacity_gb": capacity_gb
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let t = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("register_node failed {} {}", status, t))
        }
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>> {
        let url = format!("{}/nodes", self.base);
        let resp = self.client.get(&url).send().await?;
        // `resp.json()` takes ownership and returns deserialized body
        let nodes = resp.json::<Vec<NodeInfo>>().await?;
        Ok(nodes)
    }

    pub async fn register_object(&self, hash: &str, size: u64) -> Result<()> {
        let url = format!("{}/object/register", self.base);
        let body = serde_json::json!({
            "hash": hash,
            "size": size
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let t = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("register_object failed {} {}", status, t))
        }
    }

    pub async fn get_object(&self, hash: &str) -> Result<Option<ObjectMeta>> {
        let url = format!("{}/object/{}", self.base, hash);
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        if status.is_success() {
            let obj = resp.json::<ObjectMeta>().await?;
            Ok(Some(obj))
        } else if status.as_u16() == 404 {
            Ok(None)
        } else {
            let t = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("get_object failed {} {}", status, t))
        }
    }

    pub async fn placement_for_hash(&self, hash: &str, rf: usize) -> Result<Vec<String>> {
        let url = format!("{}/placement/{}?rf={}", self.base, hash, rf);
        let resp = self.client.get(&url).send().await?;
        let arr = resp.json::<Vec<String>>().await?;
        Ok(arr)
    }

    pub async fn mark_replica_healed(&self, hash: &str, node_id: &str) -> Result<()> {
        let url = format!("{}/replica/mark_healed", self.base);
        let body = serde_json::json!({
            "hash": hash,
            "node_id": node_id
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let t = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("mark_replica_healed failed {} {}", status, t))
        }
    }

    pub async fn mark_replica_missing(&self, hash: &str, node_id: &str) -> Result<()> {
        let url = format!("{}/replica/mark_missing", self.base);
        let body = serde_json::json!({
            "hash": hash,
            "node_id": node_id
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let t = resp.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("mark_replica_missing failed {} {}", status, t))
        }
    }
}
