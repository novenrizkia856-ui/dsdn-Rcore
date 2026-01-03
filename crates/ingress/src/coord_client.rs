use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct CoordinatorClient(pub Arc<ClientWrapper>);

#[derive(Clone)]
pub struct ClientWrapper {
    pub base: String,
    pub client: Client,
}

impl CoordinatorClient {
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("reqwest client");

        Self(Arc::new(ClientWrapper { base, client }))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NodeInfo {
    pub id: String,
    pub zone: String,
    pub addr: String,
    pub capacity_gb: u64,
    pub meta: serde_json::Value,
}

impl ClientWrapper {
    pub async fn placement_for_hash(&self, hash: &str, rf: usize) -> Result<Vec<String>> {
        let url = format!("{}/placement/{}?rf={}", &self.base, hash, rf);
        let r = self.client.get(&url).send().await?;
        let status = r.status();
        if !status.is_success() {
            let s = r.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("placement error: {} {}", status, s));
        }
        let arr = r.json::<Vec<String>>().await?;
        Ok(arr)
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>> {
        let url = format!("{}/nodes", &self.base);
        let r = self.client.get(&url).send().await?;
        let status = r.status();
        if !status.is_success() {
            let s = r.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("nodes error: {} {}", status, s));
        }
        let arr = r.json::<Vec<NodeInfo>>().await?;
        Ok(arr)
    }

    pub async fn ping(&self) -> Result<()> {
        // ping by checking /nodes endpoint
        let url = format!("{}/nodes", &self.base);
        let r = self.client.get(&url).send().await?;
        let status = r.status();
        if status.is_success() {
            Ok(())
        } else {
            let s = r.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("ping failed: {} {}", status, s))
        }
    }
}

// Wrapper convenience methods so callers can use CoordinatorClient directly (Arc<CoordinatorClient> also works via deref)
impl CoordinatorClient {
    pub async fn placement_for_hash(&self, hash: &str, rf: usize) -> Result<Vec<String>> {
        self.0.placement_for_hash(hash, rf).await
    }
    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>> {
        self.0.list_nodes().await
    }
    pub async fn ping(&self) -> Result<()> {
        self.0.ping().await
    }
}
