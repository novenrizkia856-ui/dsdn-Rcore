//! Health Check Command
//!
//! This module implements comprehensive health check commands for DSDN components:
//!
//! - `agent health all` - Check all components (DA, coordinator, nodes)
//! - `agent health da` - Check DA layer only
//! - `agent health coordinator` - Check coordinator only
//! - `agent health nodes` - Check all nodes
//!
//! # Output Contract
//!
//! Each component check reports:
//! - Status: healthy / degraded / unhealthy
//! - Latency: measured in milliseconds (real measurement, not estimated)
//! - Issues: explicit list of detected problems
//!
//! # Exit Codes
//!
//! - 0: All checked components are healthy
//! - 1: One or more components are unhealthy or degraded

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::cmd_da::DAConfig;
use crate::cmd_verify;

// ════════════════════════════════════════════════════════════════════════════
// HEALTH STATUS TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Health status enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Component is fully operational.
    Healthy,
    /// Component is operational but with issues.
    Degraded,
    /// Component is not operational.
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "HEALTHY"),
            HealthStatus::Degraded => write!(f, "DEGRADED"),
            HealthStatus::Unhealthy => write!(f, "UNHEALTHY"),
        }
    }
}

impl HealthStatus {
    /// Returns true if status is healthy.
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
    
    /// Returns the status indicator symbol.
    pub fn symbol(&self) -> &'static str {
        match self {
            HealthStatus::Healthy => "✓",
            HealthStatus::Degraded => "⚠",
            HealthStatus::Unhealthy => "✗",
        }
    }
}

/// Health check result for a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name.
    pub name: String,
    /// Health status.
    pub status: HealthStatus,
    /// Measured latency in milliseconds.
    pub latency_ms: u64,
    /// List of detected issues (empty if healthy).
    pub issues: Vec<String>,
    /// Additional details (optional).
    pub details: Option<String>,
}

impl ComponentHealth {
    /// Create a healthy component health.
    pub fn healthy(name: &str, latency_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Healthy,
            latency_ms,
            issues: Vec::new(),
            details: None,
        }
    }
    
    /// Create a healthy component with details.
    pub fn healthy_with_details(name: &str, latency_ms: u64, details: String) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Healthy,
            latency_ms,
            issues: Vec::new(),
            details: Some(details),
        }
    }
    
    /// Create an unhealthy component health.
    pub fn unhealthy(name: &str, latency_ms: u64, issues: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Unhealthy,
            latency_ms,
            issues,
            details: None,
        }
    }
    
    /// Create a degraded component health.
    pub fn degraded(name: &str, latency_ms: u64, issues: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Degraded,
            latency_ms,
            issues,
            details: None,
        }
    }
}

/// Aggregated health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Overall health status.
    pub overall_status: HealthStatus,
    /// Individual component health results.
    pub components: Vec<ComponentHealth>,
    /// Total check duration in milliseconds.
    pub total_duration_ms: u64,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
}

impl HealthCheckResult {
    /// Create a new health check result from component healths.
    pub fn from_components(components: Vec<ComponentHealth>, duration_ms: u64) -> Self {
        // Overall status is the worst status of all components
        let overall_status = if components.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        Self {
            overall_status,
            components,
            total_duration_ms: duration_ms,
            timestamp,
        }
    }
    
    /// Returns true if overall health is healthy.
    pub fn is_healthy(&self) -> bool {
        self.overall_status.is_healthy()
    }
    
    /// Format as table.
    pub fn to_table(&self) -> String {
        let mut output = String::new();
        output.push_str("┌─────────────────────────────────────────────────────────────────────────────┐\n");
        output.push_str("│                         DSDN HEALTH CHECK                                   │\n");
        output.push_str("├─────────────────────┬───────────────────────────────────────────────────────┤\n");
        output.push_str(&format!("│ Overall Status      │ {} {:50} │\n", 
            self.overall_status.symbol(), self.overall_status));
        output.push_str(&format!("│ Total Duration      │ {:>50} ms │\n", self.total_duration_ms));
        output.push_str(&format!("│ Timestamp           │ {:>53} │\n", self.timestamp));
        output.push_str("├─────────────────────┴───────────────────────────────────────────────────────┤\n");
        output.push_str("│ COMPONENT HEALTH:                                                           │\n");
        output.push_str("├───────────────────────────┬──────────────┬──────────────┬──────────────────┤\n");
        output.push_str("│ Component                 │ Status       │ Latency (ms) │ Issues           │\n");
        output.push_str("├───────────────────────────┼──────────────┼──────────────┼──────────────────┤\n");
        
        for component in &self.components {
            let issue_count = if component.issues.is_empty() {
                "none".to_string()
            } else {
                format!("{} issue(s)", component.issues.len())
            };
            
            output.push_str(&format!(
                "│ {:25} │ {} {:10} │ {:>12} │ {:16} │\n",
                truncate_str(&component.name, 25),
                component.status.symbol(),
                component.status,
                component.latency_ms,
                truncate_str(&issue_count, 16)
            ));
        }
        
        output.push_str("└───────────────────────────┴──────────────┴──────────────┴──────────────────┘\n");
        
        // Print issues if any
        let components_with_issues: Vec<_> = self.components.iter()
            .filter(|c| !c.issues.is_empty())
            .collect();
        
        if !components_with_issues.is_empty() {
            output.push_str("\n┌─────────────────────────────────────────────────────────────────────────────┐\n");
            output.push_str("│ DETECTED ISSUES:                                                            │\n");
            output.push_str("├─────────────────────────────────────────────────────────────────────────────┤\n");
            
            for component in components_with_issues {
                for issue in &component.issues {
                    output.push_str(&format!("│ [{}] {:68} │\n",
                        truncate_str(&component.name, 6),
                        truncate_str(issue, 68)
                    ));
                }
            }
            
            output.push_str("└─────────────────────────────────────────────────────────────────────────────┘\n");
        }
        
        output
    }
    
    /// Format as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize health result: {}", e))
    }
}

/// Truncate string with ellipsis.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK IMPLEMENTATIONS
// ════════════════════════════════════════════════════════════════════════════

/// Check DA layer health.
pub async fn check_da_health() -> ComponentHealth {
    let start = Instant::now();
    let config = DAConfig::from_env();
    
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ComponentHealth::unhealthy(
                "DA Layer",
                start.elapsed().as_millis() as u64,
                vec![format!("failed to create HTTP client: {}", e)],
            );
        }
    };
    
    // Check DA header endpoint
    let url = format!("{}/header/local_head", config.rpc_url);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return ComponentHealth::unhealthy(
                "DA Layer",
                start.elapsed().as_millis() as u64,
                vec![format!("DA unreachable: {}", e)],
            );
        }
    };
    
    let latency = start.elapsed().as_millis() as u64;
    
    if !response.status().is_success() {
        return ComponentHealth::unhealthy(
            "DA Layer",
            latency,
            vec![format!("DA returned error status: {}", response.status())],
        );
    }
    
    // Parse response to get height
    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return ComponentHealth::degraded(
                "DA Layer",
                latency,
                vec![format!("failed to read DA response: {}", e)],
            );
        }
    };
    
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(e) => {
            return ComponentHealth::degraded(
                "DA Layer",
                latency,
                vec![format!("failed to parse DA response: {}", e)],
            );
        }
    };
    
    let height = json.get("header")
        .and_then(|h| h.get("height"))
        .and_then(|h| h.as_str())
        .and_then(|h| h.parse::<u64>().ok());
    
    match height {
        Some(h) => ComponentHealth::healthy_with_details(
            "DA Layer",
            latency,
            format!("height: {}", h),
        ),
        None => ComponentHealth::degraded(
            "DA Layer",
            latency,
            vec!["missing or invalid height in DA response".to_string()],
        ),
    }
}

/// Check coordinator health.
pub async fn check_coordinator_health() -> ComponentHealth {
    let start = Instant::now();
    
    // Get coordinator endpoint from environment
    let coordinator_endpoint = std::env::var("DSDN_COORDINATOR_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:45831".to_string());
    
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ComponentHealth::unhealthy(
                "Coordinator",
                start.elapsed().as_millis() as u64,
                vec![format!("failed to create HTTP client: {}", e)],
            );
        }
    };
    
    // Check coordinator health endpoint
    let url = format!("{}/health", coordinator_endpoint);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return ComponentHealth::unhealthy(
                "Coordinator",
                start.elapsed().as_millis() as u64,
                vec![format!("Coordinator unreachable: {}", e)],
            );
        }
    };
    
    let latency = start.elapsed().as_millis() as u64;
    
    if response.status().is_success() {
        ComponentHealth::healthy_with_details(
            "Coordinator",
            latency,
            format!("endpoint: {}", coordinator_endpoint),
        )
    } else {
        ComponentHealth::unhealthy(
            "Coordinator",
            latency,
            vec![format!("Coordinator returned error status: {}", response.status())],
        )
    }
}

/// Node health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealthInfo {
    /// Node ID.
    pub node_id: String,
    /// Node address.
    pub addr: String,
    /// Health status.
    pub status: HealthStatus,
    /// Measured latency in milliseconds.
    pub latency_ms: u64,
    /// Issue if unhealthy.
    pub issue: Option<String>,
}

/// Check all nodes health.
pub async fn check_nodes_health() -> (ComponentHealth, Vec<NodeHealthInfo>) {
    let start = Instant::now();
    let config = DAConfig::from_env();
    
    // Rebuild state from DA to get node list
    let state = match cmd_verify::rebuild_state_from_da(&config).await {
        Ok(s) => s,
        Err(e) => {
            return (
                ComponentHealth::unhealthy(
                    "Nodes",
                    start.elapsed().as_millis() as u64,
                    vec![format!("failed to get node list from DA: {}", e)],
                ),
                Vec::new(),
            );
        }
    };
    
    if state.nodes.is_empty() {
        return (
            ComponentHealth::healthy_with_details(
                "Nodes",
                start.elapsed().as_millis() as u64,
                "no nodes registered".to_string(),
            ),
            Vec::new(),
        );
    }
    
    // Sort nodes by node_id for deterministic order
    let mut nodes: Vec<_> = state.nodes.values().collect();
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                ComponentHealth::unhealthy(
                    "Nodes",
                    start.elapsed().as_millis() as u64,
                    vec![format!("failed to create HTTP client: {}", e)],
                ),
                Vec::new(),
            );
        }
    };
    
    let mut node_healths: Vec<NodeHealthInfo> = Vec::new();
    let mut healthy_count = 0;
    let mut unhealthy_count = 0;
    let mut issues: Vec<String> = Vec::new();
    
    // Check each node in deterministic order (sorted by node_id)
    for node in &nodes {
        if !node.active {
            // Skip inactive nodes but record them
            node_healths.push(NodeHealthInfo {
                node_id: node.node_id.clone(),
                addr: node.addr.clone(),
                status: HealthStatus::Unhealthy,
                latency_ms: 0,
                issue: Some("node marked as inactive in DA".to_string()),
            });
            unhealthy_count += 1;
            issues.push(format!("node '{}' is inactive", node.node_id));
            continue;
        }
        
        let node_start = Instant::now();
        let url = format!("http://{}/health", node.addr);
        
        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                let latency = node_start.elapsed().as_millis() as u64;
                node_healths.push(NodeHealthInfo {
                    node_id: node.node_id.clone(),
                    addr: node.addr.clone(),
                    status: HealthStatus::Unhealthy,
                    latency_ms: latency,
                    issue: Some(format!("unreachable: {}", e)),
                });
                unhealthy_count += 1;
                issues.push(format!("node '{}' unreachable", node.node_id));
                continue;
            }
        };
        
        let latency = node_start.elapsed().as_millis() as u64;
        
        if response.status().is_success() {
            node_healths.push(NodeHealthInfo {
                node_id: node.node_id.clone(),
                addr: node.addr.clone(),
                status: HealthStatus::Healthy,
                latency_ms: latency,
                issue: None,
            });
            healthy_count += 1;
        } else {
            node_healths.push(NodeHealthInfo {
                node_id: node.node_id.clone(),
                addr: node.addr.clone(),
                status: HealthStatus::Unhealthy,
                latency_ms: latency,
                issue: Some(format!("returned status: {}", response.status())),
            });
            unhealthy_count += 1;
            issues.push(format!("node '{}' returned status: {}", node.node_id, response.status()));
        }
    }
    
    let total_latency = start.elapsed().as_millis() as u64;
    let total_nodes = nodes.len();
    
    let component_health = if unhealthy_count == 0 {
        ComponentHealth::healthy_with_details(
            "Nodes",
            total_latency,
            format!("{}/{} healthy", healthy_count, total_nodes),
        )
    } else if unhealthy_count == total_nodes {
        ComponentHealth::unhealthy("Nodes", total_latency, issues)
    } else {
        ComponentHealth::degraded(
            "Nodes",
            total_latency,
            issues,
        )
    };
    
    (component_health, node_healths)
}

// ════════════════════════════════════════════════════════════════════════════
// COMMAND HANDLERS
// ════════════════════════════════════════════════════════════════════════════

/// Handle `agent health all` command.
/// Checks ALL components: DA, coordinator, nodes.
pub async fn handle_health_all(json_output: bool) -> Result<bool> {
    let start = Instant::now();
    
    println!("Checking all components...\n");
    
    // Check DA - required component
    println!("[CHECK] DA Layer...");
    let da_health = check_da_health().await;
    println!("  {} DA Layer: {} ({}ms)", 
        da_health.status.symbol(), da_health.status, da_health.latency_ms);
    
    // Check Coordinator - required component
    println!("[CHECK] Coordinator...");
    let coord_health = check_coordinator_health().await;
    println!("  {} Coordinator: {} ({}ms)",
        coord_health.status.symbol(), coord_health.status, coord_health.latency_ms);
    
    // Check Nodes - check all nodes
    println!("[CHECK] Nodes...");
    let (nodes_health, node_details) = check_nodes_health().await;
    println!("  {} Nodes: {} ({}ms)",
        nodes_health.status.symbol(), nodes_health.status, nodes_health.latency_ms);
    
    // Print individual node status
    if !node_details.is_empty() {
        for node in &node_details {
            println!("    {} {} ({}): {}ms",
                node.status.symbol(),
                node.node_id,
                truncate_str(&node.addr, 20),
                node.latency_ms
            );
        }
    }
    
    let duration = start.elapsed().as_millis() as u64;
    
    let result = HealthCheckResult::from_components(
        vec![da_health, coord_health, nodes_health],
        duration,
    );
    
    println!();
    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }
    
    Ok(result.is_healthy())
}

/// Handle `agent health da` command.
/// Checks DA layer ONLY - no other components.
pub async fn handle_health_da(json_output: bool) -> Result<bool> {
    let start = Instant::now();
    
    println!("Checking DA Layer...\n");
    
    let da_health = check_da_health().await;
    
    let duration = start.elapsed().as_millis() as u64;
    
    let result = HealthCheckResult::from_components(vec![da_health], duration);
    
    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }
    
    Ok(result.is_healthy())
}

/// Handle `agent health coordinator` command.
/// Checks coordinator ONLY - no DA or nodes.
pub async fn handle_health_coordinator(json_output: bool) -> Result<bool> {
    let start = Instant::now();
    
    println!("Checking Coordinator...\n");
    
    let coord_health = check_coordinator_health().await;
    
    let duration = start.elapsed().as_millis() as u64;
    
    let result = HealthCheckResult::from_components(vec![coord_health], duration);
    
    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }
    
    Ok(result.is_healthy())
}

/// Handle `agent health nodes` command.
/// Checks ALL nodes - deterministic order by node_id.
pub async fn handle_health_nodes(json_output: bool) -> Result<bool> {
    let start = Instant::now();
    
    println!("Checking Nodes...\n");
    
    let (nodes_health, node_details) = check_nodes_health().await;
    
    // Print individual node status (deterministic order)
    for node in &node_details {
        let issue_str = node.issue.as_deref().unwrap_or("-");
        println!("  {} {} ({}): {}ms - {}",
            node.status.symbol(),
            node.node_id,
            truncate_str(&node.addr, 20),
            node.latency_ms,
            truncate_str(issue_str, 40)
        );
    }
    
    let duration = start.elapsed().as_millis() as u64;
    
    let result = HealthCheckResult::from_components(vec![nodes_health], duration);
    
    println!();
    if json_output {
        println!("{}", result.to_json()?);
    } else {
        print!("{}", result.to_table());
    }
    
    Ok(result.is_healthy())
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // TEST 1: HEALTH STATUS DISPLAY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Healthy), "HEALTHY");
        assert_eq!(format!("{}", HealthStatus::Degraded), "DEGRADED");
        assert_eq!(format!("{}", HealthStatus::Unhealthy), "UNHEALTHY");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 2: HEALTH STATUS IS HEALTHY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_status_is_healthy() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(!HealthStatus::Degraded.is_healthy());
        assert!(!HealthStatus::Unhealthy.is_healthy());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 3: HEALTH STATUS SYMBOL
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_status_symbol() {
        assert_eq!(HealthStatus::Healthy.symbol(), "✓");
        assert_eq!(HealthStatus::Degraded.symbol(), "⚠");
        assert_eq!(HealthStatus::Unhealthy.symbol(), "✗");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 4: COMPONENT HEALTH HEALTHY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_component_health_healthy() {
        let health = ComponentHealth::healthy("Test", 100);
        assert_eq!(health.name, "Test");
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.latency_ms, 100);
        assert!(health.issues.is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 5: COMPONENT HEALTH UNHEALTHY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_component_health_unhealthy() {
        let health = ComponentHealth::unhealthy(
            "Test",
            200,
            vec!["issue 1".to_string(), "issue 2".to_string()],
        );
        assert_eq!(health.status, HealthStatus::Unhealthy);
        assert_eq!(health.issues.len(), 2);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 6: COMPONENT HEALTH DEGRADED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_component_health_degraded() {
        let health = ComponentHealth::degraded(
            "Test",
            150,
            vec!["warning".to_string()],
        );
        assert_eq!(health.status, HealthStatus::Degraded);
        assert_eq!(health.issues.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 7: HEALTH CHECK RESULT - ALL HEALTHY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_check_result_all_healthy() {
        let components = vec![
            ComponentHealth::healthy("DA", 50),
            ComponentHealth::healthy("Coordinator", 30),
            ComponentHealth::healthy("Nodes", 100),
        ];
        
        let result = HealthCheckResult::from_components(components, 200);
        
        assert_eq!(result.overall_status, HealthStatus::Healthy);
        assert!(result.is_healthy());
        assert_eq!(result.components.len(), 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 8: HEALTH CHECK RESULT - ONE UNHEALTHY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_check_result_one_unhealthy() {
        let components = vec![
            ComponentHealth::healthy("DA", 50),
            ComponentHealth::unhealthy("Coordinator", 30, vec!["down".to_string()]),
            ComponentHealth::healthy("Nodes", 100),
        ];
        
        let result = HealthCheckResult::from_components(components, 200);
        
        assert_eq!(result.overall_status, HealthStatus::Unhealthy);
        assert!(!result.is_healthy());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 9: HEALTH CHECK RESULT - ONE DEGRADED
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_check_result_one_degraded() {
        let components = vec![
            ComponentHealth::healthy("DA", 50),
            ComponentHealth::degraded("Coordinator", 30, vec!["slow".to_string()]),
            ComponentHealth::healthy("Nodes", 100),
        ];
        
        let result = HealthCheckResult::from_components(components, 200);
        
        assert_eq!(result.overall_status, HealthStatus::Degraded);
        assert!(!result.is_healthy());
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 10: HEALTH CHECK RESULT TO TABLE
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_check_result_to_table() {
        let components = vec![
            ComponentHealth::healthy("DA Layer", 50),
            ComponentHealth::unhealthy("Coordinator", 30, vec!["unreachable".to_string()]),
        ];
        
        let result = HealthCheckResult::from_components(components, 100);
        let table = result.to_table();
        
        assert!(table.contains("DSDN HEALTH CHECK"));
        assert!(table.contains("DA Layer"));
        assert!(table.contains("Coordinator"));
        assert!(table.contains("DETECTED ISSUES"));
        assert!(table.contains("unreachable"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 11: HEALTH CHECK RESULT JSON
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_check_result_json() {
        let components = vec![
            ComponentHealth::healthy("DA", 50),
        ];
        
        let result = HealthCheckResult::from_components(components, 100);
        let json = result.to_json().expect("should serialize");
        
        assert!(json.contains("DA"));
        assert!(json.contains("Healthy"));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 12: COMPONENT HEALTH WITH DETAILS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_component_health_with_details() {
        let health = ComponentHealth::healthy_with_details(
            "DA",
            100,
            "height: 12345".to_string(),
        );
        
        assert_eq!(health.details, Some("height: 12345".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 13: NODE HEALTH INFO SERIALIZATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_node_health_info_serialization() {
        let info = NodeHealthInfo {
            node_id: "node-1".to_string(),
            addr: "127.0.0.1:9000".to_string(),
            status: HealthStatus::Healthy,
            latency_ms: 50,
            issue: None,
        };
        
        let json = serde_json::to_string(&info).expect("should serialize");
        let parsed: NodeHealthInfo = serde_json::from_str(&json).expect("should parse");
        
        assert_eq!(parsed.node_id, "node-1");
        assert_eq!(parsed.status, HealthStatus::Healthy);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 14: TRUNCATE STRING
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("short", 10), "short");
        assert_eq!(truncate_str("exactly10!", 10), "exactly10!");
        assert_eq!(truncate_str("this is too long", 10), "this is...");
    }

    // ════════════════════════════════════════════════════════════════════════
    // TEST 15: HEALTH STATUS EQUALITY
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_health_status_equality() {
        assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
        assert_eq!(HealthStatus::Degraded, HealthStatus::Degraded);
        assert_eq!(HealthStatus::Unhealthy, HealthStatus::Unhealthy);
        assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
    }
}