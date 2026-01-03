use serde::{Serialize, Deserialize};

/// Node runtime statistics used for scoring.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NodeStats {
    /// fraction 0.0-1.0 of CPU free (e.g. 0.6 means 60% CPU free)
    pub cpu_free: f64,
    /// RAM free in MiB
    pub ram_free_mb: f64,
    /// GPU free units (count or normalized capacity)
    pub gpu_free: f64,
    /// latency in ms (to the data or coordinator) - lower is better
    pub latency_ms: f64,
    /// I/O pressure 0.0-1.0 (higher is worse)
    pub io_pressure: f64,
}

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            cpu_free: 0.0,
            ram_free_mb: 0.0,
            gpu_free: 0.0,
            latency_ms: 9999.0,
            io_pressure: 1.0,
        }
    }
}

/// Workload demand description used by scheduler.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workload {
    /// soft requirement for CPU fraction (0.0-1.0). Scheduler will prefer nodes with >= cpu_req
    pub cpu_req: Option<f64>,
    /// soft requirement for RAM in MiB
    pub ram_req_mb: Option<f64>,
    /// soft requirement for GPU units
    pub gpu_req: Option<f64>,
    /// maximum acceptable latency in ms (optional)
    pub max_latency_ms: Option<f64>,
    /// how tolerant the workload is to high IO pressure (0.0 intolerant, 1.0 very tolerant)
    pub io_tolerance: Option<f64>,
}

/// Scheduler weights structure that controls scoring formula:
/// S = w1*CPU_free + w2*RAM_free + w3*GPU_free + w4*(1/latency) - w5*IO_pressure
#[derive(Clone, Debug)]
pub struct Scheduler {
    pub w_cpu: f64,
    pub w_ram: f64,
    pub w_gpu: f64,
    pub w_latency: f64,
    pub w_io: f64,
}

impl Scheduler {
    pub fn default() -> Self {
        Scheduler {
            w_cpu: 1.0,
            w_ram: 0.001,     // ram in MiB so scale down
            w_gpu: 2.0,
            w_latency: 50.0,  // multiply inverse latency
            w_io: 1.5,
        }
    }

    /// Compute score for a node given stats. Higher is better.
    pub fn score(&self, stats: &NodeStats) -> f64 {
        // avoid divide by zero
        let inv_latency = if stats.latency_ms <= 0.0 { 1.0 } else { 1.0 / stats.latency_ms };
        let s = self.w_cpu * stats.cpu_free
            + self.w_ram * stats.ram_free_mb
            + self.w_gpu * stats.gpu_free
            + self.w_latency * inv_latency
            - self.w_io * stats.io_pressure;
        s
    }

    /// Check if node meets basic workload soft requirements
    pub fn meets(&self, stats: &NodeStats, wl: &Workload) -> bool {
        if let Some(cpu_req) = wl.cpu_req {
            if stats.cpu_free < cpu_req { return false; }
        }
        if let Some(ram_req) = wl.ram_req_mb {
            if stats.ram_free_mb < ram_req { return false; }
        }
        if let Some(gpu_req) = wl.gpu_req {
            if stats.gpu_free < gpu_req { return false; }
        }
        if let Some(max_lat) = wl.max_latency_ms {
            if stats.latency_ms > max_lat { return false; }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_score_ordering() {
        let s = Scheduler::default();
        let a = NodeStats { cpu_free: 0.8, ram_free_mb: 16000.0, gpu_free: 0.0, latency_ms: 5.0, io_pressure: 0.1 };
        let b = NodeStats { cpu_free: 0.5, ram_free_mb: 8000.0, gpu_free: 1.0, latency_ms: 10.0, io_pressure: 0.05 };
        let sa = s.score(&a);
        let sb = s.score(&b);
        // a probably better due to high CPU and RAM
        assert!(sa > sb);
    }
}
